package image

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"
)

// ProofsFile is the record file's name in Limbo's state folder (/var/lib/limbo/state for the daemon).
const ProofsFile = "image-proofs.json"

// How says how Check accepted an image.
type How string

const (
	// ByRecord: a full hash proved this very file earlier and nothing about it has changed since. The image was not read.
	ByRecord How = "record"
	// ByHash: the image was hashed in full.
	ByHash How = "full"
	// ByMemory (CheckCached only): this process hashed this very file earlier (listing profiles, never a start).
	ByMemory How = "memory"
)

// Proofs remembers which images were hashed in full, so a start can skip a multi-gigabyte hash (owner's decision,
// 2026-11-09: a 12.7 GB Windows base cost 25 s of CPU and of waiting on every start, and pushed GBs through the page
// cache).
//
// The record is a cache of a proof, never a way to trust an image that was never hashed. Check accepts an image without
// reading it only when all of these hold, and hashes it in full otherwise, exactly as before:
//
//   - the image is a regular file (not a link), owned by Owner (root), not writable by group or others, in a folder
//     owned by Owner that group and others cannot write;
//   - its device, inode, size, modification time and change time (nanoseconds) are those recorded when it was hashed;
//   - the recorded SHA-256 is the one the manifest asks for, and the weekly check has not refused it since.
//
// The change time cannot be set from user space: writing the file, truncating it, changing its owner, mode or ACL, or
// linking it all move it, and so does replacing it (a new file, a new inode or a new change time). Only root can do any
// of that to a file that passes the first rule, and root is trusted anyway.
//
// The record file (Path) counts only when it is a regular file owned by Owner, not writable by group or others, in a
// folder of Owner's that group and others cannot write, and parses cleanly; anything else (missing, damaged, someone
// else's) is ignored, the image is hashed in full, and the next proof rewrites the file. Only a process running as
// Owner writes records. A zero Proofs (or a nil one) keeps nothing: every Check hashes in full.
type Proofs struct {
	Path  string // the record file; empty keeps nothing
	Owner uint32 // the one trusted owner of images, folders and the record file: 0 (root); tests use their own uid

	mu     sync.Mutex
	memory map[string]memo // image path -> what this process hashed (CheckCached only)
	now    func() time.Time
}

type memo struct {
	sig Sig
	sum string
}

// Sig is what identifies a file's state: which file it is (device, inode) and that it has not changed (size,
// modification and change times in nanoseconds).
type Sig struct {
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
	CtimeNs int64  `json:"ctime_ns"`
}

func sigOf(st *syscall.Stat_t) Sig {
	return Sig{Dev: uint64(st.Dev), Ino: uint64(st.Ino), Size: st.Size, MtimeNs: st.Mtim.Nano(), CtimeNs: st.Ctim.Nano()}
}

// Record is one proof: the file at Path, in the state Sig, hashed in full to SHA256 at HashedAt.
type Record struct {
	Path string `json:"path"`
	Sig
	SHA256   string    `json:"sha256"`
	HashedAt time.Time `json:"hashed_at"`
	// RefusedAt is set when the weekly check hashed the file and it no longer matched SHA256 (Found is what it hashed
	// to). A refused record never lets a start skip the hash; a later full hash that matches a manifest replaces it.
	RefusedAt *time.Time `json:"refused_at,omitempty"`
	Found     string     `json:"found,omitempty"`
}

// Refused says whether the weekly check refused this image.
func (r Record) Refused() bool { return r.RefusedAt != nil }

// recordFile is the file's JSON.
type recordFile struct {
	Version int      `json:"version"`
	Images  []Record `json:"images"`
}

const (
	fileVersion = 1
	maxFileSize = 1 << 20
	maxRecords  = 1000
)

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (p *Proofs) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// Check proves that the file at path has SHA-256 want: from its record when every rule above holds, by hashing it in
// full otherwise. A full hash that matches is recorded (when this process runs as Owner and the file is eligible). The
// error wraps ErrMismatch when the file is not what the manifest says, or is the file's own error (missing, unreadable).
func (p *Proofs) Check(path, want string) (How, error) {
	path = filepath.Clean(path)
	if p != nil && p.Path != "" {
		recs, _ := p.load()
		if rec, ok := recs[path]; ok && !rec.Refused() && rec.SHA256 == want {
			if s, err := p.eligible(path); err == nil && s == rec.Sig {
				return ByRecord, nil
			}
		}
	}
	return p.hash(path, want)
}

// CheckCached is Check for listing profiles, never for a start: it also accepts a file this process itself hashed to
// want earlier, while its stat signature is unchanged and the weekly check has not refused it. That keeps a listing
// from re-hashing an image the record cannot cover (one that is not root's), as the listing's own cache did before.
func (p *Proofs) CheckCached(path, want string) (How, error) {
	path = filepath.Clean(path)
	if p == nil {
		return p.hash(path, want)
	}
	recs, _ := p.load()
	rec, has := recs[path]
	if has && rec.Refused() {
		return p.hash(path, want)
	}
	if has && rec.SHA256 == want {
		if s, err := p.eligible(path); err == nil && s == rec.Sig {
			return ByRecord, nil
		}
	}
	p.mu.Lock()
	m, ok := p.memory[path]
	p.mu.Unlock()
	if ok && m.sum == want {
		if fi, err := stat(path); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && sigOf(st) == m.sig {
				return ByMemory, nil
			}
		}
	}
	return p.hash(path, want)
}

// hash hashes the file in full (following a link, as before), and on a match records it when it is eligible and did not
// change while it was read.
func (p *Proofs) hash(path, want string) (How, error) {
	sum, before, stable, err := hashFile(path)
	if err != nil {
		return ByHash, err
	}
	if sum != want {
		return ByHash, mismatch(path, want, sum)
	}
	if p == nil || !stable {
		return ByHash, nil
	}
	p.mu.Lock()
	if p.memory == nil {
		p.memory = map[string]memo{}
	}
	p.memory[path] = memo{before, sum}
	p.mu.Unlock()
	if p.Path != "" && os.Geteuid() == int(p.Owner) {
		if s, err := p.eligible(path); err == nil && s == before {
			_ = p.put(Record{Path: path, Sig: before, SHA256: sum, HashedAt: p.clock().UTC()}) // a cache: losing it costs one hash
		}
	}
	return ByHash, nil
}

// Replaced in tests: hashFile to count full hashes, lstat and stat to show a file or folder as someone else's.
var (
	hashFile = hashPath
	lstat    = os.Lstat
	stat     = os.Stat
)

// hashPath opens and hashes the file, and reports its signature when opened and whether it was the same after the hash.
func hashPath(path string) (sum string, before Sig, stable bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", Sig{}, false, err
	}
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return "", Sig{}, false, err
	}
	before = sigOf(&st)
	if sum, err = hashOpen(f); err != nil {
		return "", Sig{}, false, err
	}
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return "", Sig{}, false, err
	}
	return sum, before, sigOf(&st) == before, nil
}

// eligible applies the ownership rules to the image and its folder and returns its signature. It never follows a link
// at the last step: a link is not eligible.
func (p *Proofs) eligible(path string) (Sig, error) {
	fi, err := lstat(path)
	if err != nil {
		return Sig{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Sig{}, errors.New("no stat information")
	}
	switch {
	case !fi.Mode().IsRegular():
		return Sig{}, errors.New("not a regular file (a link or something else)")
	case st.Uid != p.Owner:
		return Sig{}, fmt.Errorf("owned by uid %d, not %s", st.Uid, p.ownerName())
	case fi.Mode().Perm()&0o022 != 0:
		return Sig{}, errors.New("writable by group or others")
	}
	if err := p.ownFolder(filepath.Dir(path)); err != nil {
		return Sig{}, err
	}
	return sigOf(st), nil
}

// ownFolder checks that only Owner can change what a folder holds.
func (p *Proofs) ownFolder(dir string) error {
	fi, err := stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok || !fi.IsDir():
		return fmt.Errorf("%s is not a folder", dir)
	case st.Uid != p.Owner:
		return fmt.Errorf("its folder %s is owned by uid %d, not %s", dir, st.Uid, p.ownerName())
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("its folder %s is writable by group or others", dir)
	}
	return nil
}

func (p *Proofs) ownerName() string {
	if p.Owner == 0 {
		return "root"
	}
	return fmt.Sprintf("uid %d", p.Owner)
}

// FileState says what load made of the record file.
type FileState int

const (
	FileMissing FileState = iota // no record file yet
	FileOK                       // read and trusted
	FileIgnored                  // there, but damaged or not Owner's: ignored, rewritten by the next proof
)

// load reads the record file if it can be trusted. Records are keyed by path. It takes no lock: the file is only ever
// replaced whole (rename), so a reader sees one version or the other.
func (p *Proofs) load() (map[string]Record, FileState) {
	recs, st, _ := p.loadWhy()
	return recs, st
}

func (p *Proofs) loadWhy() (map[string]Record, FileState, error) {
	empty := map[string]Record{}
	if p == nil || p.Path == "" {
		return empty, FileMissing, nil
	}
	fi, err := lstat(p.Path)
	if errors.Is(err, os.ErrNotExist) {
		return empty, FileMissing, nil
	}
	if err != nil {
		return empty, FileIgnored, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok || !fi.Mode().IsRegular():
		return empty, FileIgnored, errors.New("the record file is not a regular file")
	case st.Uid != p.Owner:
		return empty, FileIgnored, fmt.Errorf("the record file is owned by uid %d, not %s", st.Uid, p.ownerName())
	case fi.Mode().Perm()&0o022 != 0:
		return empty, FileIgnored, errors.New("the record file is writable by group or others")
	}
	if err := p.ownFolder(filepath.Dir(p.Path)); err != nil {
		return empty, FileIgnored, fmt.Errorf("the record file's folder: %w", err)
	}
	f, err := os.OpenFile(p.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, FileIgnored, err
	}
	defer f.Close()
	var fst syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &fst); err != nil || fst.Dev != st.Dev || fst.Ino != st.Ino {
		return empty, FileIgnored, errors.New("the record file changed while it was opened")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return empty, FileIgnored, err
	}
	if len(b) > maxFileSize {
		return empty, FileIgnored, errors.New("the record file is too large")
	}
	var rf recordFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rf); err != nil {
		return empty, FileIgnored, fmt.Errorf("the record file is damaged: %w", err)
	}
	if dec.More() {
		return empty, FileIgnored, errors.New("the record file is damaged: data after the record")
	}
	if rf.Version != fileVersion {
		return empty, FileIgnored, fmt.Errorf("the record file has version %d, not %d", rf.Version, fileVersion)
	}
	if len(rf.Images) > maxRecords {
		return empty, FileIgnored, errors.New("the record file holds too many records")
	}
	out := make(map[string]Record, len(rf.Images))
	for _, r := range rf.Images {
		if err := r.valid(); err != nil {
			return empty, FileIgnored, fmt.Errorf("the record file is damaged: %w", err)
		}
		if _, dup := out[r.Path]; dup {
			return empty, FileIgnored, fmt.Errorf("the record file is damaged: %s twice", r.Path)
		}
		out[r.Path] = r
	}
	return out, FileOK, nil
}

func (r Record) valid() error {
	switch {
	case !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path:
		return fmt.Errorf("record path %q is not a clean absolute path", r.Path)
	case !hexRe.MatchString(r.SHA256):
		return fmt.Errorf("record for %s: bad sha256", r.Path)
	case r.Found != "" && !hexRe.MatchString(r.Found):
		return fmt.Errorf("record for %s: bad found", r.Path)
	case r.Size < 0 || r.HashedAt.IsZero():
		return fmt.Errorf("record for %s: bad size or time", r.Path)
	case (r.RefusedAt == nil) != (r.Found == ""):
		return fmt.Errorf("record for %s: a refusal needs both its time and what was found", r.Path)
	}
	return nil
}

// lock serialises read-modify-write of the record file between processes (the daemon, `limbo up`, the weekly check).
func (p *Proofs) lock() (func(), error) {
	f, err := os.OpenFile(p.Path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// put adds or replaces one record. An untrusted record file is replaced by one holding only the new record.
func (p *Proofs) put(r Record) error {
	return p.update(func(recs map[string]Record) { recs[r.Path] = r })
}

// update applies change to the trusted records (or none, if the file is missing or ignored) and writes them back whole.
func (p *Proofs) update(change func(map[string]Record)) error {
	if err := p.ownFolder(filepath.Dir(p.Path)); err != nil {
		return fmt.Errorf("image proofs: not written: %w", err)
	}
	unlock, err := p.lock()
	if err != nil {
		return err
	}
	defer unlock()
	recs, _ := p.load()
	change(recs)
	return p.save(recs)
}

// save writes the records to a new file and renames it over the old one, so a reader never sees half a file and a
// foreign or damaged file is replaced, not edited.
func (p *Proofs) save(recs map[string]Record) error {
	rf := recordFile{Version: fileVersion, Images: make([]Record, 0, len(recs))}
	for _, r := range recs {
		rf.Images = append(rf.Images, r)
	}
	sort.Slice(rf.Images, func(i, j int) bool { return rf.Images[i].Path < rf.Images[j].Path })
	if len(rf.Images) > maxRecords {
		rf.Images = rf.Images[:maxRecords]
	}
	b, err := json.MarshalIndent(rf, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p.Path), ".image-proofs-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), p.Path); err != nil {
		return err
	}
	ok = true
	return nil
}

// Status describes one record for `limbo image list`.
type Status struct {
	Record
	// Quick says whether a start would skip the hash right now (for a manifest asking for Record.SHA256); Why says why
	// not.
	Quick bool
	Why   string
}

// List returns every record with whether it would let a start skip the hash now, and what load made of the file
// (FileIgnored comes with the reason).
func (p *Proofs) List() ([]Status, FileState, error) {
	recs, st, why := p.loadWhy()
	out := make([]Status, 0, len(recs))
	for _, r := range recs {
		s := Status{Record: r}
		switch sig, err := p.eligible(r.Path); {
		case r.Refused():
			s.Why = "refused by the weekly check: it hashed to " + r.Found
		case err != nil:
			s.Why = err.Error()
		case sig != r.Sig:
			s.Why = "changed since it was hashed (the next start hashes it in full)"
		default:
			s.Quick = true
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, st, why
}
