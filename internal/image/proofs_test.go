package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The tests run as an ordinary user, so the trusted owner is the test's own uid; a file or folder "owned by someone
// else" is shown so through the stat hooks.

type world struct {
	t      *testing.T
	p      *Proofs
	img    string // an eligible image: the user's own, 0644, in the user's own 0755 folder
	sum    string
	hashes int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	root := t.TempDir()
	imgDir, state := filepath.Join(root, "images"), filepath.Join(root, "state")
	for _, d := range []string{imgDir, state} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil { // whatever the umask
			t.Fatal(err)
		}
	}
	w := &world{t: t, img: filepath.Join(imgDir, "base.qcow2")}
	w.write("a base image")
	w.p = &Proofs{Path: filepath.Join(state, ProofsFile), Owner: uint32(os.Getuid())}
	real := hashFile
	hashFile = func(path string) (string, Sig, bool, error) { w.hashes++; return real(path) }
	t.Cleanup(func() { hashFile = real })
	return w
}

// write replaces the image's content in place (same inode) and remembers its digest.
func (w *world) write(content string) {
	w.t.Helper()
	if err := os.WriteFile(w.img, []byte(content), 0o644); err != nil {
		w.t.Fatal(err)
	}
	if err := os.Chmod(w.img, 0o644); err != nil {
		w.t.Fatal(err)
	}
	s := sha256.Sum256([]byte(content))
	w.sum = hex.EncodeToString(s[:])
}

func (w *world) check(want How) {
	w.t.Helper()
	before := w.hashes
	how, err := w.p.Check(w.img, w.sum)
	if err != nil {
		w.t.Fatalf("check: %v", err)
	}
	if how != want {
		w.t.Fatalf("checked by %q, want %q", how, want)
	}
	if hashed := w.hashes > before; hashed != (want == ByHash) {
		w.t.Fatalf("hashed=%v for a check by %q", hashed, how)
	}
}

func (w *world) records() map[string]Record {
	w.t.Helper()
	recs, st := w.p.load()
	if st != FileOK {
		w.t.Fatalf("record file state %v", st)
	}
	return recs
}

// setRecord writes the record file by hand (as the trusted owner), the way a test stages a proof.
func (w *world) setRecord(r Record) {
	w.t.Helper()
	if err := w.p.update(func(m map[string]Record) { m[r.Path] = r }); err != nil {
		w.t.Fatal(err)
	}
}

func sigFor(t *testing.T, path string) Sig {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return sigOf(fi.Sys().(*syscall.Stat_t))
}

type ownedBy struct {
	os.FileInfo
	st syscall.Stat_t
}

func (o ownedBy) Sys() any { return &o.st }

// showOwner makes both stat hooks report path as owned by uid.
func showOwner(t *testing.T, path string, uid uint32) {
	ol, os_ := lstat, stat
	wrap := func(f func(string) (os.FileInfo, error)) func(string) (os.FileInfo, error) {
		return func(p string) (os.FileInfo, error) {
			fi, err := f(p)
			if err != nil || filepath.Clean(p) != path {
				return fi, err
			}
			st := *fi.Sys().(*syscall.Stat_t)
			st.Uid = uid
			return ownedBy{fi, st}, nil
		}
	}
	lstat, stat = wrap(ol), wrap(os_)
	t.Cleanup(func() { lstat, stat = ol, os_ })
}

func TestFirstCheckHashesAndRecordsTheProof(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	r, ok := w.records()[w.img]
	if !ok || r.SHA256 != w.sum || r.Sig != sigFor(t, w.img) || r.HashedAt.IsZero() || r.Refused() {
		t.Fatalf("record %+v", r)
	}
	fi, err := os.Lstat(w.p.Path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("record file mode: %v %v", fi.Mode(), err)
	}
}

func TestMatchSkipsTheHash(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	for range 3 {
		w.check(ByRecord)
	}
}

// Each field of the signature, changed on its own in the record, sends the check back to a full hash (which then
// records the file as it is).
func TestEachChangedFieldHashesInFull(t *testing.T) {
	for _, field := range []string{"dev", "ino", "size", "mtime", "ctime"} {
		t.Run(field, func(t *testing.T) {
			w := newWorld(t)
			w.check(ByHash)
			r := w.records()[w.img]
			switch field {
			case "dev":
				r.Dev++
			case "ino":
				r.Ino++
			case "size":
				r.Size++
			case "mtime":
				r.MtimeNs++
			case "ctime":
				r.CtimeNs++
			}
			w.setRecord(r)
			w.check(ByHash)
			w.check(ByRecord)
		})
	}
}

// The same changes made to the real file. Restoring the modification time does not help: the change time moved.
func TestChangesToTheFileHashInFull(t *testing.T) {
	cases := map[string]func(w *world){
		"rewritten with the same content": func(w *world) { w.write("a base image") },
		"chmod": func(w *world) {
			if err := os.Chmod(w.img, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"mtime put back after a write": func(w *world) {
			fi, _ := os.Stat(w.img)
			w.write("a base image")
			if err := os.Chtimes(w.img, fi.ModTime(), fi.ModTime()); err != nil {
				t.Fatal(err)
			}
		},
		"replaced by a copy (a new inode)": func(w *world) {
			tmp := w.img + ".new"
			if err := os.WriteFile(tmp, []byte("a base image"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(tmp, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, w.img); err != nil {
				t.Fatal(err)
			}
		},
		"grown": func(w *world) { w.write("a base image, grown") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.check(ByHash)
			time.Sleep(10 * time.Millisecond) // past the filesystem's timestamp granularity
			change(w)
			w.check(ByHash)
		})
	}
}

func TestRecordForAnotherDigestDoesNotCount(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	other := strings.Repeat("0", 64)
	how, err := w.p.Check(w.img, other)
	if how != ByHash || !errors.Is(err, ErrMismatch) {
		t.Fatalf("a manifest asking for another digest: %q %v", how, err)
	}
	w.check(ByRecord) // the proof itself still stands
}

// An image that does not meet the ownership rules is hashed in full every time, even with a perfect record, and no
// record is written for it.
func TestIneligibleImagesAreAlwaysHashed(t *testing.T) {
	cases := map[string]func(w *world) string{
		"image owned by someone else": func(w *world) string {
			showOwner(t, w.img, w.p.Owner+1)
			return w.img
		},
		"image writable by group": func(w *world) string {
			if err := os.Chmod(w.img, 0o664); err != nil {
				t.Fatal(err)
			}
			return w.img
		},
		"image writable by others": func(w *world) string {
			if err := os.Chmod(w.img, 0o646); err != nil {
				t.Fatal(err)
			}
			return w.img
		},
		"a link to the image": func(w *world) string {
			link := filepath.Join(filepath.Dir(w.img), "link.qcow2")
			if err := os.Symlink(w.img, link); err != nil {
				t.Fatal(err)
			}
			return link
		},
		"folder owned by someone else": func(w *world) string {
			showOwner(t, filepath.Dir(w.img), w.p.Owner+1)
			return w.img
		},
		"folder writable by group": func(w *world) string {
			if err := os.Chmod(filepath.Dir(w.img), 0o775); err != nil {
				t.Fatal(err)
			}
			return w.img
		},
		"folder writable by others (sticky, like /tmp)": func(w *world) string {
			if err := os.Chmod(filepath.Dir(w.img), 0o1777); err != nil {
				t.Fatal(err)
			}
			return w.img
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			path := setup(w)
			for i := range 2 {
				before := w.hashes
				how, err := w.p.Check(path, w.sum)
				if err != nil || how != ByHash || w.hashes != before+1 {
					t.Fatalf("check %d: %q %v (hashes %d)", i, how, err, w.hashes-before)
				}
			}
			if recs, st := w.p.load(); st != FileMissing || len(recs) != 0 {
				t.Fatalf("a record was written for an ineligible image: %v %+v", st, recs)
			}
			// Even a hand-made record that matches perfectly is not enough.
			w.setRecord(Record{Path: path, Sig: sigFor(t, w.img), SHA256: w.sum, HashedAt: time.Now()})
			before := w.hashes
			if how, err := w.p.Check(path, w.sum); err != nil || how != ByHash || w.hashes != before+1 {
				t.Fatalf("matching record for an ineligible image: %q %v", how, err)
			}
		})
	}
}

// A damaged, foreign or loose record file is ignored (the image is hashed in full) and the next proof replaces it.
func TestUntrustedRecordFileIsIgnoredAndRewritten(t *testing.T) {
	cases := map[string]func(w *world){
		"garbage": func(w *world) {
			if err := os.WriteFile(w.p.Path, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unknown field": func(w *world) { w.editFile(`"version": 1`, `"version": 1, "trust_me": true`) },
		"other version": func(w *world) { w.editFile(`"version": 1`, `"version": 2`) },
		"bad digest":    func(w *world) { w.editFile(w.sum, strings.ToUpper(w.sum)) },
		"relative path": func(w *world) { w.editFile(`"path": "`+w.img, `"path": "images/../`+w.img[1:]) },
		"duplicate record": func(w *world) {
			r := w.records()[w.img]
			b, _ := json.Marshal(recordFile{Version: 1, Images: []Record{r, r}})
			if err := os.WriteFile(w.p.Path, b, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable": func(w *world) {
			if err := os.Chmod(w.p.Path, 0o620); err != nil {
				t.Fatal(err)
			}
		},
		"someone else's": func(w *world) { showOwner(t, w.p.Path, w.p.Owner+1) },
		"its folder is someone else's": func(w *world) {
			showOwner(t, filepath.Dir(w.p.Path), w.p.Owner+1)
		},
		"a link to a good copy": func(w *world) {
			cp := w.p.Path + ".copy"
			b, _ := os.ReadFile(w.p.Path)
			if err := os.WriteFile(cp, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(w.p.Path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(cp, w.p.Path); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.check(ByHash)
			damage(w)
			if _, st := w.p.load(); st != FileIgnored {
				t.Fatalf("record file state %v, want ignored", st)
			}
			w.check(ByHash)
			if strings.Contains(name, "folder") { // nothing is written into a folder that is not the owner's alone
				if _, st := w.p.load(); st != FileIgnored {
					t.Fatal("written into a folder that is not the owner's")
				}
				return
			}
			if name == "someone else's" { // the stat hook still shows the new file as foreign; look at the real one
				lstat, stat = os.Lstat, os.Stat
			}
			fi, err := os.Lstat(w.p.Path)
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
				t.Fatalf("not rewritten as a regular 0600 file: %v %v", fi, err)
			}
			w.check(ByRecord)
		})
	}
}

func (w *world) editFile(old, new string) {
	w.t.Helper()
	b, err := os.ReadFile(w.p.Path)
	if err != nil {
		w.t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		w.t.Fatalf("record file lacks %q:\n%s", old, b)
	}
	if err := os.WriteFile(w.p.Path, []byte(strings.Replace(string(b), old, new, 1)), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

// Only the trusted owner writes records: a check run by anyone else hashes and leaves the file alone.
func TestOnlyTheOwnerWritesRecords(t *testing.T) {
	w := newWorld(t)
	w.p.Owner++ // this process is no longer the owner (and nothing it owns is trusted)
	how, err := w.p.Check(w.img, w.sum)
	if err != nil || how != ByHash {
		t.Fatalf("%q %v", how, err)
	}
	if _, err := os.Lstat(w.p.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a record file was written by a process that is not the owner: %v", err)
	}
}

func TestNoRecordFileMeansAlwaysHash(t *testing.T) {
	w := newWorld(t)
	for _, p := range []*Proofs{nil, {}} {
		for range 2 {
			before := w.hashes
			if how, err := p.Check(w.img, w.sum); err != nil || how != ByHash || w.hashes != before+1 {
				t.Fatalf("%q %v", how, err)
			}
		}
	}
}

func TestMissingImageIsNotAMismatch(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	if err := os.Remove(w.img); err != nil {
		t.Fatal(err)
	}
	_, err := w.p.Check(w.img, w.sum)
	if err == nil || errors.Is(err, ErrMismatch) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing image: %v", err)
	}
}

// The listing's cache: a file this process hashed is not hashed again while its signature holds, even when the record
// cannot cover it (not root's), but never once the weekly check refused it.
func TestCheckCached(t *testing.T) {
	w := newWorld(t)
	if err := os.Chmod(filepath.Dir(w.img), 0o775); err != nil { // ineligible for records
		t.Fatal(err)
	}
	for i, want := range []How{ByHash, ByMemory, ByMemory} {
		before := w.hashes
		how, err := w.p.CheckCached(w.img, w.sum)
		if err != nil || how != want || (w.hashes > before) != (want == ByHash) {
			t.Fatalf("listing %d: %q %v", i, how, err)
		}
	}
	time.Sleep(10 * time.Millisecond)
	w.write("a base image") // same content, new change time
	if how, _ := w.p.CheckCached(w.img, w.sum); how != ByHash {
		t.Fatalf("after a write: %q", how)
	}
	// The start path never uses what the listing remembered.
	if how, _ := w.p.Check(w.img, w.sum); how != ByHash {
		t.Fatalf("a start used the listing's memory: %q", how)
	}
	// A refusal by the weekly check beats the memory.
	now := time.Now()
	w.setRecord(Record{Path: w.img, Sig: sigFor(t, w.img), SHA256: w.sum, HashedAt: now, RefusedAt: &now, Found: strings.Repeat("1", 64)})
	if how, _ := w.p.CheckCached(w.img, w.sum); how != ByHash {
		t.Fatalf("a refused image came from memory: %q", how)
	}
}

func TestHashMatchesSha256sum(t *testing.T) {
	// More than one read chunk and one drop chunk, and not a multiple of either.
	p := filepath.Join(t.TempDir(), "big")
	b := make([]byte, dropChunk+readChunk+12345)
	for i := range b {
		b[i] = byte(i * 7)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(b)
	got, err := SHA256(p)
	if err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatalf("%s %v", got, err)
	}
}
