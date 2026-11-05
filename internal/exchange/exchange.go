// Package exchange is the way out of a guest's shared folder.
//
// A guest that may write to its shared folder writes only into its own outbox, /var/lib/limbo/exchange/<guest>, which
// only root can open (the engine refuses any other writable share). Nothing in an outbox reaches a person until it is
// taken: Take copies one file into a root-only scratch folder, so the guest cannot change it afterwards, has ClamAV
// scan the copy, and hands back the copy only if ClamAV finds nothing. A file ClamAV knows is moved into a root-only
// held folder (and out of the outbox) and recorded, so Heimdall can take it into its own quarantine (immunity). If
// ClamAV cannot run, nothing is handed back: no scan, no file.
//
// The bytes go to the person's own process (the limbo CLI, as them), which writes them where they asked, without
// execute or setuid bits. Limbo never writes into $HOME as root.
//
// Names of files come from the guest and are untrusted: a name with control characters or that is not valid UTF-8
// is not listed, and every name is shown as data.
package exchange

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits.
const (
	MaxFileBytes = 2 << 30 // largest file taken out at once
	maxListed    = 1000
	maxPathBytes = 512
	maxWalk      = 20000
)

// Event kinds (docs/EVENTS.md).
const (
	EventFile = "exchange.file" // a file was scanned clean and handed to a person
	EventHeld = "exchange.held" // ClamAV knew a file: it was held and not handed out
	EventFail = "exchange.fail" // a file could not be scanned: not handed out
)

// Scan results.
const (
	Clean    = "clean"
	Infected = "infected"
)

// Scanner scans one file. ClamAV is the real one.
type Scanner interface {
	// Scan returns Clean, or Infected with the signature's name. An error means the file was not scanned.
	Scan(ctx context.Context, path string) (result, signature string, err error)
}

// Emitter writes the audit log.
type Emitter interface {
	Emit(kind, guest string, detail map[string]string) error
}

// Error is a refusal with a stable code and HTTP status.
type Error struct {
	Status                int
	Code, Message, Remedy string
}

func (e *Error) Error() string      { return e.Code + ": " + e.Message + ". Remedy: " + e.Remedy }
func (e *Error) ErrCode() string    { return e.Code }
func (e *Error) ErrMessage() string { return e.Message }
func (e *Error) ErrRemedy() string  { return e.Remedy }
func (e *Error) HTTPStatus() int    { return e.Status }

func refuse(status int, code, remedy, format string, a ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, a...), Remedy: remedy}
}

// Service holds the folders.
type Service struct {
	Root    string // /var/lib/limbo/exchange: one outbox per guest
	Scratch string // root-only folder for the copies being scanned (in the state folder)
	Held    string // root-only folder for files ClamAV knew (in the state folder)
	Scanner Scanner
	Events  Emitter
}

// File is one entry of an outbox.
type File struct {
	Path     string    `json:"path"` // relative to the outbox, "/"-separated; untrusted text from the guest
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// Listing is an outbox's content.
type Listing struct {
	Guest    string `json:"guest"`
	Files    []File `json:"files"`    // never null
	Unlisted int    `json:"unlisted"` // entries not shown: not regular files, unsafe names, or past the limit
}

var guestRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,11}$`)

// Outbox is a guest's outbox folder.
func (s *Service) Outbox(guest string) string { return filepath.Join(s.Root, guest) }

// Prepare makes the outbox (and the root above it) root-only. The engine calls it before a guest with a writable
// share starts.
func Prepare(root, guest string) error {
	if !guestRe.MatchString(guest) {
		return fmt.Errorf("exchange: bad guest name")
	}
	for _, d := range []string{root, filepath.Join(root, guest)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("exchange: %s is not a folder", d)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// safeName: shown to people, so no control or invisible formatting characters, valid UTF-8, bounded.
func safeName(p string) bool {
	if p == "" || len(p) > maxPathBytes || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func (s *Service) open(guest string) (*os.Root, error) {
	if !guestRe.MatchString(guest) {
		return nil, refuse(http.StatusNotFound, "not_found", "give a guest's name", "there is no guest named %q", guest)
	}
	dir := s.Outbox(guest)
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return nil, refuse(http.StatusNotFound, "not_found", "turn on the guest's shared folder first", "guest %q has no outbox", guest)
	}
	return os.OpenRoot(dir)
}

// List shows what a guest left in its outbox.
func (s *Service) List(guest string) (Listing, error) {
	r, err := s.open(guest)
	if err != nil {
		return Listing{}, err
	}
	defer r.Close()
	out := Listing{Guest: guest, Files: []File{}}
	n := 0
	_ = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if p == "." {
			return nil
		}
		n++
		if n > maxWalk {
			return fs.SkipAll
		}
		if err != nil {
			out.Unlisted++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if !safeName(p) {
				out.Unlisted++
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !safeName(p) || len(out.Files) >= maxListed {
			out.Unlisted++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			out.Unlisted++
			return nil
		}
		out.Files = append(out.Files, File{Path: p, Size: info.Size(), Modified: info.ModTime().UTC()})
		return nil
	})
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
	return out, nil
}

// Taken is a file that passed the scan: a private copy the caller streams and then calls Close on.
type Taken struct {
	File   *os.File
	Path   string // the relative name, as listed
	SHA256 string
	Size   int64
	tmp    string
}

// Close removes the private copy.
func (t *Taken) Close() error {
	t.File.Close()
	return os.Remove(t.tmp)
}

func cleanRel(p string) (string, bool) {
	if !safeName(p) || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return "", false
	}
	c := path.Clean(p)
	if c != p || c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

func (s *Service) emit(kind, guest string, d map[string]string) error {
	if s.Events == nil {
		return nil
	}
	return s.Events.Emit(kind, guest, d)
}

// Take copies one file out of the outbox, scans the copy, and returns it if ClamAV finds nothing. by names who asked
// (for the record).
func (s *Service) Take(ctx context.Context, guest, rel string, detail map[string]string) (*Taken, error) {
	p, ok := cleanRel(rel)
	if !ok {
		return nil, refuse(http.StatusBadRequest, "bad_request", "use a path exactly as the listing shows it", "that is not a file name in the outbox")
	}
	r, err := s.open(guest)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// os.Root never leaves the outbox, whatever links the guest made; O_NOFOLLOW refuses a link as the last part.
	src, err := r.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refuse(http.StatusNotFound, "not_found", "list the outbox again", "there is no such file in %s's outbox", guest)
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, refuse(http.StatusBadRequest, "not_a_file", "only plain files can be taken out", "that is not a plain file")
	}
	if fi.Size() > MaxFileBytes {
		return nil, refuse(http.StatusRequestEntityTooLarge, "too_large", "split it inside the guest", "the file is larger than %d bytes", int64(MaxFileBytes))
	}
	for _, d := range []string{s.Scratch, s.Held} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	tmp, err := os.CreateTemp(s.Scratch, "take-*")
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, MaxFileBytes+1))
	if err == nil && n > MaxFileBytes {
		err = errors.New("the file grew past the limit while it was copied")
	}
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, refuse(http.StatusInternalServerError, "copy_failed", "try again", "copying the file failed: %v", err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if detail == nil {
		detail = map[string]string{}
	}
	detail["path"], detail["sha256"], detail["size"] = clip(p, 200), sum, fmt.Sprint(n)

	result, sig, scanErr := Clean, "", error(nil)
	if s.Scanner == nil {
		scanErr = errors.New("no scanner configured")
	} else {
		result, sig, scanErr = s.Scanner.Scan(ctx, tmp.Name())
	}
	if scanErr != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		detail["reason"] = clip(scanErr.Error(), 200)
		_ = s.emit(EventFail, guest, detail)
		return nil, refuse(http.StatusServiceUnavailable, "scanner_unavailable", "make sure ClamAV works ('clamscan --version'; its database is updated by freshclam), then try again", "the file could not be scanned, so it stays in the outbox")
	}
	if result != Clean {
		held := filepath.Join(s.Held, sum)
		tmp.Close()
		_ = os.Rename(tmp.Name(), held)
		_ = os.Chmod(held, 0o400)
		_ = r.Remove(p) // out of the outbox; the held copy is the one kept
		detail["signature"] = clip(sig, 200)
		_ = s.emit(EventHeld, guest, detail)
		return nil, refuse(http.StatusConflict, "infected", "nothing to do: it is held, and Heimdall can take it into its quarantine", "ClamAV knows this file (%s); it was held and not handed out", clip(sig, 120))
	}
	detail["scan"] = Clean
	if err := s.emit(EventFile, guest, detail); err != nil {
		// A file that leaves without a record does not leave.
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("cannot record the file in the audit log: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	return &Taken{File: tmp, Path: p, SHA256: sum, Size: n, tmp: tmp.Name()}, nil
}

func clip(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ClamAV scans with clamdscan (the running clamd, fast) and falls back to clamscan (loads the database itself, slow)
// when clamd is not there. Exit 0 is clean, 1 is a match, anything else is an error.
type ClamAV struct{}

var foundRe = regexp.MustCompile(`: (.+) FOUND$`)

func (ClamAV) Scan(ctx context.Context, p string) (string, string, error) {
	var lastErr error
	for _, argv := range [][]string{
		{"clamdscan", "--no-summary", "--fdpass", "--", p},
		{"clamscan", "--no-summary", "--", p},
	} {
		if _, err := exec.LookPath(argv[0]); err != nil {
			lastErr = err
			continue
		}
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
			return Clean, "", nil
		case errors.As(err, &ee) && ee.ExitCode() == 1:
			sig := "unknown signature"
			for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
				if m := foundRe.FindStringSubmatch(line); m != nil {
					sig = m[1]
				}
			}
			return Infected, sig, nil
		}
		lastErr = fmt.Errorf("%s: %v", argv[0], err)
	}
	if lastErr == nil {
		lastErr = errors.New("no ClamAV scanner found")
	}
	return "", "", lastErr
}
