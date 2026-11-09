//go:build linux

package wine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// RunsDir is where each run's folder goes, under Limbo's state folder (never shared into a sandbox).
func RunsDir(state string) string { return filepath.Join(state, "wine-runs") }

// keepRuns is how many run folders are kept; older ones are removed when a run starts. The event log, the audit trail,
// is never pruned; a run folder is the detail behind one of its lines.
const keepRuns = 200

// Record is a run's machine-readable record, run.json in its run folder: what ran, under which profile, what it was
// allowed, and how it ended. It is written when the run starts (status "running") and again when it ends, so a record
// still "running" after its process is gone means limbo itself was killed. The wine.start and wine.stop events name
// its path.
type Record struct {
	ID            string     `json:"id"`
	Prefix        string     `json:"prefix"`
	Via           string     `json:"via"` // "cli", or "path" through Limbo's wine command on PATH
	Parent        string     `json:"parent,omitempty"`
	Profile       string     `json:"profile,omitempty"`
	ProfileSHA256 string     `json:"profile_sha256,omitempty"`
	Program       string     `json:"program"`
	Args          []string   `json:"args"`
	ProgramPath   string     `json:"program_path,omitempty"` // the host file the program names, when it names one
	ProgramSHA256 string     `json:"program_sha256,omitempty"`
	ProgramSize   int64      `json:"program_size,omitempty"`
	Cwd           string     `json:"cwd"`
	Arch          string     `json:"arch,omitempty"`
	Windows       string     `json:"windows,omitempty"`
	Started       time.Time  `json:"started"`
	Ended         *time.Time `json:"ended,omitempty"`
	Status        string     `json:"status"` // running, exited, stopped, sandbox_failed
	ExitCode      *int       `json:"exit_code,omitempty"`
	Stopped       string     `json:"stopped,omitempty"` // the signal limbo stopped the program on
	Allowed       Allowed    `json:"allowed"`
	Trace         *Trace     `json:"trace,omitempty"`
}

// Allowed is what the sandbox was given.
type Allowed struct {
	Network string        `json:"network"`
	GPU     bool          `json:"gpu"`
	Display []string      `json:"display"`
	Audio   string        `json:"audio"`
	Shares  []RecordShare `json:"shares"`
	Env     []string      `json:"env"` // names set explicitly (values are not recorded)
}

// RecordShare is one share as the record lists it.
type RecordShare struct {
	Path     string `json:"path"`
	Source   string `json:"source,omitempty"` // when a symlink made it differ from path
	Writable bool   `json:"writable"`
}

// Trace describes the behaviour trace file, when the run was traced.
type Trace struct {
	File      string `json:"file"`
	Channels  string `json:"channels"`
	Bytes     int64  `json:"bytes"`
	Limit     int64  `json:"limit"`
	Truncated bool   `json:"truncated"`
}

func allowed(o Options, s *Sandbox) Allowed {
	a := Allowed{Network: o.Network, GPU: s.GPU, Display: append([]string{}, s.Display...), Audio: s.Audio, Shares: []RecordShare{}, Env: sortedKeys(o.Env)}
	if a.Audio == "" {
		a.Audio = "none"
	}
	for _, sh := range o.Shares {
		rs := RecordShare{Path: sh.Path, Writable: sh.Writable}
		if sh.Source != sh.Path {
			rs.Source = sh.Source
		}
		a.Shares = append(a.Shares, rs)
	}
	return a
}

func (r *Record) save(dir string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "run.json"), append(b, '\n'))
}

// newRunDir makes a run folder named by its start time and a random suffix (so names sort by time), and prunes the
// oldest beyond keepRuns.
func newRunDir(state string, now time.Time) (id, dir string, err error) {
	root := RunsDir(state)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", "", err
	}
	pruneRuns(root, keepRuns-1)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	id = now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
	dir = filepath.Join(root, id)
	return id, dir, os.Mkdir(dir, 0o700)
}

func pruneRuns(root string, keep int) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() && len(e.Name()) > 16 && e.Name()[8] == 'T' {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		_ = os.RemoveAll(filepath.Join(root, names[0]))
		names = names[1:]
	}
}

// maxHash bounds the program file Limbo hashes before a run (a few hundred megabytes take well under a second).
const maxHash = 512 << 20

// hashFile returns a regular file's SHA-256 and size; the hash is empty above maxHash.
func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return "", 0, os.ErrInvalid
	}
	if fi.Size() > maxHash {
		return "", fi.Size(), nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), fi.Size(), nil
}

// clean makes text fit for the event log: valid UTF-8, control and invisible characters replaced, at most n bytes.
func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "?") {
		switch {
		case unicode.IsControl(r), r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// pathList joins paths for an event's detail: comma-separated, with "%" and "," in a path escaped.
func pathList(paths []string) string {
	esc := strings.NewReplacer("%", "%25", ",", "%2C")
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = clean(esc.Replace(p), 512)
	}
	return strings.Join(out, ",")
}
