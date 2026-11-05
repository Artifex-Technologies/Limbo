package license

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// Windows license keys (docs/SETTINGS_PAGE.md, "Windows licenses").
//
// The keys are kept in a folder only root can open (/etc/limbo/licenses, 0700; each file 0600). Everything that leaves
// this package for display is masked. The full key leaves only through Reveal (the admin socket: root, so a password)
// and KeyForInstall (for the one moment a Windows guest installs; no installer exists yet, so nothing calls it). It is
// never put in an error, an event, a report or a response on the agent or control sockets.

// DefaultDir is where limbo serve keeps the keys.
const DefaultDir = "/etc/limbo/licenses"

// keyRe is a Windows product key: five groups of five letters or digits.
var keyRe = regexp.MustCompile(`^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$`)

// keyLikeRe finds something that looks like a key inside other text (a name), so a key typed into the wrong box is refused.
var keyLikeRe = regexp.MustCompile(`(?i)[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}`)

var idRe = regexp.MustCompile(`^lic-[0-9a-f]{8}$`)

var guestRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,11}$`)

const (
	maxName     = 80
	maxLicenses = 64
	maxAssigned = 32
)

// Errors with no key in them, ever.
var (
	ErrBadKey      = errors.New("license: that is not a Windows product key (five groups of five letters or digits, separated by hyphens)")
	ErrBadName     = errors.New("license: the name must be 1-80 printable characters and must not contain a key")
	ErrNoLicense   = errors.New("license: there is no license with that id")
	ErrBadGuest    = errors.New("license: not a guest name")
	ErrTooMany     = errors.New("license: too many licenses or assignments")
	ErrDuplicate   = errors.New("license: that key is already stored")
	ErrUnsafeStore = errors.New("license: the license folder is not root-only (0700, owned by root)")
)

// entry is one stored license (the file's content).
type entry struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Key      string    `json:"key"`
	Added    time.Time `json:"added"`
	Assigned []string  `json:"assigned"`
}

// Masked is what may be shown anywhere: no key, only its last group.
type Masked struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Masked   string    `json:"masked"` // "XXXXX-XXXXX-XXXXX-XXXXX-7K2QF"
	Added    time.Time `json:"added"`
	Assigned []string  `json:"assigned"` // guest names; never null
}

// Store is the folder of keys.
type Store struct {
	Dir string
	mu  sync.Mutex
	// requireRoot is off in tests (which do not run as root).
	requireRoot bool
}

// OpenStore prepares the folder (creating it 0700) and refuses one that others could read or write.
func OpenStore(dir string) (*Store, error) {
	return openStore(dir, true)
}

func openStore(dir string, requireRoot bool) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return nil, ErrUnsafeStore
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && requireRoot && st.Uid != 0 {
		return nil, ErrUnsafeStore
	}
	return &Store{Dir: dir, requireRoot: requireRoot}, nil
}

// NormalizeKey upper-cases a key and trims spaces around it; it does not judge validity beyond the shape.
func NormalizeKey(k string) (string, error) {
	k = strings.ToUpper(strings.TrimSpace(k))
	if !keyRe.MatchString(k) {
		return "", ErrBadKey
	}
	return k, nil
}

// MaskKey hides all but the last group.
func MaskKey(k string) string {
	if len(k) < 5 {
		return "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
	}
	return "XXXXX-XXXXX-XXXXX-XXXXX-" + k[len(k)-5:]
}

func cleanName(n string) (string, error) {
	n = strings.TrimSpace(n)
	if n == "" || len(n) > maxName || keyLikeRe.MatchString(n) {
		return "", ErrBadName
	}
	for _, r := range n {
		if !unicode.IsPrint(r) {
			return "", ErrBadName
		}
	}
	return n, nil
}

func (s *Store) load() ([]*entry, error) {
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []*entry
	for _, d := range ents {
		name := d.Name()
		if !strings.HasSuffix(name, ".json") || !idRe.MatchString(strings.TrimSuffix(name, ".json")) {
			continue
		}
		e, err := s.read(strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue // a damaged file is left alone, not shown
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Added.Before(out[j].Added) || (out[i].Added.Equal(out[j].Added) && out[i].ID < out[j].ID)
	})
	return out, nil
}

func (s *Store) read(id string) (*entry, error) {
	if !idRe.MatchString(id) {
		return nil, ErrNoLicense
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, id+".json"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrNoLicense
	}
	defer f.Close()
	var e entry
	if err := json.NewDecoder(f).Decode(&e); err != nil || e.ID != id {
		return nil, ErrNoLicense
	}
	if e.Assigned == nil {
		e.Assigned = []string{}
	}
	return &e, nil
}

func (s *Store) write(e *entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".lic-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(s.Dir, e.ID+".json"))
}

func (e *entry) masked() Masked {
	a := append([]string{}, e.Assigned...)
	return Masked{ID: e.ID, Name: e.Name, Masked: MaskKey(e.Key), Added: e.Added, Assigned: a}
}

// Add stores a key under a name and returns its masked view.
func (s *Store) Add(name, key string) (Masked, error) {
	k, err := NormalizeKey(key)
	if err != nil {
		return Masked{}, err
	}
	n, err := cleanName(name)
	if err != nil {
		return Masked{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return Masked{}, err
	}
	if len(all) >= maxLicenses {
		return Masked{}, ErrTooMany
	}
	for _, e := range all {
		if e.Key == k {
			return Masked{}, ErrDuplicate
		}
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	e := &entry{ID: "lic-" + hex.EncodeToString(b[:]), Name: n, Key: k, Added: time.Now().UTC().Truncate(time.Second), Assigned: []string{}}
	if err := s.write(e); err != nil {
		return Masked{}, fmt.Errorf("license: storing the key failed")
	}
	return e.masked(), nil
}

// List returns every license, masked. Never nil.
func (s *Store) List() ([]Masked, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]Masked, 0, len(all))
	for _, e := range all {
		out = append(out, e.masked())
	}
	return out, nil
}

// Get returns one license, masked.
func (s *Store) Get(id string) (Masked, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.read(id)
	if err != nil {
		return Masked{}, err
	}
	return e.masked(), nil
}

// Remove deletes a license.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.read(id); err != nil {
		return err
	}
	return os.Remove(filepath.Join(s.Dir, id+".json"))
}

// Reveal returns the full key. Root only (the admin socket); the caller must not log it.
func (s *Store) Reveal(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.read(id)
	if err != nil {
		return "", err
	}
	return e.Key, nil
}

// Assign records that guest uses this license. A guest uses at most one: an earlier assignment elsewhere is removed.
func (s *Store) Assign(id, guest string) (Masked, error) {
	if !guestRe.MatchString(guest) {
		return Masked{}, ErrBadGuest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return Masked{}, err
	}
	var target *entry
	for _, e := range all {
		if e.ID == id {
			target = e
		}
	}
	if target == nil {
		return Masked{}, ErrNoLicense
	}
	for _, e := range all {
		if e != target && contains(e.Assigned, guest) {
			e.Assigned = without(e.Assigned, guest)
			if err := s.write(e); err != nil {
				return Masked{}, err
			}
		}
	}
	if !contains(target.Assigned, guest) {
		if len(target.Assigned) >= maxAssigned {
			return Masked{}, ErrTooMany
		}
		target.Assigned = append(target.Assigned, guest)
		sort.Strings(target.Assigned)
		if err := s.write(target); err != nil {
			return Masked{}, err
		}
	}
	return target.masked(), nil
}

// Unassign removes guest from the license.
func (s *Store) Unassign(id, guest string) (Masked, error) {
	if !guestRe.MatchString(guest) {
		return Masked{}, ErrBadGuest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.read(id)
	if err != nil {
		return Masked{}, err
	}
	if contains(e.Assigned, guest) {
		e.Assigned = without(e.Assigned, guest)
		if err := s.write(e); err != nil {
			return Masked{}, err
		}
	}
	return e.masked(), nil
}

// AssignedTo returns the id of the license a guest uses, or "".
func (s *Store) AssignedTo(guest string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return ""
	}
	for _, e := range all {
		if contains(e.Assigned, guest) {
			return e.ID
		}
	}
	return ""
}

// KeyForInstall returns the key assigned to guest, for the one moment its Windows installs (the unattended answer
// file). Not called yet: Limbo has no Windows installer (no Windows ISO or license has existed to build it against).
func (s *Store) KeyForInstall(guest string) (string, error) {
	id := s.AssignedTo(guest)
	if id == "" {
		return "", ErrNoLicense
	}
	return s.Reveal(id)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func without(xs []string, x string) []string {
	out := []string{}
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}
