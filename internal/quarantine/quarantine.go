// Package quarantine records which guests are held, why, and what a human
// decided. It is pure state and rules; it does not touch libvirt or the
// firewall (package engine does), and it does not know who is calling (package
// api does, via which socket the request arrived on).
//
// The rules it does enforce are the ones that must hold no matter who asks:
// a level only ever goes up, a record is decided once, and an advisory can
// never change status.
package quarantine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Level is how strongly a guest is held. Higher is stronger.
type Level string

const (
	LevelRestrict Level = "restrict" // deny-all firewall, guest keeps running
	LevelIsolate  Level = "isolate"  // restrict plus the virtual link down
)

func (l Level) rank() int {
	switch l {
	case LevelRestrict:
		return 1
	case LevelIsolate:
		return 2
	}
	return 0
}

// Status of a record.
type Status string

const (
	StatusOpen      Status = "open"      // held, awaiting a human verdict
	StatusSafe      Status = "safe"      // human cleared it; restrictions lifted
	StatusDangerous Status = "dangerous" // human condemned it; stays held
	StatusClosed    Status = "closed"    // a dangerous record the human has finished with
)

// Limits on text that arrives from outside. Advisories and evidence derive from
// guest-controlled data, so they are bounded before being stored or shown.
const (
	maxReason   = 512
	maxAdvisory = 8 << 10
	maxAdvisors = 16
	maxEvidence = 32
	maxEvKey    = 64
	maxEvValue  = 512
)

// Advisory is an opinion attached to a record. Untrusted: see package doc.
type Advisory struct {
	Source string    `json:"source"`
	Time   time.Time `json:"time"`
	Text   string    `json:"text"`
}

// Verdict is a human's decision.
type Verdict struct {
	Value Status    `json:"value"`
	By    string    `json:"by"`
	Note  string    `json:"note"`
	Time  time.Time `json:"time"`
}

// Record is one quarantine.
type Record struct {
	ID       string            `json:"id"`
	Guest    string            `json:"guest"`
	Reason   string            `json:"reason"`
	Source   string            `json:"source"`
	Level    Level             `json:"level"`
	Status   Status            `json:"status"`
	Opened   time.Time         `json:"opened"`
	Evidence map[string]string `json:"evidence,omitempty"`
	Advisory []Advisory        `json:"advisory,omitempty"`
	Verdict  *Verdict          `json:"verdict,omitempty"`
}

// Errors callers can match on.
var (
	ErrNotFound    = errors.New("quarantine: no such record")
	ErrNotOpen     = errors.New("quarantine: record is not open")
	ErrLowerLevel  = errors.New("quarantine: a level can only be raised")
	ErrBadVerdict  = errors.New("quarantine: verdict must be safe or dangerous")
	ErrNotDanger   = errors.New("quarantine: only a dangerous record can be closed")
	ErrBadLevel    = errors.New("quarantine: unknown level")
	ErrTooManyAdvs = errors.New("quarantine: too many advisories on this record")
)

// Store keeps records as one JSON file each (mode 0600) in a directory, so a
// daemon restart loses nothing and a human can read them with cat.
type Store struct {
	mu   sync.Mutex
	dir  string
	recs map[string]*Record
	now  func() time.Time
}

// Open loads (or creates) the store at dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, recs: map[string]*Record{}, now: func() time.Time { return time.Now().UTC() }}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("quarantine: %s is corrupt: %w", e.Name(), err)
		}
		s.recs[r.ID] = &r
	}
	return s, nil
}

// Holding reports whether the guest is currently held: an open or dangerous
// record exists. engine.Up refuses to start a held guest.
func (s *Store) Holding(guest string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if r.Guest == guest && (r.Status == StatusOpen || r.Status == StatusDangerous) {
			return *r, true
		}
	}
	return Record{}, false
}

// Quarantine opens a record for guest, or returns the existing open one. If one
// is already open, the level is raised when the new request is stronger and the
// new reason is noted as evidence, so repeated alerts about one guest do not
// pile up records. created reports whether a new record was made.
func (s *Store) Quarantine(guest, reason, source string, level Level, evidence map[string]string) (rec Record, created bool, err error) {
	if level.rank() == 0 {
		return Record{}, false, ErrBadLevel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if r.Guest == guest && r.Status == StatusOpen {
			if level.rank() > r.Level.rank() {
				r.Level = level
			}
			if r.Evidence == nil {
				r.Evidence = map[string]string{}
			}
			if len(r.Evidence) < maxEvidence {
				r.Evidence[fmt.Sprintf("also[%d]", len(r.Evidence))] = clean(source+": "+reason, maxEvValue)
			}
			return *r, false, s.save(r)
		}
	}
	r := &Record{
		ID: newID(), Guest: guest, Reason: clean(reason, maxReason), Source: clean(source, maxEvKey),
		Level: level, Status: StatusOpen, Opened: s.now(), Evidence: cleanEvidence(evidence),
	}
	s.recs[r.ID] = r
	return *r, true, s.save(r)
}

// Raise increases an open record's level. Lowering is refused: nothing automated
// may loosen a hold, and even a human loosens by verdict, not by level.
func (s *Store) Raise(id string, level Level) (Record, error) {
	if level.rank() == 0 {
		return Record{}, ErrBadLevel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if r.Status != StatusOpen {
		return Record{}, ErrNotOpen
	}
	if level.rank() < r.Level.rank() {
		return Record{}, ErrLowerLevel
	}
	r.Level = level
	return *r, s.save(r)
}

// AddAdvisory attaches an opinion. It cannot change status or level.
func (s *Store) AddAdvisory(id, source, text string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if r.Status != StatusOpen {
		return Record{}, ErrNotOpen
	}
	if len(r.Advisory) >= maxAdvisors {
		return Record{}, ErrTooManyAdvs
	}
	r.Advisory = append(r.Advisory, Advisory{Source: clean(source, maxEvKey), Time: s.now(), Text: clean(text, maxAdvisory)})
	return *r, s.save(r)
}

// Decide records a human verdict on an open record. This is the only way a
// record leaves the open state; the API only exposes it on the admin socket.
func (s *Store) Decide(id string, verdict Status, by, note string) (Record, error) {
	if verdict != StatusSafe && verdict != StatusDangerous {
		return Record{}, ErrBadVerdict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if r.Status != StatusOpen {
		return Record{}, ErrNotOpen
	}
	r.Status = verdict
	r.Verdict = &Verdict{Value: verdict, By: clean(by, maxEvKey), Note: clean(note, maxReason), Time: s.now()}
	return *r, s.save(r)
}

// Close finishes a dangerous record, freeing the guest name for reuse. Human only.
func (s *Store) Close(id, by string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if r.Status != StatusDangerous {
		return Record{}, ErrNotDanger
	}
	r.Status = StatusClosed
	if r.Verdict != nil {
		r.Verdict.Note = clean(r.Verdict.Note+" [closed by "+by+"]", maxReason)
	}
	return *r, s.save(r)
}

// Get returns one record.
func (s *Store) Get(id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return *r, nil
}

// List returns all records, newest first.
func (s *Store) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Opened.After(out[j].Opened) })
	return out
}

func (s *Store) save(r *Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, r.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "q-" + hex.EncodeToString(b[:])
}

// clean bounds a string and strips control characters (other than space), so
// text from a guest cannot smuggle terminal escapes or hidden lines into
// whatever later displays it.
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			continue
		}
		if r == '\n' || r == '\t' {
			r = ' '
		}
		if n+len(string(r)) > max {
			break
		}
		b.WriteRune(r)
		n += len(string(r))
	}
	return b.String()
}

func cleanEvidence(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]string{}
	for _, k := range keys {
		if len(out) >= maxEvidence {
			break
		}
		out[clean(k, maxEvKey)] = clean(in[k], maxEvValue)
	}
	return out
}
