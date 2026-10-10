// Package events writes Limbo's audit trail: an append-only JSON-lines file.
//
// This file is the contract with Heimdall (see docs/EVENTS.md). Heimdall
// reads it from a separate process and never writes to it, the same
// independence Heimdall keeps from Sarina. It is also the evidence trail for
// analysis reports, so every state change in a guest's life is recorded here
// before the action it describes is attempted.
package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Kinds. Adding one is backwards compatible; renaming or removing one is a
// contract change.
const (
	GuestDefine   = "guest.define"
	GuestStart    = "guest.start"
	GuestStop     = "guest.stop"
	AppLaunch     = "app.launch"
	PolicyApply   = "policy.apply"
	PolicyRemove  = "policy.remove"
	ImageVerified = "image.verified"
	ImageRejected = "image.rejected"
	GateBlocked   = "gate.blocked"

	// Quarantine and validation runs (docs/QUARANTINE.md).
	QuarantineOpen     = "quarantine.open"
	QuarantineRaise    = "quarantine.raise"
	QuarantineAdvisory = "quarantine.advisory"
	QuarantineVerdict  = "quarantine.verdict"
	PolicyRestrict     = "policy.restrict" // firewall replaced with deny-all
	PolicyRelease      = "policy.release"  // original firewall restored
	LinkDown           = "link.down"
	LinkUp             = "link.up"
	RunStart           = "run.start"
	RunEnd             = "run.end"
	RunError           = "run.error" // a run was refused or failed; detail.code is the stable code

	// Hardware passthrough (docs/ARCHITECTURE.md section 4.1).
	PassthroughApprove = "passthrough.approve" // a person approved a time-limited window at a terminal
	PassthroughRevoke  = "passthrough.revoke"
	HardwareStuck      = "hardware.stuck" // a device did not return to the host; reboot needed
)

// Event is one line of the log. Detail holds kind-specific string fields; it is
// strings only so consumers never have to guess types.
type Event struct {
	Time   time.Time         `json:"time"`
	Kind   string            `json:"kind"`
	Guest  string            `json:"guest"`
	Detail map[string]string `json:"detail,omitempty"`
}

// Logger appends events to a file. The zero value is not usable; use Open.
type Logger struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time
}

// Open creates the log (mode 0600, directory 0700) if needed and opens it for
// append. O_APPEND makes each write atomic with respect to other writers.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Emit writes one event and syncs it, so an event describing an action that
// then crashes the host is still on disk.
func (l *Logger) Emit(kind, guest string, detail map[string]string) error {
	b, err := json.Marshal(Event{Time: l.now(), Kind: kind, Guest: guest, Detail: detail})
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return l.f.Sync()
}

// Close closes the underlying file.
func (l *Logger) Close() error { return l.f.Close() }

// Read loads an event log. Lines that are not valid events are skipped and
// counted rather than failing the read: a report over a log with one torn line
// is still worth having, and the count is reported alongside it.
func Read(path string) (evs []Event, skipped int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Event
		if json.Unmarshal(line, &e) != nil || e.Kind == "" {
			skipped++
			continue
		}
		evs = append(evs, e)
	}
	return evs, skipped, sc.Err()
}
