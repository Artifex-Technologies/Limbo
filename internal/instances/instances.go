// Package instances is what the Settings page shows and changes (docs/SETTINGS_PAGE.md): the guests a person keeps,
// their figures, and the few things about them a person may change.
//
// An instance is a manifest root registered in /etc/limbo/instances/<name>.json (through the admin socket, so with
// the password). Its manifest is never edited afterwards. What a person changes (processors, memory, disk size,
// shared folder, clipboard, devices) is kept apart, in the daemon's state folder, and laid over the manifest when the
// guest starts, inside bounds: a change can never give a guest a network, a host folder of its choosing, or a device
// the manifest did not already name.
//
// Who may ask is decided by the api package (which socket, and the password switch). This package adds the rules
// that hold whoever asks: an instance with an owner is changed only by that person (or root); a guest Heimdall holds
// is not started, stopped, changed or emptied except by root; and a held guest's disk is evidence, never freed.
package instances

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/disk"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

// Default locations under limbo serve.
const (
	DefaultDir          = "/etc/limbo/instances"
	DefaultLimboRoot    = "/var/lib/limbo"
	DefaultExchangeRoot = "/var/lib/limbo/exchange"
)

// Guests is the part of the engine this package uses.
type Guests interface {
	Up(ctx context.Context, m *manifest.Manifest) error
	Down(ctx context.Context, m *manifest.Manifest) error
	Defined(ctx context.Context, m *manifest.Manifest) bool
	// RunningDomains lists the libvirt domains that are running now (one virsh call).
	RunningDomains(ctx context.Context) (map[string]bool, error)
	CleanState(m *manifest.Manifest)
}

// Holder says whether Heimdall (or a person) holds a guest. *quarantine.Store satisfies it.
type Holder interface {
	Holding(guest string) (quarantine.Record, bool)
}

// Emitter writes the audit log.
type Emitter interface {
	Emit(kind, guest string, detail map[string]string) error
}

// Caller is who asked: root through the admin socket, or a member of limbo-users through user.sock.
type Caller struct {
	Admin bool
	UID   int
	User  string // account name, "" if unknown
}

// Error is a refusal with a stable code, a plain message, a one-line remedy and the HTTP status it maps to.
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

// Codes (docs/SETTINGS_PAGE.md, "Protocol").
const (
	CodeNotFound    = "not_found"
	CodeBadRequest  = "bad_request"
	CodeOutOfRange  = "out_of_range"
	CodeNotOwner    = "not_owner"
	CodeHeld        = "held_by_heimdall"
	CodeRunning     = "running"
	CodeNotRunning  = "not_running"
	CodeReadOnly    = "not_an_instance"
	CodeStartFailed = "start_failed"
	CodeStopFailed  = "stop_failed"
	CodeExists      = "exists"
)

// Entry is one registered instance (the file in Dir).
type Entry struct {
	Manifest manifest.Manifest `json:"manifest"`
	// Owner is the account that may change it through user.sock. Empty: any member of limbo-users.
	Owner string `json:"owner,omitempty"`
}

// Overrides are the changes a person made, laid over the manifest at start. Zero values mean "as the manifest says".
type Overrides struct {
	CPUs         int       `json:"cpus,omitempty"`
	MemoryMB     int       `json:"memory_mb,omitempty"`
	DiskGB       int       `json:"disk_gb,omitempty"`
	SharedFolder string    `json:"shared_folder,omitempty"` // "", "off" or "on"
	Clipboard    string    `json:"clipboard,omitempty"`
	Devices      *[]string `json:"devices,omitempty"` // a subset of the manifest's devices.pci
}

// Change is a request to change an instance. Every field is optional; what is absent stays as it is.
type Change struct {
	CPUs         *int      `json:"cpus"`
	MemoryMB     *int      `json:"memory_mb"`
	DiskGB       *int      `json:"disk_gb"`
	SharedFolder *string   `json:"shared_folder"`
	Clipboard    *string   `json:"clipboard"`
	Devices      *[]string `json:"devices"`
}

// Hold describes why a guest is held.
type Hold struct {
	ID     string    `json:"id"`
	Status string    `json:"status"` // open | dangerous
	Level  string    `json:"level"`  // restrict | isolate
	By     string    `json:"by"`     // heimdall | person
	Since  time.Time `json:"since"`
}

// Disk is a guest's disk figures, in bytes.
type Disk struct {
	BaseBytes    int64 `json:"base_bytes"`    // the base image (shared by every guest built from it)
	OwnBytes     int64 `json:"own_bytes"`     // the guest's own changes (its overlay)
	VirtualBytes int64 `json:"virtual_bytes"` // the size the guest sees; 0 if unknown
	DiskGB       int   `json:"disk_gb"`       // the size asked for (0: the image's own)
}

// View is one row of the Settings page.
type View struct {
	Name           string    `json:"name"`
	Kind           string    `json:"kind"`  // instance | run | manual
	OS             string    `json:"os"`    // linux | windows
	State          string    `json:"state"` // running | stopped | held
	Running        bool      `json:"running"`
	Address        string    `json:"address"` // the guest's IPv4 address while it is up, else ""
	CPUs           int       `json:"cpus"`
	MemoryMB       int       `json:"memory_mb"`
	Network        string    `json:"network"` // none | allowlist | internet-only (what the manifest gives; a hold cuts it)
	Disk           Disk      `json:"disk"`
	SharedFolder   string    `json:"shared_folder"` // off | read-only | writable
	Clipboard      string    `json:"clipboard"`     // off | text
	Devices        []string  `json:"devices"`       // never null
	Disposable     bool      `json:"disposable"`
	Owner          string    `json:"owner"`
	Mine           bool      `json:"mine"` // the caller may change it (ownership only; the switch is separate)
	Hold           *Hold     `json:"hold"` // null unless held
	HeldByHeimdall bool      `json:"held_by_heimdall"`
	Pending        bool      `json:"pending"` // changed while running: the change applies at the next start
	License        string    `json:"license"` // id of the Windows license assigned to it, or ""
	Overrides      Overrides `json:"overrides"`
}

// Space is how much of the host's disk Limbo uses, in bytes.
type Space struct {
	TotalBytes    int64 `json:"total_bytes"`    // everything under /var/lib/limbo, plus base images kept elsewhere
	ImagesBytes   int64 `json:"images_bytes"`   // /var/lib/limbo/images
	GuestsBytes   int64 `json:"guests_bytes"`   // guests' own disks (overlays) in the state folder
	EvidenceBytes int64 `json:"evidence_bytes"` // disks kept as evidence of condemned guests
	ExchangeBytes int64 `json:"exchange_bytes"` // shared-folder outboxes waiting to be scanned
}

// Service answers for the instances.
type Service struct {
	Dir          string // registry: /etc/limbo/instances (root writes; the daemon reads)
	StateDir     string // the daemon's state folder
	LimboRoot    string // /var/lib/limbo, for the space figures
	ExchangeRoot string // where a guest's shared-folder outbox lives (package exchange scans it)
	Guests       Guests
	Holds        Holder
	Events       Emitter
	// LicenseOf returns the id of the license assigned to a guest, or "". May be nil.
	LicenseOf func(guest string) string
	// HostLimits returns the host's processors and memory (MiB); replaced in tests.
	HostLimits func() (cpus, memMB int)

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,11}$`)
var runRe = regexp.MustCompile(`^r[0-9a-f]{8}$`)
var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (s *Service) lock(name string) func() {
	s.mu.Lock()
	if s.locks == nil {
		s.locks = map[string]*sync.Mutex{}
	}
	l := s.locks[name]
	if l == nil {
		l = &sync.Mutex{}
		s.locks[name] = l
	}
	s.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func (s *Service) entryPath(name string) string { return filepath.Join(s.Dir, name+".json") }
func (s *Service) overridePath(name string) string {
	return filepath.Join(s.StateDir, "instances", name+".json")
}

func notFound(name string) *Error {
	return refuse(http.StatusNotFound, CodeNotFound, "list the instances (GET /v1/instances) for the names that exist", "there is no instance named %q", name)
}

// load reads a registered instance. Only files root could have written count.
func (s *Service) load(name string) (*Entry, error) {
	if !nameRe.MatchString(name) {
		return nil, notFound(name)
	}
	f, err := os.OpenFile(s.entryPath(name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, notFound(name)
	}
	defer f.Close()
	var e Entry
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, refuse(http.StatusInternalServerError, CodeBadRequest, "ask root to fix or re-add it (limbo instance add)", "the record of instance %q is damaged", name)
	}
	raw, _ := json.Marshal(e.Manifest)
	m, err := manifest.Parse(raw)
	if err != nil || m.Name != name {
		return nil, refuse(http.StatusInternalServerError, CodeBadRequest, "ask root to fix or re-add it (limbo instance add)", "the manifest of instance %q is not valid", name)
	}
	e.Manifest = *m
	return &e, nil
}

func (s *Service) overrides(name string) Overrides {
	var o Overrides
	b, err := os.ReadFile(s.overridePath(name))
	if err == nil {
		_ = json.Unmarshal(b, &o)
	}
	return o
}

func (s *Service) saveOverrides(name string, o Overrides) error {
	dir := filepath.Dir(s.overridePath(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(o, "", "  ")
	tmp := s.overridePath(name) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.overridePath(name))
}

// Effective is the manifest a registered instance starts from: its own, with the person's changes laid over it.
func (s *Service) Effective(e *Entry, o Overrides) (*manifest.Manifest, error) {
	m := e.Manifest // copy
	m.Devices.PCI = append([]string(nil), e.Manifest.Devices.PCI...)
	if o.CPUs > 0 {
		m.CPUs = o.CPUs
	}
	if o.MemoryMB > 0 {
		m.MemoryMB = o.MemoryMB
	}
	if o.DiskGB > 0 {
		m.DiskGB = o.DiskGB
	}
	switch o.SharedFolder {
	case "off":
		m.ExchangeDir, m.ExchangeWritable = "", false
	case "on":
		if m.ExchangeDir == "" {
			// The guest's outbox: it writes there, and nothing reaches the person until it is scanned (package exchange).
			m.ExchangeDir, m.ExchangeWritable = filepath.Join(s.ExchangeRoot, m.Name), true
		}
	}
	if o.Clipboard != "" {
		m.Clipboard = o.Clipboard
	}
	if o.Devices != nil {
		m.Devices.PCI = append([]string(nil), (*o.Devices)...)
	}
	if err := m.Validate(); err != nil {
		return nil, refuse(http.StatusBadRequest, CodeOutOfRange, "choose values the guest's manifest allows", "%v", err)
	}
	return &m, nil
}

func (s *Service) hold(name string) (*Hold, bool) {
	if s.Holds == nil {
		return nil, false
	}
	rec, held := s.Holds.Holding(name)
	if !held {
		return nil, false
	}
	by := "person"
	if !strings.HasPrefix(rec.Source, "human") && !strings.HasPrefix(rec.Source, "admin") {
		by = "heimdall"
	}
	return &Hold{ID: rec.ID, Status: string(rec.Status), Level: string(rec.Level), By: by, Since: rec.Opened}, true
}

func shared(m *manifest.Manifest) string {
	switch {
	case m.ExchangeDir == "":
		return "off"
	case m.ExchangeWritable:
		return "writable"
	}
	return "read-only"
}

func (s *Service) view(m *manifest.Manifest, kind string, e *Entry, o Overrides, running map[string]bool, c Caller) View {
	v := View{
		Name: m.Name, Kind: kind, OS: m.OS, CPUs: m.CPUs, MemoryMB: m.MemoryMB, Network: m.Network.Mode,
		SharedFolder: shared(m), Clipboard: m.Clipboard, Devices: append([]string{}, m.Devices.PCI...),
		Disposable: m.Disposable, Overrides: o,
	}
	v.Running = running[virt.DomainName(m)]
	v.State = "stopped"
	if v.Running {
		v.State = "running"
	}
	if cur, err := s.startedFrom(m.Name); err == nil && cur.Subnet > 0 && (v.Running || s.Guests.Defined(context.Background(), cur)) {
		v.Address = virt.Addr(cur).Guest.String()
	}
	if h, held := s.hold(m.Name); held {
		v.Hold, v.State = h, "held"
		v.HeldByHeimdall = h.By == "heimdall"
	}
	ownPath := filepath.Join(s.StateDir, virt.DiskName(m))
	v.Disk = Disk{BaseBytes: disk.Allocated(m.Image.Path), OwnBytes: disk.Allocated(ownPath), DiskGB: m.DiskGB}
	if n, err := disk.VirtualSize(ownPath); err == nil {
		v.Disk.VirtualBytes = n
	} else if n, err := disk.VirtualSize(m.Image.Path); err == nil {
		v.Disk.VirtualBytes = n
	}
	if e != nil {
		v.Owner = e.Owner
		v.Mine = c.Admin || e.Owner == "" || e.Owner == c.User
		if v.Running {
			// What runs is the manifest it was started from; a newer change waits for the next start.
			if cur, err := s.startedFrom(m.Name); err == nil {
				v.Pending = cur.CPUs != m.CPUs || cur.MemoryMB != m.MemoryMB || cur.DiskGB != m.DiskGB ||
					shared(cur) != shared(m) || cur.Clipboard != m.Clipboard || strings.Join(cur.Devices.PCI, ",") != strings.Join(m.Devices.PCI, ",")
			}
		}
	}
	if s.LicenseOf != nil {
		v.License = s.LicenseOf(m.Name)
	}
	return v
}

// startedFrom reads the copy of the manifest a running guest was started from (engine.Up writes it).
func (s *Service) startedFrom(name string) (*manifest.Manifest, error) {
	return manifest.Load(filepath.Join(s.StateDir, name+".manifest.json"))
}

func (s *Service) running(ctx context.Context) map[string]bool {
	r, err := s.Guests.RunningDomains(ctx)
	if err != nil {
		return map[string]bool{}
	}
	return r
}

// List returns every instance, then every other guest Limbo has running (validation and sample runs, guests started
// by hand with limbo up), sorted by name within each kind. Never nil.
func (s *Service) List(ctx context.Context, c Caller) []View {
	running := s.running(ctx)
	out := []View{}
	seen := map[string]bool{}
	ents, _ := os.ReadDir(s.Dir)
	for _, d := range ents {
		name, ok := strings.CutSuffix(d.Name(), ".json")
		if !ok || !nameRe.MatchString(name) {
			continue
		}
		e, err := s.load(name)
		if err != nil {
			continue
		}
		o := s.overrides(name)
		m, err := s.Effective(e, o)
		if err != nil {
			m = &e.Manifest
		}
		out = append(out, s.view(m, "instance", e, o, running, c))
		seen[name] = true
	}
	files, _ := os.ReadDir(s.StateDir)
	var others []View
	for _, d := range files {
		name, ok := strings.CutSuffix(d.Name(), ".manifest.json")
		if !ok || seen[name] || !nameRe.MatchString(name) {
			continue
		}
		m, err := s.startedFrom(name)
		if err != nil || m.Name != name {
			continue
		}
		kind := "manual"
		if runRe.MatchString(name) {
			kind = "run"
		}
		others = append(others, s.view(m, kind, nil, Overrides{}, running, c))
	}
	sort.Slice(others, func(i, j int) bool {
		if others[i].Kind != others[j].Kind {
			return others[i].Kind < others[j].Kind
		}
		return others[i].Name < others[j].Name
	})
	return append(out, others...)
}

// Get returns one guest's row.
func (s *Service) Get(ctx context.Context, name string, c Caller) (View, error) {
	for _, v := range s.List(ctx, c) {
		if v.Name == name {
			return v, nil
		}
	}
	return View{}, notFound(name)
}

// Space adds up what Limbo takes on the host's disk.
func (s *Service) Space(ctx context.Context) Space {
	sp := Space{
		TotalBytes:    disk.Usage(s.LimboRoot),
		ImagesBytes:   disk.Usage(filepath.Join(s.LimboRoot, "images")),
		EvidenceBytes: disk.Usage(filepath.Join(s.StateDir, "evidence")),
		ExchangeBytes: disk.Usage(s.ExchangeRoot),
	}
	files, _ := os.ReadDir(s.StateDir)
	for _, d := range files {
		if strings.HasSuffix(d.Name(), ".qcow2") && d.Type().IsRegular() {
			sp.GuestsBytes += disk.Allocated(filepath.Join(s.StateDir, d.Name()))
		}
	}
	// Base images kept outside Limbo's folder are Limbo's use of the disk too; each counted once.
	base := map[string]bool{}
	ents, _ := os.ReadDir(s.Dir)
	for _, d := range ents {
		name, ok := strings.CutSuffix(d.Name(), ".json")
		if !ok {
			continue
		}
		if e, err := s.load(name); err == nil {
			p := filepath.Clean(e.Manifest.Image.Path)
			if !base[p] && !strings.HasPrefix(p, filepath.Clean(s.LimboRoot)+"/") {
				base[p] = true
				sp.TotalBytes += disk.Allocated(p)
			}
		}
	}
	return sp
}

// mayChange applies the rules that hold whoever asks through user.sock: the instance is registered, the caller owns
// it, and Heimdall does not hold it.
func (s *Service) mayChange(name string, c Caller) (*Entry, error) {
	e, err := s.load(name)
	if err != nil {
		if nameRe.MatchString(name) {
			if _, err2 := os.Stat(filepath.Join(s.StateDir, name+".manifest.json")); err2 == nil {
				return nil, refuse(http.StatusConflict, CodeReadOnly, "only guests registered as instances (limbo instance add) can be changed here", "%q is a run or a guest started by hand, not an instance", name)
			}
		}
		return nil, err
	}
	if !c.Admin && e.Owner != "" && e.Owner != c.User {
		return nil, refuse(http.StatusForbidden, CodeNotOwner, "ask "+e.Owner+" or use the password", "instance %q belongs to %s", name, e.Owner)
	}
	if h, held := s.hold(name); held && !c.Admin {
		return nil, refuse(http.StatusConflict, CodeHeld, "decide about it on Heimdall's page (Settings > Security), which needs the password", "instance %q is held (%s, %s)", name, h.ID, h.Status)
	}
	return e, nil
}

func (s *Service) audit(kind, guest string, c Caller, detail map[string]string) error {
	if s.Events == nil {
		return nil
	}
	if detail == nil {
		detail = map[string]string{}
	}
	if c.Admin {
		detail["principal"] = "admin"
	} else {
		detail["principal"] = "user"
	}
	detail["peer"] = fmt.Sprintf("uid=%d", c.UID)
	return s.Events.Emit(kind, guest, detail)
}

// Start starts an instance from its effective manifest.
func (s *Service) Start(ctx context.Context, name string, c Caller) (View, error) {
	e, err := s.mayChange(name, c)
	if err != nil {
		return View{}, err
	}
	unlock := s.lock(name)
	defer unlock()
	o := s.overrides(name)
	m, err := s.Effective(e, o)
	if err != nil {
		return View{}, err
	}
	if s.running(ctx)[virt.DomainName(m)] {
		return View{}, refuse(http.StatusConflict, CodeRunning, "stop it first, or leave it running", "instance %q is already running", name)
	}
	if err := s.audit(EventRequest, name, c, map[string]string{"action": "start"}); err != nil {
		return View{}, err
	}
	if s.Guests.Defined(ctx, m) {
		// It stopped by itself (the guest shut down): clear what is left before starting it again.
		prev, perr := s.startedFrom(name)
		if perr != nil {
			prev = m
		}
		_ = s.Guests.Down(ctx, prev)
	}
	if err := s.Guests.Up(ctx, m); err != nil {
		return View{}, refuse(http.StatusInternalServerError, CodeStartFailed, "see 'limbo doctor' and the Limbo log", "instance %q did not start: %v", name, err)
	}
	return s.Get(ctx, name, c)
}

// Stop stops an instance. Its own disk stays.
func (s *Service) Stop(ctx context.Context, name string, c Caller) (View, error) {
	if _, err := s.mayChange(name, c); err != nil {
		return View{}, err
	}
	unlock := s.lock(name)
	defer unlock()
	m, err := s.startedFrom(name)
	if err != nil || !s.Guests.Defined(ctx, m) {
		return View{}, refuse(http.StatusConflict, CodeNotRunning, "nothing to do", "instance %q is not running", name)
	}
	if err := s.audit(EventRequest, name, c, map[string]string{"action": "stop"}); err != nil {
		return View{}, err
	}
	if err := s.Guests.Down(ctx, m); err != nil {
		return View{}, refuse(http.StatusInternalServerError, CodeStopFailed, "see the Limbo log; root can run 'limbo down'", "instance %q did not stop cleanly: %v", name, err)
	}
	s.Guests.CleanState(m)
	return s.Get(ctx, name, c)
}

// HostLimits reads the host's processors and memory.
func HostLimits() (int, int) {
	mem := 0
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var kb int
		for _, line := range strings.Split(string(b), "\n") {
			if _, err := fmt.Sscanf(line, "MemTotal: %d kB", &kb); err == nil {
				mem = kb / 1024
				break
			}
		}
	}
	return runtime.NumCPU(), mem
}

// hostReserveMB is memory never given to one guest, so the host keeps working.
const hostReserveMB = 2048

// Configure applies a change, within bounds. On a running guest it is saved and applies at the next start.
func (s *Service) Configure(ctx context.Context, name string, ch Change, c Caller) (View, error) {
	e, err := s.mayChange(name, c)
	if err != nil {
		return View{}, err
	}
	unlock := s.lock(name)
	defer unlock()
	o := s.overrides(name)
	cpus, memMB := 64, 1<<20
	if s.HostLimits != nil {
		cpus, memMB = s.HostLimits()
	}
	bad := func(remedy, format string, a ...any) (View, error) {
		return View{}, refuse(http.StatusBadRequest, CodeOutOfRange, remedy, format, a...)
	}
	changed := []string{}
	if ch.CPUs != nil {
		if *ch.CPUs < 1 || *ch.CPUs > cpus {
			return bad(fmt.Sprintf("choose 1 to %d", cpus), "processors must be 1 to %d (this computer has %d)", cpus, cpus)
		}
		o.CPUs = *ch.CPUs
		changed = append(changed, "cpus")
	}
	if ch.MemoryMB != nil {
		limit := memMB - hostReserveMB
		if limit < 512 {
			limit = 512
		}
		if *ch.MemoryMB < 512 || *ch.MemoryMB > limit {
			return bad(fmt.Sprintf("choose 512 to %d MiB", limit), "memory must be 512 to %d MiB (the computer keeps %d MiB for itself)", limit, hostReserveMB)
		}
		o.MemoryMB = *ch.MemoryMB
		changed = append(changed, "memory_mb")
	}
	if ch.DiskGB != nil {
		cur := int64(0)
		m, _ := s.Effective(e, o)
		if m != nil {
			if n, err := disk.VirtualSize(filepath.Join(s.StateDir, virt.DiskName(m))); err == nil {
				cur = n
			} else if n, err := disk.VirtualSize(m.Image.Path); err == nil {
				cur = n
			}
		}
		min := int((cur + (1<<30 - 1)) >> 30)
		if min < 1 {
			min = 1
		}
		if *ch.DiskGB < min || *ch.DiskGB > manifest.MaxDiskGB {
			return bad(fmt.Sprintf("choose %d to %d GiB", min, manifest.MaxDiskGB), "a disk can only grow: %d to %d GiB", min, manifest.MaxDiskGB)
		}
		o.DiskGB = *ch.DiskGB
		changed = append(changed, "disk_gb")
	}
	if ch.SharedFolder != nil {
		if *ch.SharedFolder != "off" && *ch.SharedFolder != "on" {
			return bad(`send "off" or "on"`, "shared_folder must be off or on")
		}
		o.SharedFolder = *ch.SharedFolder
		changed = append(changed, "shared_folder")
	}
	if ch.Clipboard != nil {
		if *ch.Clipboard != manifest.ClipOff && *ch.Clipboard != manifest.ClipText {
			return bad(`send "off" or "text"`, "clipboard must be off or text")
		}
		o.Clipboard = *ch.Clipboard
		changed = append(changed, "clipboard")
	}
	if ch.Devices != nil {
		allowed := map[string]bool{}
		for _, d := range e.Manifest.Devices.PCI {
			allowed[d] = true
		}
		seen := map[string]bool{}
		for _, d := range *ch.Devices {
			if !allowed[d] || seen[d] {
				return bad("choose among the devices the instance's manifest names", "device %q is not one the manifest names (devices are given by root, then the host's passthrough policy)", d)
			}
			seen[d] = true
		}
		d := append([]string{}, (*ch.Devices)...)
		o.Devices = &d
		changed = append(changed, "devices")
	}
	if len(changed) == 0 {
		return bad("send at least one of cpus, memory_mb, disk_gb, shared_folder, clipboard, devices", "nothing to change")
	}
	if _, err := s.Effective(e, o); err != nil {
		return View{}, err
	}
	if err := s.audit(EventChange, name, c, map[string]string{"changed": strings.Join(changed, ",")}); err != nil {
		return View{}, err
	}
	if err := s.saveOverrides(name, o); err != nil {
		return View{}, err
	}
	return s.Get(ctx, name, c)
}

// FreeSpace deletes a stopped instance's own disk: it starts from its base image again next time. Never for a held
// guest, whoever asks: its disk is evidence.
func (s *Service) FreeSpace(ctx context.Context, name string, c Caller) (int64, error) {
	e, err := s.mayChange(name, c)
	if err != nil {
		return 0, err
	}
	if h, held := s.hold(name); held {
		return 0, refuse(http.StatusConflict, CodeHeld, "its disk is evidence; decide about it on Heimdall's page first", "instance %q is held (%s)", name, h.ID)
	}
	unlock := s.lock(name)
	defer unlock()
	m := &e.Manifest
	if s.running(ctx)[virt.DomainName(m)] || s.Guests.Defined(ctx, m) {
		return 0, refuse(http.StatusConflict, CodeRunning, "stop it first", "instance %q is running", name)
	}
	p := filepath.Join(s.StateDir, virt.PersistentDiskName(m))
	n := disk.Allocated(p)
	if err := s.audit(EventChange, name, c, map[string]string{"changed": "free_space"}); err != nil {
		return 0, err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	return n, nil
}

// Add registers an instance (root only). The manifest must not be disposable: a disposable guest is a run, not
// something a person keeps.
func (s *Service) Add(m *manifest.Manifest, owner string, c Caller) (View, error) {
	if !c.Admin {
		return View{}, refuse(http.StatusForbidden, CodeBadRequest, "use the password (sudo or pkexec)", "only root registers instances")
	}
	raw, _ := json.Marshal(m)
	pm, err := manifest.Parse(raw)
	if err != nil {
		return View{}, refuse(http.StatusBadRequest, CodeBadRequest, "fix the manifest ('limbo validate FILE')", "%v", err)
	}
	if pm.Disposable {
		return View{}, refuse(http.StatusBadRequest, CodeBadRequest, "set \"disposable\": false; disposable guests are for runs", "an instance is kept, so it cannot be disposable")
	}
	if runRe.MatchString(pm.Name) {
		return View{}, refuse(http.StatusBadRequest, CodeBadRequest, "choose another name", "names like %q are kept for runs", pm.Name)
	}
	if owner != "" && !userRe.MatchString(owner) {
		return View{}, refuse(http.StatusBadRequest, CodeBadRequest, "give an account name", "owner %q is not an account name", owner)
	}
	unlock := s.lock(pm.Name)
	defer unlock()
	if _, err := os.Lstat(s.entryPath(pm.Name)); err == nil {
		return View{}, refuse(http.StatusConflict, CodeExists, "remove it first, or choose another name", "instance %q already exists", pm.Name)
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return View{}, err
	}
	b, _ := json.MarshalIndent(Entry{Manifest: *pm, Owner: owner}, "", "  ")
	tmp := s.entryPath(pm.Name) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return View{}, err
	}
	if err := os.Rename(tmp, s.entryPath(pm.Name)); err != nil {
		return View{}, err
	}
	_ = s.audit(EventAdd, pm.Name, c, map[string]string{"owner": owner})
	return s.view(pm, "instance", &Entry{Manifest: *pm, Owner: owner}, Overrides{}, map[string]bool{}, c), nil
}

// Remove unregisters a stopped instance (root only). Its disk is deleted only when asked.
func (s *Service) Remove(ctx context.Context, name string, deleteDisk bool, c Caller) error {
	if !c.Admin {
		return refuse(http.StatusForbidden, CodeBadRequest, "use the password (sudo or pkexec)", "only root removes instances")
	}
	e, err := s.load(name)
	if err != nil {
		return err
	}
	unlock := s.lock(name)
	defer unlock()
	if s.Guests.Defined(ctx, &e.Manifest) {
		return refuse(http.StatusConflict, CodeRunning, "stop it first", "instance %q is running", name)
	}
	if deleteDisk {
		if h, held := s.hold(name); held {
			return refuse(http.StatusConflict, CodeHeld, "its disk is evidence; decide about it on Heimdall's page first", "instance %q is held (%s)", name, h.ID)
		}
	}
	_ = s.audit(EventRemove, name, c, map[string]string{"delete_disk": fmt.Sprint(deleteDisk)})
	if err := os.Remove(s.entryPath(name)); err != nil {
		return err
	}
	_ = os.Remove(s.overridePath(name))
	if deleteDisk {
		_ = os.Remove(filepath.Join(s.StateDir, virt.PersistentDiskName(&e.Manifest)))
	}
	return nil
}

// Event kinds this package writes (docs/EVENTS.md).
const (
	EventRequest = "instance.request" // start or stop asked for (engine events follow)
	EventChange  = "instance.change"  // settings changed, or its disk freed
	EventAdd     = "instance.add"
	EventRemove  = "instance.remove"
)
