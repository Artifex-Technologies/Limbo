// Package runs executes a command in a throwaway guest and reports what
// happened. It is how Sarina validates an update or an install somewhere that
// does not matter before the real system is touched (docs/QUARANTINE.md).
//
// The caller names a profile, not a manifest. Profiles are written by the human
// into a directory only root can write, so a caller cannot choose the network
// mode, the image, shares or devices, and a profile that is not disposable is
// refused outright. Each run gets a fresh guest name, overlay and network, and
// is torn down whatever happens.
package runs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/engine"
	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/provision"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

// Limits. Server-side, so a caller cannot lift them.
const (
	maxCommand       = 4096
	maxBundle        = 40 << 10 // a tar of source files an agent run may carry into the guest
	maxSample        = 64 << 20 // one file to analyse (sample runs: root's admin socket only)
	defaultSeconds   = 300
	maxResults       = 50
	maxConcurrent    = 2 // agent runs at once
	maxSamples       = 1 // sample analyses at once, on top of those
	defaultOutputCap = 64 << 10
	readyWaitSeconds = 180
	// bootBudgetSeconds bounds building the seed, starting the guest and waiting for
	// it to accept commands. It is separate from the command's own timeout: a caller
	// that asks for a 10 second command must not have its guest killed mid-boot.
	bootBudgetSeconds = 300
	teardownTimeoutMS = 60_000
)

var profileRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Profile is a human-written description of where runs happen.
type Profile struct {
	Manifest       manifest.Manifest `json:"manifest"`
	SSHIdentity    string            `json:"ssh_identity"`     // private key matching manifest.provision.ssh_public_key
	MaxSeconds     int               `json:"max_seconds"`      // hard cap on the COMMAND's runtime (boot is budgeted separately); default 900
	MaxOutputBytes int               `json:"max_output_bytes"` // per stream; default 64 KiB
	AllowBundle    bool              `json:"allow_bundle"`     // the human lets runs on this profile carry a small tar of files into the guest (default no)
	// AllowSample: the human lets root (Heimdall, over the admin socket) send one file to be analysed into a guest of this profile.
	// Only a sealed profile qualifies: no network, no sudo, no shared folder, no host devices (checked at every start).
	AllowSample bool `json:"allow_sample"`
}

// Run kinds: who asked, and so what may stop it.
const (
	kindAgent  = "agent"  // Sarina's agents and validation runs (agent socket); stopped when Heimdall contains Sarina
	kindSample = "sample" // a file analysed for Heimdall (admin socket)
)

// Status of a run.
type Status string

const (
	Running Status = "running"
	Done    Status = "done"    // command ran; see ExitCode
	Failed  Status = "failed"  // the guest or the harness failed; the command's result is unknown
	Timeout Status = "timeout" // the run exceeded its time limit
)

// Result is what a caller gets back. Stdout and Stderr come from inside a guest
// and are untrusted: a validation result is evidence, not instructions.
type Result struct {
	ID        string    `json:"id"`
	Profile   string    `json:"profile"`
	Status    Status    `json:"status"`
	ExitCode  *int      `json:"exit_code,omitempty"`
	Stdout    string    `json:"stdout"`
	Stderr    string    `json:"stderr"`
	Truncated bool      `json:"truncated,omitempty"`
	Error     string    `json:"error,omitempty"`  // "code: message. Remedy: hint"; empty when the command ran cleanly
	Code      string    `json:"code,omitempty"`   // stable failure code (errors.go); also set for the informational ones
	Remedy    string    `json:"remedy,omitempty"` // the one-line hint from Error
	Started   time.Time `json:"started"`
	Ended     time.Time `json:"ended,omitempty"`
}

// Executor runs a command inside a guest. Real implementation: ssh.
type Executor interface {
	// WaitReady blocks until the guest accepts commands or ctx ends.
	WaitReady(ctx context.Context, ip, user, identity string) error
	// Run executes command, returning at most limit bytes of each stream.
	Run(ctx context.Context, ip, user, identity, command string, limit int) (out, errOut string, exit int, truncated bool, err error)
}

// BundleExecutor is an Executor that can also carry a tar into the guest.
type BundleExecutor interface {
	// RunBundle unpacks the tar into a fresh folder in the guest's home, then runs command from inside it.
	RunBundle(ctx context.Context, ip, user, identity, command string, bundle []byte, limit int) (out, errOut string, exit int, truncated bool, err error)
}

// SampleExecutor is an Executor that can carry one file to analyse into the guest.
type SampleExecutor interface {
	// RunSample stores sample read-only as ~/sample/sample in the guest, then runs command from that folder.
	RunSample(ctx context.Context, ip, user, identity, command string, sample []byte, limit int) (out, errOut string, exit int, truncated bool, err error)
}

// Manager runs and remembers runs.
type Manager struct {
	ProfileDir string
	StateDir   string
	Engine     *engine.Engine
	Exec       Executor
	Events     engine.Emitter
	// BuildSeed turns a manifest into a cloud-init ISO at isoPath. Injected so
	// tests need no xorriso; production uses SeedISO.
	BuildSeed func(ctx context.Context, m *manifest.Manifest, workDir, isoPath string) error

	mu      sync.Mutex
	results map[string]*Result
	order   []string
	active  int
	devHeld map[string][]string // run id -> passthrough devices it holds
	bundles map[string][]byte   // run id -> the tar it carries into the guest
	samples map[string][]byte   // run id -> the file it carries in to be analysed
	kinds   map[string]string   // run id -> kindAgent or kindSample
	cancels map[string]context.CancelFunc

	// SampleDir is where root puts a file before asking for a sample run (/var/lib/limbo/inbox); only names inside it are accepted.
	SampleDir string
	// Contained reports whether Heimdall has contained Sarina (its lock file exists): agent runs are refused meanwhile.
	Contained func() bool

	scanMu sync.Mutex        // serializes profile scans (and the image hashing they do)
	seen   map[string]string // profile file -> code last logged, so a failure is logged once
	imgOK  map[string]imgSig // image path -> signature last verified against its sha256
}

// NewManager returns a Manager with real seed building.
func NewManager(profileDir, stateDir string, e *engine.Engine, x Executor, ev engine.Emitter) *Manager {
	m := &Manager{ProfileDir: profileDir, StateDir: stateDir, Engine: e, Exec: x, Events: ev, results: map[string]*Result{}}
	m.BuildSeed = func(ctx context.Context, mf *manifest.Manifest, workDir, iso string) error {
		return SeedISO(ctx, e.Runner, mf, workDir, iso)
	}
	return m
}

// SeedISO writes the cloud-init files and packs them into a "cidata" ISO.
func SeedISO(ctx context.Context, r engine.Runner, m *manifest.Manifest, workDir, isoPath string) error {
	s, err := provision.Build(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}
	for name, body := range map[string]string{"user-data": s.UserData, "meta-data": s.MetaData} {
		if err := os.WriteFile(filepath.Join(workDir, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	return r.Run(ctx, "", "xorriso", "-as", "mkisofs", "-o", isoPath, "-V", "cidata", "-J", "-r", workDir)
}

// ProfileInfo is what a caller is told about a profile: enough to choose and to
// plan (does it have root? a network? how long may a command run?), and nothing
// that lets it change the profile.
type ProfileInfo struct {
	Name        string `json:"name"`
	Network     string `json:"network"` // none | allowlist | internet-only
	Sudo        bool   `json:"sudo"`
	Passthrough bool   `json:"passthrough"` // the guest gets a real host device (driver testing)
	MaxSeconds  int    `json:"max_seconds"`
}

func (m *Manager) loadProfile(name string) (*Profile, error) {
	if !profileRe.MatchString(name) {
		return nil, newErr(CodeProfileInvalid, "use a name from limbo_profiles", "profile names are lowercase letters, digits and hyphens")
	}
	b, err := os.ReadFile(filepath.Join(m.ProfileDir, name+".json"))
	if err != nil {
		return nil, newErr(CodeProfileUnknown, "call limbo_profiles for the names that exist", "there is no profile named %q", name)
	}
	var p Profile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, badProfile("the profile file is not valid JSON or has unknown fields", "profile %q is malformed (%v)", name, err)
	}
	if !p.Manifest.Disposable {
		return nil, badProfile("the profile is not marked disposable", "profile %q is not disposable, so Limbo refuses it", name)
	}
	if p.Manifest.OS != manifest.OSLinux {
		return nil, badProfile("the profile is not a Linux guest", "profile %q is not a Linux guest", name)
	}
	if !path.IsAbs(p.SSHIdentity) {
		return nil, badProfile("the profile ssh_identity is not an absolute path", "profile %q: ssh_identity must be an absolute path", name)
	}
	if p.MaxSeconds <= 0 {
		p.MaxSeconds = 900
	}
	if p.MaxOutputBytes <= 0 {
		p.MaxOutputBytes = defaultOutputCap
	}
	// Normalize and validate the embedded manifest exactly as manifest.Parse does.
	raw, _ := json.Marshal(p.Manifest)
	mf, err := manifest.Parse(raw)
	if err != nil {
		return nil, badProfile("the profile manifest is invalid", "profile %q is malformed (%v)", name, err)
	}
	p.Manifest = *mf
	return &p, nil
}

// Start begins a run and returns its id immediately. A refusal is a *Error and is
// also written to the event log, so it can be diagnosed from either end.
func (m *Manager) Start(ctx context.Context, profile, command string, timeoutSeconds int) (string, error) {
	return m.StartBundle(ctx, profile, command, nil, timeoutSeconds)
}

// StartBundle is Start for a run that also carries a small tar of files (an agent's source) into the guest: it is unpacked in a
// fresh folder in the guest's home and the command runs from there. Only a profile whose human author set allow_bundle accepts one.
func (m *Manager) StartBundle(ctx context.Context, profile, command string, bundle []byte, timeoutSeconds int) (string, error) {
	return m.startLogged(ctx, profile, command, bundle, nil, kindAgent, timeoutSeconds)
}

var sampleNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// StartSample analyses one file in a sealed guest: the file named (inside SampleDir) is read now, sent into the guest on the command's
// input and left there read-only as ~/sample/sample; the command runs from that folder with LIMBO_SAMPLE_DIR set to it. For root only
// (the admin socket): the caller chooses the command, and the profile must be sealed.
func (m *Manager) StartSample(ctx context.Context, profile, command, sampleName string, timeoutSeconds int) (string, error) {
	if !sampleNameRe.MatchString(sampleName) || m.SampleDir == "" {
		return "", newErr(CodeBadRequest, "put the file in Limbo's inbox and give its name only", "the sample must be a plain file name in the inbox")
	}
	f, err := os.OpenFile(filepath.Join(m.SampleDir, sampleName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", newErr(CodeBadRequest, "put the file in Limbo's inbox first", "the sample %q cannot be opened in the inbox", sampleName)
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return "", newErr(CodeBadRequest, "send a regular file", "the sample is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSample+1))
	if err != nil || len(b) == 0 || len(b) > maxSample {
		return "", newErr(CodeBadRequest, "send a file of 1 byte to 64 MiB", "the sample is empty, unreadable or larger than %d bytes", maxSample)
	}
	return m.startLogged(ctx, profile, command, nil, b, kindSample, timeoutSeconds)
}

// StopAgentRuns ends every agent run now (Heimdall contained Sarina): each guest is torn down as when it times out. Sample runs go on.
func (m *Manager) StopAgentRuns() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, k := range m.kinds {
		if k == kindAgent {
			if c := m.cancels[id]; c != nil {
				c()
				n++
			}
		}
	}
	return n
}

func (m *Manager) startLogged(ctx context.Context, profile, command string, bundle, sample []byte, kind string, timeoutSeconds int) (string, error) {
	id, err := m.start(ctx, profile, command, bundle, sample, kind, timeoutSeconds)
	if err != nil {
		var re *Error
		if errors.As(err, &re) {
			guest := ""
			if profileRe.MatchString(profile) {
				guest = profile
			}
			_ = m.Events.Emit(events.RunError, guest, map[string]string{"code": re.Code})
		}
	}
	return id, err
}

func (m *Manager) start(ctx context.Context, profile, command string, bundle, sample []byte, kind string, timeoutSeconds int) (string, error) {
	if kind == kindAgent && m.Contained != nil && m.Contained() {
		return "", newErr(CodeContained, "wait until the owner releases Sarina (Settings > Security)", "Heimdall has contained Sarina: no runs for her agents meanwhile")
	}
	p, err := m.loadProfile(profile)
	if err != nil {
		return "", err
	}
	if kind == kindSample {
		mf := p.Manifest
		if !p.AllowSample || mf.Network.Mode != "none" || mf.Access.Sudo || mf.ExchangeDir != "" || len(mf.Devices.PCI) > 0 {
			return "", newErr(CodeProfileInvalid, "use a sealed profile with allow_sample (no network, no sudo, no shared folder, no devices)", "profile %q may not analyse samples", profile)
		}
		if _, ok := m.Exec.(SampleExecutor); !ok {
			return "", newErr(CodeBadRequest, "this Limbo cannot carry a sample into a guest", "samples are not supported here")
		}
	}
	if len(bundle) > 0 {
		if !p.AllowBundle {
			return "", newErr(CodeBadRequest, "use a profile whose author allows bundles (allow_bundle in the profile)", "profile %q does not accept files", profile)
		}
		if len(bundle) > maxBundle {
			return "", newErr(CodeBadRequest, "send less: only source files, no data or binaries", "the bundle is larger than %d bytes", maxBundle)
		}
		if _, ok := m.Exec.(BundleExecutor); !ok {
			return "", newErr(CodeBadRequest, "this Limbo cannot carry files into a guest", "bundles are not supported here")
		}
	}
	if _, err := os.Stat(p.Manifest.Image.Path); err != nil {
		return "", newErr(CodeImageMissing, "ask the operator to restore the profile's base image", "the base image for profile %q is missing or unreadable", profile)
	}
	// Checked here, not only in Engine.Up, so a refusal is immediate and the
	// operator-facing reason reaches the audit log; Up checks again regardless.
	for _, check := range []func(*manifest.Manifest) error{m.Engine.CheckHardware, m.Engine.ReadyHardware} {
		if err := check(&p.Manifest); err != nil {
			_ = m.Events.Emit(events.GateBlocked, profile, map[string]string{"reason": err.Error()})
			return "", hardwareErr(err)
		}
	}
	if command == "" || len(command) > maxCommand || strings.ContainsRune(command, 0) {
		return "", newErr(CodeBadRequest, "send a non-empty command without NUL bytes", "command must be 1-%d bytes", maxCommand)
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = defaultSeconds
	}
	if timeoutSeconds > p.MaxSeconds {
		timeoutSeconds = p.MaxSeconds
	}

	m.mu.Lock()
	// agent runs and sample runs are counted apart: Sarina's runs can never take the slot Heimdall's sample analysis needs
	running := 0
	for _, k := range m.kinds {
		if k == kind {
			running++
		}
	}
	if kind == kindSample && running >= maxSamples {
		m.mu.Unlock()
		return "", newErr(CodeBusy, "wait about a minute and retry", "a sample analysis is already in progress")
	}
	if kind != kindSample && running >= maxConcurrent {
		m.mu.Unlock()
		return "", newErr(CodeBusy, "wait about a minute and retry", "%d validation runs are already in progress", maxConcurrent)
	}
	// A passed-through device belongs to one guest at a time.
	for _, d := range p.Manifest.Devices.PCI {
		for _, held := range m.devHeld {
			for _, h := range held {
				if h == d {
					m.mu.Unlock()
					return "", newErr(CodeBusy, "wait for the run using the device to finish, then retry", "a device this profile needs is in use by another run")
				}
			}
		}
	}
	m.active++
	id := newRunID()
	if len(p.Manifest.Devices.PCI) > 0 {
		if m.devHeld == nil {
			m.devHeld = map[string][]string{}
		}
		m.devHeld[id] = p.Manifest.Devices.PCI
	}
	res := &Result{ID: id, Profile: profile, Status: Running, Started: time.Now().UTC()}
	m.results[id] = res
	if len(bundle) > 0 {
		if m.bundles == nil {
			m.bundles = map[string][]byte{}
		}
		m.bundles[id] = bundle
	}
	if len(sample) > 0 {
		if m.samples == nil {
			m.samples = map[string][]byte{}
		}
		m.samples[id] = sample
	}
	if m.kinds == nil {
		m.kinds, m.cancels = map[string]string{}, map[string]context.CancelFunc{}
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	m.kinds[id], m.cancels[id] = kind, cancelRun
	m.order = append(m.order, id)
	for len(m.order) > maxResults {
		delete(m.results, m.order[0])
		m.order = m.order[1:]
	}
	m.mu.Unlock()

	go m.execute(runCtx, id, p, command, time.Duration(timeoutSeconds)*time.Second)
	return id, nil
}

// Get returns a snapshot of a run.
func (m *Manager) Get(id string) (any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.results[id]
	if !ok {
		return nil, false
	}
	cp := *r
	return cp, true
}

func (m *Manager) finish(id string, mut func(*Result)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.results[id]; ok {
		mut(r)
		r.Ended = time.Now().UTC()
	}
	m.active--
	delete(m.devHeld, id) // teardown has already run: the device is back with the host
	if c := m.cancels[id]; c != nil {
		c()
	}
	delete(m.cancels, id)
	delete(m.kinds, id)
}

func (m *Manager) execute(ctx context.Context, id string, p *Profile, command string, limit time.Duration) {
	mf := p.Manifest // copy
	mf.Name = id
	runDir := filepath.Join(m.StateDir, "runs", id)
	iso := filepath.Join(runDir, "seed.iso")
	mf.Provision.SeedISO = iso

	sum := sha256.Sum256([]byte(command))
	m.mu.Lock()
	bundle := m.bundles[id]
	delete(m.bundles, id)
	sample := m.samples[id]
	delete(m.samples, id)
	m.mu.Unlock()
	start := map[string]string{
		"profile": filepath.Base(p.SSHIdentity), "command_sha256": hex.EncodeToString(sum[:]), "command": clip(command, 200),
	}
	if len(bundle) > 0 {
		bs := sha256.Sum256(bundle)
		start["bundle_sha256"], start["bundle_bytes"] = hex.EncodeToString(bs[:]), fmt.Sprint(len(bundle))
	}
	if len(sample) > 0 {
		ss := sha256.Sum256(sample)
		start["sample_sha256"], start["sample_bytes"] = hex.EncodeToString(ss[:]), fmt.Sprint(len(sample))
	}
	_ = m.Events.Emit(events.RunStart, id, start)

	bootCtx, cancel := context.WithTimeout(ctx, bootBudgetSeconds*time.Second)
	defer cancel()

	var (
		out, errOut string
		exit        int
		truncated   bool
		timedOut    bool
		fail        *Error // Limbo could not run the command: the command's result is unknown
		leaked      bool   // teardown did not finish; the guest may still exist
	)

	// QEMU runs as an unprivileged user and must be able to open the seed ISO, so
	// every directory on its path needs the execute bit for others (traverse, not
	// list). A 0700 directory here made every run fail at guest start; the ISO's
	// own contents are not secret.
	for _, d := range []string{filepath.Join(m.StateDir, "runs"), runDir} {
		if err := mkdirTraversable(d); err != nil {
			fail = classify("prepare", err, nil)
			break
		}
	}

	if fail == nil {
		func() {
			// Teardown always runs, with its own context: a run that timed out, or
			// whose caller went away, must still have its guest destroyed.
			defer func() {
				dctx, dcancel := context.WithTimeout(context.Background(), teardownTimeoutMS*time.Millisecond)
				defer dcancel()
				leaked = m.Engine.Down(dctx, &mf) != nil
				m.Engine.CleanState(&mf)
				if !leaked {
					_ = os.RemoveAll(runDir)
				} // else the directory stays as the marker ReapOrphans retries from
			}()

			if err := m.BuildSeed(bootCtx, &mf, filepath.Join(runDir, "seed"), iso); err != nil {
				fail = classify("seed", err, bootCtx.Err())
				return
			}
			if err := m.Engine.Up(bootCtx, &mf); err != nil {
				fail = classify("up", err, bootCtx.Err())
				return
			}
			ip := virt.Addr(&mf).Guest.String()
			wctx, wcancel := context.WithTimeout(bootCtx, readyWaitSeconds*time.Second)
			defer wcancel()
			if err := m.Exec.WaitReady(wctx, ip, mf.Access.User, p.SSHIdentity); err != nil {
				fail = classify("ready", err, wctx.Err())
				return
			}
			// The command's own clock starts only now, once the guest is ready.
			cmdCtx, ccancel := context.WithTimeout(ctx, limit)
			defer ccancel()
			var runErr error
			if se, ok := m.Exec.(SampleExecutor); ok && len(sample) > 0 {
				out, errOut, exit, truncated, runErr = se.RunSample(cmdCtx, ip, mf.Access.User, p.SSHIdentity, command, sample, p.MaxOutputBytes)
			} else if be, ok := m.Exec.(BundleExecutor); ok && len(bundle) > 0 {
				out, errOut, exit, truncated, runErr = be.RunBundle(cmdCtx, ip, mf.Access.User, p.SSHIdentity, command, bundle, p.MaxOutputBytes)
			} else {
				out, errOut, exit, truncated, runErr = m.Exec.Run(cmdCtx, ip, mf.Access.User, p.SSHIdentity, command, p.MaxOutputBytes)
			}
			timedOut = errors.Is(cmdCtx.Err(), context.DeadlineExceeded)
			if runErr != nil && !timedOut {
				fail = classify("command", runErr, nil)
			}
		}()
	}

	// What the caller is told. A non-zero exit is a normal Done result; only a
	// *Error means Limbo could not run the command.
	status, note := Done, (*Error)(nil)
	switch {
	case fail != nil:
		status, note = Failed, fail
	case timedOut:
		status = Timeout
		note = newErr(CodeCommandTimeout, "raise timeout_seconds (up to the profile's limit) or run something shorter",
			"the command was still running after %d seconds and was killed", int(limit.Seconds()))
	case leaked:
		note = newErr(CodeTeardownFailed, "ask the operator to destroy the leftover guest limbo-"+id+" (virsh -c qemu:///system list --all)",
			"the command ran but cleaning up the guest did not finish")
	case truncated:
		note = &Error{Code: CodeOutputTrunc, Message: "the command ran but its output was cut at the profile's size limit", Remedy: "filter the output (grep, tail) and rerun if the missing part matters"}
	}

	// Audit first, then publish: a caller must never see a finished run that is
	// not yet in the audit log.
	detail := map[string]string{"status": string(status)}
	if status == Done {
		detail["exit_code"] = fmt.Sprint(exit)
	}
	if note != nil {
		detail["code"] = note.Code
	}
	if leaked {
		detail["teardown"] = "failed"
	}
	_ = m.Events.Emit(events.RunEnd, id, detail)
	if note != nil && note.Code != CodeOutputTrunc {
		_ = m.Events.Emit(events.RunError, id, map[string]string{"code": note.Code})
	}

	m.finish(id, func(r *Result) {
		r.Status, r.Stdout, r.Stderr, r.Truncated = status, sanitize(out), sanitize(errOut), truncated
		if status == Done {
			r.ExitCode = &exit
		}
		if note != nil {
			r.Code, r.Remedy = note.Code, note.Remedy
			if note.Code != CodeOutputTrunc {
				r.Error = note.Error()
			}
		}
	})
}

// ReapOrphans destroys guests left behind by runs that did not finish cleanly:
// Limbo was killed or restarted mid-run, or teardown failed. Every run keeps a
// directory under StateDir/runs until its guest is gone, so what remains there
// is exactly what leaked. Call it once at startup; it returns how many it reaped.
func (m *Manager) ReapOrphans(ctx context.Context) int {
	ents, _ := os.ReadDir(filepath.Join(m.StateDir, "runs"))
	n := 0
	for _, e := range ents {
		id := e.Name()
		if !e.IsDir() || !runIDRe.MatchString(id) {
			continue
		}
		mf := &manifest.Manifest{Name: id, Disposable: true}
		if g, err := engine.LoadGuest(m.StateDir, id); err == nil {
			mf = g
		}
		if err := m.Engine.Down(ctx, mf); err != nil {
			_ = m.Events.Emit(events.RunError, id, map[string]string{"code": CodeTeardownFailed, "during": "startup reap"})
			continue
		}
		m.Engine.CleanState(mf)
		_ = os.RemoveAll(filepath.Join(m.StateDir, "runs", id))
		_ = m.Events.Emit(events.RunError, id, map[string]string{"code": CodeGuestKilled, "during": "startup reap"})
		n++
	}
	return n
}

var runIDRe = regexp.MustCompile(`^r[0-9a-f]{8}$`)

func mkdirTraversable(path string) error {
	if err := os.MkdirAll(path, 0o711); err != nil {
		return err
	}
	return os.Chmod(path, 0o711) // MkdirAll is subject to the umask
}

func newRunID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "r" + hex.EncodeToString(b[:]) // 9 chars: valid guest name, interface names stay short
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
