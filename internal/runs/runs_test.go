//go:build linux

package runs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/engine"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	// bootDelay makes starting a guest slow, as a real boot is.
	bootDelay time.Duration
	// failOn makes any command containing it fail with failErr.
	failOn  string
	failErr error
}

func (f *fakeRunner) Run(_ context.Context, _ string, name string, args ...string) error {
	f.mu.Lock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	slow := f.bootDelay > 0 && strings.Contains(strings.Join(args, " "), "qemu:///system start")
	failing := f.failOn != "" && strings.Contains(f.calls[len(f.calls)-1], f.failOn)
	f.mu.Unlock()
	if slow {
		time.Sleep(f.bootDelay)
	}
	if failing {
		return f.failErr
	}
	return nil
}

func (f *fakeRunner) has(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

type fakeEvents struct {
	mu    sync.Mutex
	kinds []string
	codes []string // kind:code of every event that carried a code
}

func (f *fakeEvents) Emit(kind, _ string, d map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kinds = append(f.kinds, kind)
	if d["code"] != "" {
		f.codes = append(f.codes, kind+":"+d["code"])
	}
	return nil
}

type fakeExec struct {
	out, errOut string
	exit        int
	trunc       bool
	runErr      error
	block       chan struct{} // if set, Run waits on it (or ctx)
	readyBlock  bool          // WaitReady waits for ctx to end
	gotIP       string
	gotCmd      string
}

func (f *fakeExec) WaitReady(ctx context.Context, _, _, _ string) error {
	if f.readyBlock {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}
func (f *fakeExec) Run(ctx context.Context, ip, _, _, command string, _ int) (string, string, int, bool, error) {
	f.gotIP, f.gotCmd = ip, command
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return "", "", 0, false, ctx.Err()
		}
	}
	return f.out, f.errOut, f.exit, f.trunc, f.runErr
}

const abcSHA = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

type env struct {
	m    *Manager
	run  *fakeRunner
	ev   *fakeEvents
	ex   *fakeExec
	prof string
}

func setup(t *testing.T, disposable bool) *env {
	t.Helper()
	dir := t.TempDir()
	img := filepath.Join(dir, "base.img")
	if err := os.WriteFile(img, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	profDir := filepath.Join(dir, "profiles")
	os.MkdirAll(profDir, 0o755)
	body := `{"manifest":{"name":"template","os":"linux","image":{"path":"` + img + `","sha256":"` + abcSHA + `"},
	  "network":{"mode":"allowlist","allow":[{"addr":"203.0.113.5","port":443}]},"disposable":` + boolStr(disposable) + `,
	  "access":{"user":"analyst"},"app":{"name":"x","exec":"true"},
	  "provision":{"ssh_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample analyst@host"}},
	  "ssh_identity":"/etc/limbo/keys/validation","max_seconds":30}`
	os.WriteFile(filepath.Join(profDir, "arch-update.json"), []byte(body), 0o644)

	r, ev, ex := &fakeRunner{}, &fakeEvents{}, &fakeExec{out: "ok\n"}
	e := &engine.Engine{Runner: r, Events: ev, StateDir: filepath.Join(dir, "state")}
	m := NewManager(profDir, filepath.Join(dir, "state"), e, ex, ev)
	m.BuildSeed = func(_ context.Context, _ *manifest.Manifest, _ string, iso string) error {
		// QEMU is unprivileged: every directory down to the ISO must be traversable.
		for d := filepath.Dir(iso); strings.HasPrefix(d, m.StateDir); d = filepath.Dir(d) {
			if fi, err := os.Stat(d); err != nil || fi.Mode().Perm()&0o001 == 0 {
				return errors.New("directory " + d + " is not traversable by the hypervisor user")
			}
		}
		return nil
	}
	return &env{m: m, run: r, ev: ev, ex: ex, prof: "arch-update"}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func wait(t *testing.T, m *Manager, id string) Result {
	t.Helper()
	for i := 0; i < 400; i++ {
		v, ok := m.Get(id)
		if !ok {
			t.Fatal("run vanished")
		}
		if r := v.(Result); r.Status != Running {
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run never finished")
	return Result{}
}

func TestSuccessfulRunTearsDownAndReportsOutput(t *testing.T) {
	x := setup(t, true)
	x.ex.out, x.ex.exit = "Packages (3) upgraded\n", 0
	id, err := x.m.Start(context.Background(), x.prof, "pacman -Syu --noconfirm", 0)
	if err != nil {
		t.Fatal(err)
	}
	r := wait(t, x.m, id)
	if r.Status != Done || r.ExitCode == nil || *r.ExitCode != 0 || !strings.Contains(r.Stdout, "upgraded") {
		t.Fatalf("%+v", r)
	}
	if x.ex.gotCmd != "pacman -Syu --noconfirm" || !strings.HasPrefix(x.ex.gotIP, "10.213.") {
		t.Fatalf("executor got %q @ %q", x.ex.gotCmd, x.ex.gotIP)
	}
	for _, want := range []string{"qemu-img create", "qemu:///system start limbo-" + id, "net-undefine limbo-" + id, "nft delete table inet limbo_" + id} {
		if !x.run.has(want) {
			t.Errorf("missing %q in %v", want, x.run.calls)
		}
	}
	if len(id) != 9 || id[0] != 'r' {
		t.Errorf("run id %q must be a valid short guest name", id)
	}
	if got := x.ev.kinds; got[0] != "run.start" || got[len(got)-1] != "run.end" {
		t.Errorf("events %v", got)
	}
	if _, err := os.Stat(filepath.Join(x.m.StateDir, "runs", id)); !os.IsNotExist(err) {
		t.Error("run directory not removed")
	}
	if _, err := os.Stat(filepath.Join(x.m.StateDir, id+".manifest.json")); !os.IsNotExist(err) {
		t.Error("manifest copy left behind")
	}
}

func TestNonZeroExitIsAResultNotAFailure(t *testing.T) {
	x := setup(t, true)
	x.ex.exit, x.ex.errOut = 1, "error: failed to commit transaction\n"
	id, _ := x.m.Start(context.Background(), x.prof, "pacman -Syu", 0)
	r := wait(t, x.m, id)
	if r.Status != Done || *r.ExitCode != 1 || !strings.Contains(r.Stderr, "failed to commit") {
		t.Fatalf("a failing update is exactly what a validation run exists to observe: %+v", r)
	}
}

func TestExecutorErrorIsFailedAndStillTearsDown(t *testing.T) {
	x := setup(t, true)
	x.ex.runErr = errors.New("ssh connection failed")
	id, _ := x.m.Start(context.Background(), x.prof, "true", 0)
	r := wait(t, x.m, id)
	if r.Status != Failed || r.ExitCode != nil || r.Code != CodeRunFailed {
		t.Fatalf("%+v", r)
	}
	if !x.run.has("nft delete table inet limbo_" + id) {
		t.Fatal("guest not torn down after a failed run")
	}
}

func TestTimeoutDestroysTheGuest(t *testing.T) {
	x := setup(t, true)
	x.ex.block = make(chan struct{}) // never released
	id, _ := x.m.Start(context.Background(), x.prof, "sleep 999", 1)
	r := wait(t, x.m, id)
	if r.Status != Timeout {
		t.Fatalf("%+v", r)
	}
	if !x.run.has("nft delete table inet limbo_" + id) {
		t.Fatal("timed-out guest was not torn down")
	}
}

func TestProfileRules(t *testing.T) {
	x := setup(t, false) // not disposable
	if _, err := x.m.Start(context.Background(), x.prof, "true", 0); err == nil || !strings.Contains(err.Error(), "not disposable") {
		t.Fatalf("non-disposable profile accepted: %v", err)
	}
	if got := x.m.Profiles(); len(got) != 0 {
		t.Fatalf("an unusable profile must not be offered: %v", got)
	}
	y := setup(t, true)
	if got := y.m.Profiles(); len(got) != 1 || got[0] != "arch-update" {
		t.Fatalf("%v", got)
	}
	for _, bad := range []string{"../etc/passwd", "ARCH", "", "a/b", "nope"} {
		if _, err := y.m.Start(context.Background(), bad, "true", 0); err == nil {
			t.Errorf("profile %q accepted", bad)
		}
	}
}

func TestCommandValidation(t *testing.T) {
	x := setup(t, true)
	for _, bad := range []string{"", strings.Repeat("a", maxCommand+1), "ls\x00rm"} {
		if _, err := x.m.Start(context.Background(), x.prof, bad, 0); err == nil {
			t.Errorf("command of %d bytes accepted", len(bad))
		}
	}
}

func TestTimeoutIsClampedToTheProfileMax(t *testing.T) {
	x := setup(t, true) // max_seconds 30
	x.ex.block = make(chan struct{})
	start := time.Now()
	id, err := x.m.Start(context.Background(), x.prof, "sleep 999", 100000)
	if err != nil {
		t.Fatal(err)
	}
	// Not waiting 30s: just check the run is still in flight, then release it.
	time.Sleep(50 * time.Millisecond)
	if v, _ := x.m.Get(id); v.(Result).Status != Running {
		t.Fatal("run ended early")
	}
	close(x.ex.block)
	wait(t, x.m, id)
	if time.Since(start) > 10*time.Second {
		t.Fatal("slow")
	}
}

func TestConcurrencyLimit(t *testing.T) {
	x := setup(t, true)
	x.ex.block = make(chan struct{})
	var ids []string
	for i := 0; i < maxConcurrent; i++ {
		id, err := x.m.Start(context.Background(), x.prof, "true", 0)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if _, err := x.m.Start(context.Background(), x.prof, "true", 0); err == nil {
		t.Fatal("run beyond the concurrency limit accepted")
	}
	close(x.ex.block)
	for _, id := range ids {
		wait(t, x.m, id)
	}
	id, err := x.m.Start(context.Background(), x.prof, "true", 0)
	if err != nil {
		t.Fatalf("slot not freed after runs finished: %v", err)
	}
	wait(t, x.m, id)
}

func TestCapWriter(t *testing.T) {
	c := &capWriter{limit: 5}
	c.Write([]byte("abc"))
	c.Write([]byte("defgh"))
	c.Write([]byte("more"))
	if c.String() != "abcde" || !c.truncated {
		t.Fatalf("%q %v", c.String(), c.truncated)
	}
}

// Regression, from a real model: it asked for a 10 second timeout and the run was
// killed while the guest was still booting, because the timeout covered boot. The
// timeout is for the command; boot has its own budget.
func TestACommandTimeoutShorterThanBootDoesNotKillTheGuestMidBoot(t *testing.T) {
	x := setup(t, true)
	x.run.bootDelay = 1500 * time.Millisecond // boot takes longer than the 1s timeout below
	id, err := x.m.Start(context.Background(), x.prof, "uname -r", 1)
	if err != nil {
		t.Fatal(err)
	}
	r := wait(t, x.m, id)
	if r.Status != Done || r.ExitCode == nil {
		t.Fatalf("a quick command in a slow-booting guest must complete: %+v", r)
	}
}

func TestDetailsDescribeProfilesWithoutExposingTheirContents(t *testing.T) {
	x := setup(t, true)
	got := x.m.Details().([]ProfileInfo)
	if len(got) != 1 || got[0].Name != "arch-update" || got[0].Network != "allowlist" || got[0].Sudo || got[0].MaxSeconds != 30 {
		t.Fatalf("%+v", got)
	}
	// A non-disposable profile is not offered, so it is not described either.
	y := setup(t, false)
	if d := y.m.Details().([]ProfileInfo); len(d) != 0 {
		t.Fatalf("an unusable profile was described: %+v", d)
	}
}
