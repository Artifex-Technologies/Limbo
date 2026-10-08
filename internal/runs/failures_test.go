//go:build linux

package runs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

// Failure modes of the agent-socket path (docs/INTEGRATION-FAILURES.md): each is
// a coded error with a remedy, is logged with the same code, and leaves no guest.

func torn(x *env, id string) bool { return x.run.has("nft delete table inet limbo_" + id) }

func startCode(t *testing.T, x *env, profile string) string {
	t.Helper()
	_, err := x.m.Start(context.Background(), profile, "true", 0)
	var re *Error
	if !errors.As(err, &re) {
		t.Fatalf("want a coded error, got %v", err)
	}
	if re.Remedy == "" || !strings.HasPrefix(re.Error(), re.Code+": ") {
		t.Fatalf("error must carry its code and a remedy: %q", re.Error())
	}
	return re.Code
}

func TestRefusedStartsAreCodedAndLogged(t *testing.T) {
	x := setup(t, true)
	for profile, want := range map[string]string{"nope": CodeProfileUnknown, "../etc/passwd": CodeProfileInvalid, "Bad": CodeProfileInvalid} {
		if got := startCode(t, x, profile); got != want {
			t.Errorf("%q: got %s want %s", profile, got, want)
		}
	}
	if _, err := x.m.Start(context.Background(), x.prof, "", 0); !strings.HasPrefix(fmt.Sprint(err), CodeBadRequest) {
		t.Errorf("empty command: %v", err)
	}
	if len(x.ev.codes) != 4 || !strings.HasPrefix(x.ev.codes[0], "run.error:") {
		t.Errorf("refusals must reach the event log with their code: %v", x.ev.codes)
	}
}

func TestMalformedAndNonDisposableProfilesAreProfileInvalid(t *testing.T) {
	x := setup(t, false)
	if got := startCode(t, x, x.prof); got != CodeProfileInvalid {
		t.Fatalf("non-disposable: %s", got)
	}
	os.WriteFile(filepath.Join(x.m.ProfileDir, "broken.json"), []byte("{not json"), 0o644)
	if got := startCode(t, x, "broken"); got != CodeProfileInvalid {
		t.Fatalf("malformed: %s", got)
	}
	os.WriteFile(filepath.Join(x.m.ProfileDir, "typo.json"), []byte(`{"manifest":{},"ssh_identty":"x"}`), 0o644)
	if got := startCode(t, x, "typo"); got != CodeProfileInvalid {
		t.Fatalf("unknown field: %s", got)
	}
}

func TestMissingImageIsRefusedBeforeAnythingIsCreated(t *testing.T) {
	x := setup(t, true)
	p, _ := x.m.loadProfile(x.prof)
	os.Remove(p.Manifest.Image.Path)
	if got := startCode(t, x, x.prof); got != CodeImageMissing {
		t.Fatalf("got %s", got)
	}
	if len(x.run.calls) != 0 {
		t.Fatalf("nothing may be created for a run that cannot start: %v", x.run.calls)
	}
}

func finishedWith(t *testing.T, x *env, id string, status Status, code string) Result {
	t.Helper()
	r := wait(t, x.m, id)
	if r.Status != status || r.Code != code {
		t.Fatalf("want %s/%s, got %+v", status, code, r)
	}
	if r.ExitCode != nil || r.Remedy == "" || !strings.HasPrefix(r.Error, code+": ") {
		t.Fatalf("an infrastructure failure must have no exit code and a remedy: %+v", r)
	}
	if strings.Contains(r.Error, "/") {
		t.Fatalf("error text must not carry host paths: %q", r.Error)
	}
	if !torn(x, id) {
		t.Fatal("guest not torn down")
	}
	return r
}

func TestImageChecksumMismatchIsImageMismatch(t *testing.T) {
	x := setup(t, true)
	p, _ := x.m.loadProfile(x.prof)
	os.WriteFile(p.Manifest.Image.Path, []byte("tampered"), 0o600)
	id, err := x.m.Start(context.Background(), x.prof, "true", 0)
	if err != nil {
		t.Fatal(err)
	}
	finishedWith(t, x, id, Failed, CodeImageMismatch)
}

func TestHostAndVirtFailuresAreClassified(t *testing.T) {
	for name, tc := range map[string]struct {
		failOn string
		err    error
		code   string
	}{
		"guest will not start": {"qemu:///system start", errors.New("virsh: error: internal error: process exited"), CodeBootFailed},
		"libvirt down":         {"qemu:///system net-define", errors.New("virsh: error: failed to connect to the hypervisor"), CodeVirtUnavail},
		"virsh missing":        {"qemu:///system net-define", fmt.Errorf("virsh: %w", exec.ErrNotFound), CodeVirtUnavail},
		"disk full":            {"qemu-img create", errors.New("qemu-img: No space left on device"), CodeHostResources},
		"memory":               {"qemu:///system start", errors.New("Cannot allocate memory"), CodeHostResources},
	} {
		t.Run(name, func(t *testing.T) {
			x := setup(t, true)
			x.run.failOn, x.run.failErr = tc.failOn, tc.err
			id, _ := x.m.Start(context.Background(), x.prof, "true", 0)
			r := finishedWith(t, x, id, Failed, tc.code)
			if strings.Contains(r.Error, "process exited") || strings.Contains(r.Error, "hypervisor") {
				t.Fatalf("raw tool output must not reach the model: %q", r.Error)
			}
			if got := x.ev.codes; len(got) == 0 || got[len(got)-1] != "run.error:"+tc.code {
				t.Fatalf("event log must carry the same code: %v", got)
			}
		})
	}
}

func TestSeedToolMissingIsVirtUnavailable(t *testing.T) {
	x := setup(t, true)
	x.m.BuildSeed = func(context.Context, *manifest.Manifest, string, string) error {
		return fmt.Errorf("xorriso: %w", exec.ErrNotFound)
	}
	id, _ := x.m.Start(context.Background(), x.prof, "true", 0)
	finishedWith(t, x, id, Failed, CodeVirtUnavail)
}

func TestSlowBootIsBootTimeoutNotACommandFailure(t *testing.T) {
	x := setup(t, true)
	x.ex.readyBlock = true
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	id, _ := x.m.Start(ctx, x.prof, "true", 0)
	finishedWith(t, x, id, Failed, CodeBootTimeout)
}

func TestCommandTimeoutIsCodedAndTornDown(t *testing.T) {
	x := setup(t, true)
	x.ex.block = make(chan struct{})
	id, _ := x.m.Start(context.Background(), x.prof, "sleep 999", 1)
	r := wait(t, x.m, id)
	if r.Status != Timeout || r.Code != CodeCommandTimeout || r.Remedy == "" || !strings.HasPrefix(r.Error, "command_timeout: ") {
		t.Fatalf("%+v", r)
	}
	if !torn(x, id) || x.ev.codes[len(x.ev.codes)-1] != "run.error:command_timeout" {
		t.Fatalf("teardown or event missing: %v", x.ev.codes)
	}
}

func TestGuestKilledMidCommand(t *testing.T) {
	x := setup(t, true)
	x.ex.runErr = fmt.Errorf("%w: Connection reset by peer", errConnection)
	id, _ := x.m.Start(context.Background(), x.prof, "stress", 0)
	finishedWith(t, x, id, Failed, CodeGuestKilled)
}

// The distinction the model depends on: a failing command is a result with an
// exit code and no code; only Limbo's own failure carries one.
func TestCommandFailureIsAResultWithNoCode(t *testing.T) {
	x := setup(t, true)
	x.ex.exit, x.ex.errOut = 2, "no such package"
	id, _ := x.m.Start(context.Background(), x.prof, "pacman -S nope", 0)
	r := wait(t, x.m, id)
	if r.Status != Done || r.ExitCode == nil || *r.ExitCode != 2 || r.Code != "" || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	if len(x.ev.codes) != 0 {
		t.Fatalf("a failing command is not an infrastructure error: %v", x.ev.codes)
	}
}

func TestHugeOutputIsFlaggedAndBinaryOutputIsMadeSafe(t *testing.T) {
	x := setup(t, true)
	x.ex.out, x.ex.trunc = "ok\x00\x1b[31m\xff\xfe\n", true
	id, _ := x.m.Start(context.Background(), x.prof, "cat /dev/urandom", 0)
	r := wait(t, x.m, id)
	if r.Status != Done || !r.Truncated || r.Code != CodeOutputTrunc || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	if strings.ContainsAny(r.Stdout, "\x00\x1b") || !utf8.ValidString(r.Stdout) {
		t.Fatalf("unsafe output: %q", r.Stdout)
	}
}

func TestBusyIsCoded(t *testing.T) {
	x := setup(t, true)
	x.ex.block = make(chan struct{})
	var ids []string
	for i := 0; i < maxConcurrent; i++ {
		id, _ := x.m.Start(context.Background(), x.prof, "true", 0)
		ids = append(ids, id)
	}
	if got := startCode(t, x, x.prof); got != CodeBusy {
		t.Fatalf("got %s", got)
	}
	close(x.ex.block)
	for _, id := range ids {
		wait(t, x.m, id)
	}
}

// A caller that goes away must not leave a guest or a slot behind.
func TestCancelledCallerStillGetsTeardownAndASettledRecord(t *testing.T) {
	x := setup(t, true)
	x.ex.block = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	id, _ := x.m.Start(ctx, x.prof, "sleep 60", 0)
	cancel()
	r := wait(t, x.m, id)
	if r.Status == Running || !torn(x, id) {
		t.Fatalf("run left behind: %+v", r)
	}
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	if x.m.active != 0 {
		t.Fatalf("slot leaked: %d", x.m.active)
	}
}

func TestFailedTeardownIsReportedAndReapedLater(t *testing.T) {
	x := setup(t, true)
	x.run.failOn, x.run.failErr = "destroy", errors.New("virsh: busy")
	id, _ := x.m.Start(context.Background(), x.prof, "true", 0)
	r := wait(t, x.m, id)
	if r.Status != Done || r.Code != CodeTeardownFailed || r.ExitCode == nil || !strings.Contains(r.Remedy, id) {
		t.Fatalf("%+v", r)
	}
	runDir := filepath.Join(x.m.StateDir, "runs", id)
	if _, err := os.Stat(runDir); err != nil {
		t.Fatal("the run directory is the reaper's marker and must remain")
	}
	x.run.mu.Lock()
	x.run.failOn = ""
	x.run.mu.Unlock()
	if n := x.m.ReapOrphans(context.Background()); n != 1 {
		t.Fatalf("reaped %d", n)
	}
	if _, err := os.Stat(runDir); err == nil {
		t.Fatal("marker not removed after a successful reap")
	}
}

func TestReapOrphansAfterACrashDestroysTheGuest(t *testing.T) {
	x := setup(t, true)
	os.MkdirAll(filepath.Join(x.m.StateDir, "runs", "rdeadbeef"), 0o700)
	os.MkdirAll(filepath.Join(x.m.StateDir, "runs", "not-a-run"), 0o700)
	if n := x.m.ReapOrphans(context.Background()); n != 1 || !x.run.has("limbo_rdeadbeef") {
		t.Fatalf("reaped %d, calls %v", n, x.run.calls)
	}
}

func TestOneRunsFailureDoesNotTouchAnother(t *testing.T) {
	x := setup(t, true)
	x.run.failOn, x.run.failErr = "qemu:///system start limbo-r", errors.New("boom")
	a, _ := x.m.Start(context.Background(), x.prof, "true", 0)
	b, _ := x.m.Start(context.Background(), x.prof, "true", 0)
	for _, id := range []string{a, b} {
		if r := wait(t, x.m, id); r.Code != CodeBootFailed || !torn(x, id) {
			t.Fatalf("%+v", r)
		}
	}
}
