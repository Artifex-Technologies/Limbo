package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/license"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

type fakeRunner struct {
	calls  []string
	stdin  map[string]string
	failOn string // substring of "name args" that should fail
}

func (f *fakeRunner) Run(_ context.Context, stdin, name string, args ...string) error {
	c := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, c)
	if f.stdin == nil {
		f.stdin = map[string]string{}
	}
	f.stdin[c] = stdin
	if f.failOn != "" && strings.Contains(c, f.failOn) {
		return errors.New("boom")
	}
	return nil
}

type fakeEvents struct{ kinds []string }

func (f *fakeEvents) Emit(kind, _ string, _ map[string]string) error {
	f.kinds = append(f.kinds, kind)
	return nil
}

// fixture writes a real 3-byte image whose SHA-256 is known, since Up verifies it.
func fixture(t *testing.T, osName string) (*manifest.Manifest, *Engine, *fakeRunner, *fakeEvents) {
	t.Helper()
	dir := t.TempDir()
	img := filepath.Join(dir, "a.img")
	if err := os.WriteFile(img, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{
		Name: "lab", OS: osName, CPUs: 2, MemoryMB: 1024,
		Image:   manifest.Image{Path: img, SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		Network: manifest.Network{Mode: manifest.NetInternetOnly}, Clipboard: manifest.ClipOff,
		Access: manifest.Access{User: "analyst"}, App: manifest.App{Name: "A", Exec: "a"},
	}
	r, ev := &fakeRunner{}, &fakeEvents{}
	return m, &Engine{Runner: r, Events: ev, StateDir: filepath.Join(dir, "state")}, r, ev
}

func index(calls []string, sub string) int {
	for i, c := range calls {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

func TestUpLoadsFirewallBeforeGuestStarts(t *testing.T) {
	m, e, r, ev := fixture(t, "linux")
	if err := e.Up(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	nft, start := index(r.calls, "nft -f -"), index(r.calls, "qemu:///system start limbo-lab")
	if nft < 0 || start < 0 || nft > start {
		t.Fatalf("firewall must load before start: %v", r.calls)
	}
	if !strings.Contains(r.stdin["nft -f -"], "table inet limbo_lab") {
		t.Fatal("ruleset not sent on stdin")
	}
	if got := ev.kinds[len(ev.kinds)-1]; got != events.GuestStart {
		t.Fatalf("last event %q", got)
	}
}

func TestUFWIsOpenedForTheBridgeAfterOurTableAndClosedOnDown(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	e.UFWActive = func() bool { return true }
	if err := e.Up(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	nft, ufw, start := index(r.calls, "nft -f -"), index(r.calls, "ufw allow in on lb-lab to any port 67 proto udp"), index(r.calls, "qemu:///system start limbo-lab")
	if !(nft >= 0 && nft < ufw && ufw < start) {
		t.Fatalf("our table first, then the host firewall, then the guest: %v", r.calls)
	}
	if index(r.calls, "ufw route allow in on lb-lab") < 0 {
		t.Fatalf("the bridge must be allowed to forward: %v", r.calls)
	}
	r.calls = nil
	if err := e.Down(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	del, drop := index(r.calls, "ufw --force delete allow in on lb-lab to any port 67 proto udp"), index(r.calls, "nft delete table inet limbo_lab")
	if del < 0 || del > drop {
		t.Fatalf("the host firewall rules go before our table does: %v", r.calls)
	}
}

func TestUFWIsLeftAloneWhenItIsOff(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	e.UFWActive = func() bool { return false }
	if err := e.Up(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if index(r.calls, "ufw") >= 0 {
		t.Fatalf("no ufw commands when it is not active: %v", r.calls)
	}
}

func TestUpBlockedBeforeAnySideEffect(t *testing.T) {
	t.Run("windows without license", func(t *testing.T) {
		m, e, r, ev := fixture(t, "windows")
		err := e.Up(context.Background(), m)
		if !errors.Is(err, license.ErrWindowsNotConfigured) || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v", err, r.calls)
		}
		if len(ev.kinds) != 1 || ev.kinds[0] != events.GateBlocked {
			t.Fatalf("events %v", ev.kinds)
		}
	})
	t.Run("tampered image", func(t *testing.T) {
		m, e, r, ev := fixture(t, "linux")
		m.Image.SHA256 = strings.Repeat("0", 64)
		if err := e.Up(context.Background(), m); err == nil || len(r.calls) != 0 {
			t.Fatalf("err=%v calls=%v", err, r.calls)
		}
		if ev.kinds[0] != events.ImageRejected {
			t.Fatalf("events %v", ev.kinds)
		}
	})
}

func TestUpFailureRollsBack(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	r.failOn = "nft -f -"
	if err := e.Up(context.Background(), m); err == nil {
		t.Fatal("expected error")
	}
	if index(r.calls, "qemu:///system start limbo-lab") >= 0 {
		t.Fatal("guest started despite firewall failure")
	}
	if index(r.calls, "net-undefine") < 0 {
		t.Fatalf("no rollback: %v", r.calls)
	}
}

func TestDownRemovesFirewallLast(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	r.failOn = "destroy limbo-lab" // one step failing must not stop the rest
	err := e.Down(context.Background(), m)
	if err == nil {
		t.Fatal("expected joined error")
	}
	if len(r.calls) != 5 || !strings.Contains(r.calls[4], "nft delete table inet limbo_lab") {
		t.Fatalf("calls: %v", r.calls)
	}
}

// Disposable guests boot from a per-guest overlay backed by the base image, so
// the base is only opened read-only and several guests can share it.
func TestDisposableUsesOverlayAndRemovesIt(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	m.Disposable = true
	if err := e.Up(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	qi, def := index(r.calls, "qemu-img create"), index(r.calls, "qemu:///system define")
	if qi < 0 || def < 0 || qi > def {
		t.Fatalf("overlay must be created before the domain is defined: %v", r.calls)
	}
	if !strings.Contains(r.calls[qi], "-b "+m.Image.Path) || !strings.Contains(r.calls[qi], "-F qcow2") {
		t.Fatalf("overlay not backed by the base image: %s", r.calls[qi])
	}
	dom, err := os.ReadFile(filepath.Join(e.StateDir, "lab.domain.xml"))
	if err != nil || !strings.Contains(string(dom), "lab.overlay.qcow2") || strings.Contains(string(dom), m.Image.Path) {
		t.Fatalf("domain must boot from the overlay only (err=%v):\n%s", err, dom)
	}

	// Stand in for the file qemu-img would have made, then check Down discards it.
	ov := filepath.Join(e.StateDir, "lab.overlay.qcow2")
	if err := os.WriteFile(ov, []byte("guest writes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Down(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ov); !os.IsNotExist(err) {
		t.Fatalf("overlay survived Down: %v", err)
	}
}

func TestPersistentGuestBootsBaseDirectly(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	if err := e.Up(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if index(r.calls, "qemu-img") >= 0 {
		t.Fatalf("persistent guest must not get an overlay: %v", r.calls)
	}
}

type fakeHardware struct{ err, ready, after error }

func (f fakeHardware) Check(*manifest.Manifest) error { return f.err }
func (f fakeHardware) Ready(*manifest.Manifest) error { return f.ready }
func (f fakeHardware) Before(*manifest.Manifest) map[string]string {
	return map[string]string{"x": "nvidia"}
}
func (f fakeHardware) After(*manifest.Manifest, map[string]string) error {
	return f.after
}

func TestUpRefusesDevicesUnlessHostAllows(t *testing.T) {
	cases := map[string]Hardware{
		"no policy":    nil,
		"host denies":  fakeHardware{err: errors.New("nope")},
		"not approved": fakeHardware{ready: errors.New("no approval")},
	}
	for name, hw := range cases {
		t.Run(name, func(t *testing.T) {
			m, e, r, ev := fixture(t, "linux")
			m.Disposable = true
			m.Devices.PCI = []string{"0000:03:00.0"}
			e.Hardware = hw
			err := e.Up(context.Background(), m)
			if !errors.Is(err, ErrHardwareDenied) {
				t.Fatalf("want ErrHardwareDenied, got %v", err)
			}
			if len(r.calls) != 0 {
				t.Fatalf("a refused guest must not touch the host: %v", r.calls)
			}
			if len(ev.kinds) != 1 || ev.kinds[0] != events.GateBlocked {
				t.Fatalf("refusal must be audited: %v", ev.kinds)
			}
		})
	}
}

func TestUpAllowsDevicesWhenHostAllows(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	m.Disposable = true
	m.Devices.PCI = []string{"0000:03:00.0"}
	e.Hardware = fakeHardware{}
	if err := e.Up(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if index(r.calls, "qemu:///system start") < 0 {
		t.Fatalf("guest did not start: %v", r.calls)
	}
}

func TestGuestWithoutDevicesNeedsNoPolicy(t *testing.T) {
	m, e, _, _ := fixture(t, "linux")
	if err := e.Up(context.Background(), m); err != nil { // Hardware is nil
		t.Fatal(err)
	}
}

func TestStuckDeviceAfterTeardownIsAudited(t *testing.T) {
	m, e, _, ev := fixture(t, "linux")
	m.Disposable = true
	m.Devices.PCI = []string{"0000:03:00.0"}
	e.Hardware = fakeHardware{after: errors.New("still vfio-pci")}
	if err := e.Up(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if err := e.Down(context.Background(), m); err != nil {
		t.Fatalf("a stuck device must not turn teardown into a failure: %v", err)
	}
	found := false
	for _, k := range ev.kinds {
		found = found || k == events.HardwareStuck
	}
	if !found {
		t.Fatalf("hardware.stuck not audited: %v", ev.kinds)
	}
}

func TestAWritableShareNeedsANosuidNodevMount(t *testing.T) {
	if !mountSafe(0x2|0x4) || mountSafe(0x2) || mountSafe(0x4) || mountSafe(0) {
		t.Fatal("mountSafe must need both nosuid and nodev")
	}
	ro := &manifest.Manifest{ExchangeDir: t.TempDir()}
	if err := exchangeSafe(ro); err != nil {
		t.Fatalf("a read-only share needs nothing: %v", err)
	}
}
