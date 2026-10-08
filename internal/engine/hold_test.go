package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
)

type fakeHolds struct{ rec *quarantine.Record }

func (f fakeHolds) Holding(string) (quarantine.Record, bool) {
	if f.rec == nil {
		return quarantine.Record{}, false
	}
	return *f.rec, true
}

func TestRestrictReplacesTableWithDenyAll(t *testing.T) {
	m, e, r, ev := fixture(t, "linux") // internet-only
	if err := e.Restrict(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	in := r.stdin["nft -f -"]
	if !strings.HasPrefix(in, "table inet limbo_lab\ndelete table inet limbo_lab\n") {
		t.Fatalf("not an atomic replace:\n%s", in)
	}
	if strings.Contains(in, `iifname "lb-lab" accept`) || strings.Contains(in, "dport 53") {
		t.Fatalf("restrict ruleset is not deny-all:\n%s", in)
	}
	if len(ev.kinds) != 1 || ev.kinds[0] != events.PolicyRestrict {
		t.Fatalf("events: %v", ev.kinds)
	}
	if len(r.calls) != 1 {
		t.Fatalf("restrict must touch only the firewall: %v", r.calls)
	}
}

func TestIsolateAlsoDropsTheLink(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	if err := e.Isolate(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	nft, link := index(r.calls, "nft -f -"), index(r.calls, "domif-setlink limbo-lab vl-lab down")
	if nft < 0 || link < 0 || nft > link {
		t.Fatalf("restrict first, then link down: %v", r.calls)
	}
}

func TestRestrictStillActsWhenAuditFails(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	e.Events = failingEvents{}
	err := e.Restrict(context.Background(), m)
	if len(r.calls) != 1 {
		t.Fatalf("a safety-increasing action must not be blocked by a logging failure: %v", r.calls)
	}
	if err == nil {
		t.Fatal("the logging failure should still be reported")
	}
}

func TestReleaseFailsClosedWhenAuditFails(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	e.Events = failingEvents{}
	if err := e.Release(context.Background(), m); err == nil {
		t.Fatal("expected an error")
	}
	if len(r.calls) != 0 {
		t.Fatalf("a loosening action must not run unlogged: %v", r.calls)
	}
}

func TestReleaseRestoresManifestPolicyAndLink(t *testing.T) {
	m, e, r, _ := fixture(t, "linux")
	if err := e.Release(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.stdin["nft -f -"], `iifname "lb-lab" accept`) {
		t.Fatalf("original internet-only policy not restored:\n%s", r.stdin["nft -f -"])
	}
	if index(r.calls, "domif-setlink limbo-lab vl-lab up") < 0 {
		t.Fatalf("link not brought up: %v", r.calls)
	}
}

func TestUpRefusesAHeldGuest(t *testing.T) {
	for _, st := range []quarantine.Status{quarantine.StatusOpen, quarantine.StatusDangerous} {
		m, e, r, ev := fixture(t, "linux")
		e.Holds = fakeHolds{&quarantine.Record{ID: "q-1", Status: st}}
		err := e.Up(context.Background(), m)
		if !errors.Is(err, ErrQuarantined) || len(r.calls) != 0 {
			t.Fatalf("%s: err=%v calls=%v", st, err, r.calls)
		}
		if len(ev.kinds) != 1 || ev.kinds[0] != events.GateBlocked {
			t.Fatalf("%s: events %v", st, ev.kinds)
		}
	}
}

func TestUpRecordsManifestForLaterHolds(t *testing.T) {
	m, e, _, _ := fixture(t, "linux")
	if err := e.Up(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(ManifestPath(e.StateDir, "lab")); err != nil || fi.Size() == 0 {
		t.Fatalf("manifest copy missing: %v", err)
	}
}

func TestCondemnedGuestKeepsItsOverlayAsEvidence(t *testing.T) {
	m, e, _, _ := fixture(t, "linux")
	m.Disposable = true
	e.Holds = fakeHolds{&quarantine.Record{ID: "q-9", Status: quarantine.StatusDangerous}}
	os.MkdirAll(e.StateDir, 0o700)
	ov := filepath.Join(e.StateDir, "lab.overlay.qcow2")
	os.WriteFile(ov, []byte("what the guest wrote"), 0o600)
	if err := e.discardOverlay(m); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ov); !os.IsNotExist(err) {
		t.Fatal("overlay should have been moved")
	}
	kept, err := os.ReadFile(filepath.Join(e.StateDir, "evidence", "q-9.overlay.qcow2"))
	if err != nil || string(kept) != "what the guest wrote" {
		t.Fatalf("evidence not preserved: %v", err)
	}
}

type failingEvents struct{}

func (failingEvents) Emit(string, string, map[string]string) error { return errors.New("disk full") }
