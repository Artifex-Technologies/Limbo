package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/parity"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

// parityRunner records every command and fails the ones whose line starts with failOn, as the real runner words it.
type parityRunner struct {
	calls  []map[string]string
	failOn string
}

func (f *parityRunner) Run(_ context.Context, stdin, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, map[string]string{"cmd": line, "stdin": stdin})
	if f.failOn != "" && strings.HasPrefix(line, f.failOn) {
		return fmt.Errorf("%s: exit status 1: boom", line)
	}
	return nil
}

type parityEvents struct{ evs []map[string]any }

func (f *parityEvents) Emit(kind, guest string, d map[string]string) error {
	f.evs = append(f.evs, map[string]any{"kind": kind, "guest": guest, "detail": d})
	return nil
}

type parityHolds struct{ rec *quarantine.Record }

func (h parityHolds) Holding(string) (quarantine.Record, bool) {
	if h.rec == nil {
		return quarantine.Record{}, false
	}
	return *h.rec, true
}

// EngineScenario is one fixture case: a manifest, what the engine is given, and the operation.
type EngineScenario struct {
	Manifest   string `json:"manifest"`
	Op         string `json:"op"` // up, down, hold-restrict, hold-isolate, release, defined
	FailOn     string `json:"fail_on"`
	Held       string `json:"held"` // "", open, dangerous
	UFW        bool   `json:"ufw"`
	Subnets    bool   `json:"subnets"`
	InUse      []int  `json:"in_use"`
	Overlay    bool   `json:"overlay"` // a disposable guest's overlay exists before the op (down: moved or removed)
	Exchange   bool   `json:"exchange"`
	ImageBytes string `json:"image_bytes"`
}

// TestParityEngine: the exact commands, stdin, events and files of up, down, holds and release, failures included.
func TestParityEngine(t *testing.T) {
	img := "abc"
	sum := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	base := func(extra string) string {
		return `{"name":"lab","os":"linux","image":{"path":"$T/a.img","sha256":"` + sum + `"},"access":{"user":"analyst"},"app":{"name":"A","exec":"a"}` + extra + `}`
	}
	var scen []EngineScenario
	mans := []string{
		base(`,"network":{"mode":"internet-only"}`),
		base(`,"disposable":true`),
		base(`,"disposable":true,"network":{"mode":"allowlist","allow":[{"addr":"1.1.1.1","port":53,"proto":"udp"},{"addr":"2001:db8::/32","port":443}]}`),
		base(`,"disk_gb":40,"cpus":4,"memory_mb":2048`),
		base(`,"disposable":true,"devices":{"usb":["5059:4040"]}`),
		strings.Replace(base(`,"disposable":true`), `"os":"linux"`, `"os":"windows"`, 1),
		// (a writable share in its own outbox is left out: whether it is accepted depends on the mount of the test folder)
		base(`,"exchange_dir":"$T/other","exchange_writable":true`),
		base(`,"exchange_dir":"$T/ro"`),
	}
	ups := []string{"", "qemu-img create", "qemu-img resize", "virsh -c qemu:///system net-define", "virsh -c qemu:///system net-start",
		"nft -f -", "ufw allow in on lb-lab to any port 53 proto udp", "virsh -c qemu:///system define", "virsh -c qemu:///system start"}
	for mi, m := range mans {
		for _, f := range ups {
			scen = append(scen, EngineScenario{Manifest: m, Op: "up", FailOn: f, UFW: mi == 0, Subnets: mi%2 == 0, Exchange: mi >= 5})
		}
		for _, op := range []string{"down", "hold-restrict", "hold-isolate", "hold-bogus", "release", "defined"} {
			for _, f := range []string{"", "virsh -c qemu:///system destroy", "nft", "virsh -c qemu:///system domif-setlink", "ufw --force route", "virsh -c qemu:///system dominfo"} {
				scen = append(scen, EngineScenario{Manifest: m, Op: op, FailOn: f, UFW: mi == 0, Subnets: mi%2 == 0, Overlay: true})
			}
		}
	}
	scen = append(scen,
		EngineScenario{Manifest: mans[0], Op: "up", Held: "open"},
		EngineScenario{Manifest: mans[1], Op: "up", Held: "dangerous"},
		EngineScenario{Manifest: mans[1], Op: "down", Held: "dangerous", Overlay: true},
		EngineScenario{Manifest: mans[1], Op: "down", Held: "open", Overlay: true},
		EngineScenario{Manifest: mans[0], Op: "up", ImageBytes: "abd"},
		EngineScenario{Manifest: mans[0], Op: "up", ImageBytes: "-"},
		EngineScenario{Manifest: mans[0], Op: "up", Subnets: true, InUse: []int{1, 2, 3}},
	)
	var allIn []int
	for i := 1; i <= 254; i++ {
		allIn = append(allIn, i)
	}
	scen = append(scen, EngineScenario{Manifest: mans[0], Op: "up", Subnets: true, InUse: allIn})

	var cases []parity.Case
	for _, sc := range scen {
		dir := t.TempDir()
		norm := func(s string) string { return strings.ReplaceAll(s, dir, "$T") }
		b := sc.ImageBytes
		if b == "" {
			b = img
		}
		if b != "-" {
			if err := os.WriteFile(filepath.Join(dir, "a.img"), []byte(b), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		m, err := manifest.Parse([]byte(strings.ReplaceAll(sc.Manifest, "$T", dir)))
		if err != nil {
			t.Fatal(err)
		}
		r, ev := &parityRunner{failOn: sc.FailOn}, &parityEvents{}
		e := &Engine{Runner: r, Events: ev, StateDir: filepath.Join(dir, "state")}
		if sc.UFW {
			e.UFWActive = func() bool { return true }
		}
		if sc.Subnets {
			in := map[int]bool{}
			for _, x := range sc.InUse {
				in[x] = true
			}
			e.Subnets = &virt.Subnets{Path: filepath.Join(dir, "state", "subnets.json"), InUse: func() map[int]bool { return in }}
		}
		if sc.Exchange {
			e.ExchangeRoot = filepath.Join(dir, "exchange")
		}
		if sc.Held != "" {
			e.Holds = parityHolds{&quarantine.Record{ID: "q-0123456789ab", Status: quarantine.Status(sc.Held)}}
		}
		if sc.Overlay {
			_ = os.MkdirAll(e.StateDir, 0o700)
			_ = os.WriteFile(filepath.Join(e.StateDir, virt.OverlayName(m)), []byte("overlay"), 0o600)
		}
		var opErr error
		out := map[string]any{}
		ctx := context.Background()
		switch sc.Op {
		case "up":
			opErr = e.Up(ctx, m)
			out["subnet"] = m.Subnet
		case "down":
			opErr = e.Down(ctx, m)
		case "hold-restrict":
			opErr = e.Hold(ctx, m, quarantine.LevelRestrict)
		case "hold-isolate":
			opErr = e.Hold(ctx, m, quarantine.LevelIsolate)
		case "hold-bogus":
			opErr = e.Hold(ctx, m, "bogus")
		case "release":
			opErr = e.Release(ctx, m)
		case "defined":
			out["defined"] = e.Defined(ctx, m)
		}
		out["error"] = norm(parity.Err(opErr))
		for _, c := range r.calls {
			c["cmd"], c["stdin"] = norm(c["cmd"]), norm(c["stdin"])
		}
		out["calls"] = r.calls
		for _, x := range ev.evs {
			d := x["detail"].(map[string]string)
			for k, v := range d {
				d[k] = norm(v)
			}
		}
		out["events"] = ev.evs
		var files []string
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasSuffix(p, ".lock") {
				return nil
			}
			b, _ := os.ReadFile(p)
			fi, _ := os.Stat(p)
			files = append(files, fmt.Sprintf("%s %o\n%s", norm(p), fi.Mode().Perm(), norm(string(b))))
			return nil
		})
		sort.Strings(files)
		out["files"] = files
		in, _ := json.Marshal(sc)
		cases = append(cases, parity.Case{Fn: "engine", In: json.RawMessage(in), Out: out})
	}
	parity.Fixture(t, "engine", cases)
}
