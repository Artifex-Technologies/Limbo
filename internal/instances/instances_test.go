package instances

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

type fakeGuests struct {
	running map[string]bool // domain names
	defined map[string]bool
	ups     []*manifest.Manifest
	downs   []string
	upErr   error
}

func (f *fakeGuests) Up(_ context.Context, m *manifest.Manifest) error {
	if f.upErr != nil {
		return f.upErr
	}
	f.ups = append(f.ups, m)
	f.running[virt.DomainName(m)], f.defined[virt.DomainName(m)] = true, true
	return nil
}
func (f *fakeGuests) Down(_ context.Context, m *manifest.Manifest) error {
	f.downs = append(f.downs, m.Name)
	delete(f.running, virt.DomainName(m))
	delete(f.defined, virt.DomainName(m))
	return nil
}
func (f *fakeGuests) Defined(_ context.Context, m *manifest.Manifest) bool {
	return f.defined[virt.DomainName(m)]
}
func (f *fakeGuests) RunningDomains(context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	for k, v := range f.running {
		out[k] = v
	}
	return out, nil
}
func (f *fakeGuests) CleanState(*manifest.Manifest) {}

type fakeHolds map[string]quarantine.Record

func (h fakeHolds) Holding(g string) (quarantine.Record, bool) { r, ok := h[g]; return r, ok }

type fakeEvents struct{ kinds []string }

func (f *fakeEvents) Emit(kind, _ string, _ map[string]string) error {
	f.kinds = append(f.kinds, kind)
	return nil
}

func testManifest(name string) *manifest.Manifest {
	return &manifest.Manifest{
		Name: name, OS: "linux", CPUs: 2, MemoryMB: 2048,
		Image:   manifest.Image{Path: "/var/lib/limbo/images/base.qcow2", SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		Network: manifest.Network{Mode: "none"}, Clipboard: "off",
		Access: manifest.Access{User: "analyst"}, App: manifest.App{Name: "A", Exec: "a"},
		Devices: manifest.Devices{},
	}
}

func setup(t *testing.T) (*Service, *fakeGuests, fakeHolds, *fakeEvents) {
	t.Helper()
	d := t.TempDir()
	g := &fakeGuests{running: map[string]bool{}, defined: map[string]bool{}}
	h := fakeHolds{}
	ev := &fakeEvents{}
	s := &Service{
		Dir: filepath.Join(d, "etc"), StateDir: filepath.Join(d, "state"), LimboRoot: d, ExchangeRoot: filepath.Join(d, "exchange"),
		Guests: g, Holds: h, Events: ev, HostLimits: func() (int, int) { return 8, 16384 },
	}
	os.MkdirAll(s.StateDir, 0o700)
	root := Caller{Admin: true}
	if _, err := s.Add(testManifest("lab"), "", root); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(testManifest("matts"), "matt", root); err != nil {
		t.Fatal(err)
	}
	return s, g, h, ev
}

var member = Caller{UID: 1000, User: "matt"}
var other = Caller{UID: 1002, User: "guest"}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestListShowsInstancesRunsAndHandStartedGuests(t *testing.T) {
	s, g, h, _ := setup(t)
	for _, n := range []string{"r0123abcd", "manual"} {
		b, _ := json.Marshal(testManifest(n))
		os.WriteFile(filepath.Join(s.StateDir, n+".manifest.json"), b, 0o600)
	}
	g.running["limbo-r0123abcd"] = true
	h["lab"] = quarantine.Record{ID: "q1", Status: quarantine.StatusOpen, Level: quarantine.LevelRestrict, Source: "heimdall:limbo-guest"}
	vs := s.List(context.Background(), other)
	if len(vs) != 4 {
		t.Fatalf("%+v", vs)
	}
	got := map[string]View{}
	for _, v := range vs {
		got[v.Name] = v
	}
	if got["lab"].State != "held" || !got["lab"].HeldByHeimdall || got["lab"].Hold.ID != "q1" {
		t.Fatalf("held row: %+v", got["lab"])
	}
	if got["r0123abcd"].Kind != "run" || got["r0123abcd"].State != "running" || got["manual"].Kind != "manual" {
		t.Fatalf("others: %+v", vs)
	}
	if got["matts"].Mine || !got["lab"].Mine {
		t.Fatal("ownership")
	}
	if got["lab"].Devices == nil {
		t.Fatal("devices must be [] not null")
	}
}

func TestConfigureStaysInBoundsAndAppliesAtStart(t *testing.T) {
	s, g, _, ev := setup(t)
	ctx := context.Background()
	i := func(n int) *int { return &n }
	str := func(v string) *string { return &v }
	for name, ch := range map[string]Change{
		"too many cpus":  {CPUs: i(9)},
		"zero cpus":      {CPUs: i(0)},
		"too much mem":   {MemoryMB: i(16384)},
		"tiny mem":       {MemoryMB: i(256)},
		"huge disk":      {DiskGB: i(5000)},
		"bad share":      {SharedFolder: str("/etc")},
		"bad clipboard":  {Clipboard: str("all")},
		"foreign device": {Devices: &[]string{"0000:01:00.0"}},
		"nothing":        {},
	} {
		if _, err := s.Configure(ctx, "lab", ch, member); code(err) != CodeOutOfRange {
			t.Errorf("%s: %v", name, err)
		}
	}
	v, err := s.Configure(ctx, "lab", Change{CPUs: i(4), MemoryMB: i(8192), DiskGB: i(40), SharedFolder: str("on"), Clipboard: str("text")}, member)
	if err != nil {
		t.Fatal(err)
	}
	if v.CPUs != 4 || v.MemoryMB != 8192 || v.SharedFolder != "writable" || v.Clipboard != "text" || v.Disk.DiskGB != 40 {
		t.Fatalf("%+v", v)
	}
	if _, err := s.Start(ctx, "lab", member); err != nil {
		t.Fatal(err)
	}
	m := g.ups[0]
	if m.CPUs != 4 || m.ExchangeDir != filepath.Join(s.ExchangeRoot, "lab") || !m.ExchangeWritable || m.Network.Mode != "none" {
		t.Fatalf("started from %+v", m)
	}
	if ev.kinds[len(ev.kinds)-1] != EventRequest {
		t.Fatalf("events %v", ev.kinds)
	}
	if _, err := s.Start(ctx, "lab", member); code(err) != CodeRunning {
		t.Fatalf("second start: %v", err)
	}
}

func TestOwnerAndHoldRulesHoldForUsersNotRoot(t *testing.T) {
	s, _, h, _ := setup(t)
	ctx := context.Background()
	n := 3
	if _, err := s.Configure(ctx, "matts", Change{CPUs: &n}, other); code(err) != CodeNotOwner {
		t.Fatalf("not owner: %v", err)
	}
	if _, err := s.Configure(ctx, "matts", Change{CPUs: &n}, member); err != nil {
		t.Fatal(err)
	}
	h["lab"] = quarantine.Record{ID: "q1", Status: quarantine.StatusOpen, Source: "heimdall:x"}
	if _, err := s.Start(ctx, "lab", member); code(err) != CodeHeld {
		t.Fatalf("start held: %v", err)
	}
	if _, err := s.Stop(ctx, "lab", member); code(err) != CodeHeld {
		t.Fatalf("stop held: %v", err)
	}
	if _, err := s.Configure(ctx, "lab", Change{CPUs: &n}, member); code(err) != CodeHeld {
		t.Fatalf("configure held: %v", err)
	}
	// A held guest's disk is evidence: nobody frees it, root included.
	if _, err := s.FreeSpace(ctx, "lab", Caller{Admin: true}); code(err) != CodeHeld {
		t.Fatalf("free held: %v", err)
	}
}

func TestFreeSpaceDeletesOnlyAStoppedInstancesOwnDisk(t *testing.T) {
	s, g, _, _ := setup(t)
	ctx := context.Background()
	p := filepath.Join(s.StateDir, "lab.disk.qcow2")
	os.WriteFile(p, make([]byte, 8192), 0o600)
	g.defined["limbo-lab"] = true
	if _, err := s.FreeSpace(ctx, "lab", member); code(err) != CodeRunning {
		t.Fatalf("running: %v", err)
	}
	delete(g.defined, "limbo-lab")
	n, err := s.FreeSpace(ctx, "lab", member)
	if err != nil || n == 0 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("disk still there")
	}
}

func TestRunsAndHandStartedGuestsAreNotChangedHere(t *testing.T) {
	s, _, _, _ := setup(t)
	b, _ := json.Marshal(testManifest("r0123abcd"))
	os.WriteFile(filepath.Join(s.StateDir, "r0123abcd.manifest.json"), b, 0o600)
	n := 2
	if _, err := s.Configure(context.Background(), "r0123abcd", Change{CPUs: &n}, Caller{Admin: true}); code(err) != CodeReadOnly {
		t.Fatalf("%v", err)
	}
	if _, err := s.Start(context.Background(), "../../x", member); code(err) != CodeNotFound {
		t.Fatalf("%v", err)
	}
}

func TestOnlyRootRegistersAndInstancesAreNotDisposable(t *testing.T) {
	s, g, _, _ := setup(t)
	if _, err := s.Add(testManifest("new"), "", member); err == nil {
		t.Fatal("a member registered an instance")
	}
	d := testManifest("new")
	d.Disposable = true
	if _, err := s.Add(d, "", Caller{Admin: true}); err == nil {
		t.Fatal("disposable instance")
	}
	if _, err := s.Add(testManifest("lab"), "", Caller{Admin: true}); code(err) != CodeExists {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.Remove(context.Background(), "lab", false, member); err == nil {
		t.Fatal("a member removed an instance")
	}
	g.defined["limbo-lab"] = true
	if err := s.Remove(context.Background(), "lab", false, Caller{Admin: true}); code(err) != CodeRunning {
		t.Fatalf("remove running: %v", err)
	}
	delete(g.defined, "limbo-lab")
	if err := s.Remove(context.Background(), "lab", true, Caller{Admin: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), "lab", member); code(err) != CodeNotFound {
		t.Fatal("still listed")
	}
}

func TestSpaceCountsGuestsDisks(t *testing.T) {
	s, _, _, _ := setup(t)
	os.WriteFile(filepath.Join(s.StateDir, "lab.disk.qcow2"), make([]byte, 65536), 0o600)
	os.MkdirAll(filepath.Join(s.LimboRoot, "images"), 0o755)
	os.WriteFile(filepath.Join(s.LimboRoot, "images", "x"), make([]byte, 65536), 0o600)
	sp := s.Space(context.Background())
	if sp.GuestsBytes == 0 || sp.ImagesBytes == 0 || sp.TotalBytes < sp.GuestsBytes+sp.ImagesBytes {
		t.Fatalf("%+v", sp)
	}
}
