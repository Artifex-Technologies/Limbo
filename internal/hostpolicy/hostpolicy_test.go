package hostpolicy

import (
	"errors"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

const gpu, gpuAudio = "0000:03:00.0", "0000:03:00.1"

// host is a fake machine: files by path (no leading slash), as os.DirFS("/") would see them.
type host struct {
	fs   fstest.MapFS
	open map[string][]string
	drv  map[string]string
	now  time.Time
	p    *Policy
}

func newHost(t *testing.T, osID string, allow ...string) *host {
	t.Helper()
	h := &host{fs: fstest.MapFS{}, open: map[string][]string{}, drv: map[string]string{}, now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	h.file("etc/os-release", "NAME=x\nID="+osID+"\n")
	list := `{"pci_allow":[`
	for i, a := range allow {
		if i > 0 {
			list += ","
		}
		list += `"` + a + `"`
	}
	h.file("etc/limbo/host-policy.json", list+`]}`)
	h.p = &Policy{
		Root: h.fs, StateDir: t.TempDir(), RunDir: t.TempDir(),
		Now:       func() time.Time { return h.now },
		OpenFiles: func() map[string][]string { return h.open },
		Driver:    func(a string) string { return h.drv[a] },
	}
	return h
}

func (h *host) file(path, body string) { h.fs[path] = &fstest.MapFile{Data: []byte(body)} }

// device adds a PCI device whose IOMMU group holds members.
func (h *host) device(addr, class string, bootVGA bool, members ...string) {
	d := "sys/bus/pci/devices/" + addr + "/"
	h.file(d+"class", class+"\n")
	if bootVGA {
		h.file(d+"boot_vga", "1\n")
	}
	for _, mem := range members {
		h.file(d+"iommu_group/devices/"+mem, "")
	}
}

func guest(addrs ...string) *manifest.Manifest {
	return &manifest.Manifest{Name: "lab", OS: manifest.OSLinux, Disposable: true, Devices: manifest.Devices{PCI: addrs}}
}

func denied(t *testing.T, err error) {
	t.Helper()
	var d *Denied
	if !errors.As(err, &d) {
		t.Fatalf("want *Denied, got %v", err)
	}
}

func TestNoDevicesAlwaysPasses(t *testing.T) {
	h := newHost(t, "chymaera")
	if err := h.p.Check(guest()); err != nil {
		t.Fatal(err)
	}
	if err := h.p.Ready(guest()); err != nil {
		t.Fatal(err)
	}
}

func TestChymaeraNeverAllowsEvenWhenListed(t *testing.T) {
	for _, id := range []string{"chymaera", "niflheim"} {
		h := newHost(t, id, gpu)
		h.device(gpu, "0x030000", false, gpu)
		denied(t, h.p.Check(guest(gpu)))
		if !neverOS[id] {
			t.Fatalf("%s must be refused by name, not only as an unknown OS", id)
		}
	}
}

func TestUnknownOrUnreadableOSDenies(t *testing.T) {
	h := newHost(t, "debian", gpu)
	h.device(gpu, "0x030000", false, gpu)
	denied(t, h.p.Check(guest(gpu)))
	delete(h.fs, "etc/os-release")
	denied(t, h.p.Check(guest(gpu)))
}

func TestLabyrinthAllowsListedDevice(t *testing.T) {
	h := newHost(t, `"labyrinth"`, gpu, gpuAudio)
	h.device(gpu, "0x030000", false, gpu, gpuAudio)
	h.device(gpuAudio, "0x040300", false, gpu, gpuAudio)
	if err := h.p.Check(guest(gpu, gpuAudio)); err != nil {
		t.Fatal(err)
	}
}

func TestLabyrinthRefusals(t *testing.T) {
	cases := map[string]func(h *host) *manifest.Manifest{
		"not on the list": func(h *host) *manifest.Manifest {
			h.file("etc/limbo/host-policy.json", `{"pci_allow":[]}`)
			h.device(gpu, "0x030000", false, gpu)
			return guest(gpu)
		},
		"no config file": func(h *host) *manifest.Manifest {
			delete(h.fs, "etc/limbo/host-policy.json")
			h.device(gpu, "0x030000", false, gpu)
			return guest(gpu)
		},
		"malformed config": func(h *host) *manifest.Manifest {
			h.file("etc/limbo/host-policy.json", "{")
			h.device(gpu, "0x030000", false, gpu)
			return guest(gpu)
		},
		"not present": func(h *host) *manifest.Manifest { return guest(gpu) },
		"boot display": func(h *host) *manifest.Manifest {
			h.device(gpu, "0x030000", true, gpu)
			return guest(gpu)
		},
		"no iommu group": func(h *host) *manifest.Manifest {
			h.device(gpu, "0x030000", false)
			return guest(gpu)
		},
		"group has an unrequested device": func(h *host) *manifest.Manifest {
			h.device(gpu, "0x030000", false, gpu, gpuAudio)
			h.device(gpuAudio, "0x040300", false, gpu, gpuAudio)
			return guest(gpu)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, "labyrinth", gpu)
			denied(t, h.p.Check(setup(h)))
		})
	}
}

func TestBridgeInGroupIsIgnored(t *testing.T) {
	h := newHost(t, "labyrinth", gpu)
	h.device(gpu, "0x030000", false, gpu, "0000:02:00.0")
	h.device("0000:02:00.0", "0x060400", false)
	if err := h.p.Check(guest(gpu)); err != nil {
		t.Fatal(err)
	}
}

// ready returns a Labyrinth host with the GPU eligible, an NVIDIA card with a DRM node.
func ready(t *testing.T) *host {
	h := newHost(t, "labyrinth", gpu)
	h.device(gpu, "0x030000", false, gpu)
	h.file("sys/bus/pci/devices/"+gpu+"/vendor", "0x10de\n")
	h.file("sys/bus/pci/devices/"+gpu+"/drm/renderD129", "")
	h.drv[gpu] = "nvidia"
	return h
}

func TestReadyNeedsApproval(t *testing.T) {
	h := ready(t)
	var na *NeedsApproval
	if err := h.p.Ready(guest(gpu)); !errors.As(err, &na) {
		t.Fatalf("want NeedsApproval, got %v", err)
	}
}

func TestApproveThenReadyThenExpire(t *testing.T) {
	h := ready(t)
	if _, err := h.p.Approve([]string{gpu}, 30*time.Minute, "me"); err != nil {
		t.Fatal(err)
	}
	if err := h.p.Ready(guest(gpu)); err != nil {
		t.Fatalf("approved and idle should be ready: %v", err)
	}
	h.now = h.now.Add(31 * time.Minute)
	var na *NeedsApproval
	if err := h.p.Ready(guest(gpu)); !errors.As(err, &na) {
		t.Fatalf("an expired approval must not stand, got %v", err)
	}
}

func TestApprovalCoversOnlyNamedDevices(t *testing.T) {
	h := ready(t)
	const nic = "0000:04:00.0" // its own IOMMU group
	h.device(nic, "0x020000", false, nic)
	h.file("etc/limbo/host-policy.json", `{"pci_allow":["`+gpu+`","`+nic+`"]}`)
	if _, err := h.p.Approve([]string{gpu}, time.Hour, "me"); err != nil {
		t.Fatal(err)
	}
	var na *NeedsApproval
	if err := h.p.Ready(guest(gpu, nic)); !errors.As(err, &na) {
		t.Fatalf("approval for one device must not cover two, got %v", err)
	}
}

func TestApproveRefusals(t *testing.T) {
	h := ready(t)
	if _, err := h.p.Approve([]string{gpu}, 3*time.Hour, "me"); err == nil {
		t.Fatal("an approval longer than the cap was granted")
	}
	if _, err := h.p.Approve([]string{gpu}, 0, "me"); err == nil {
		t.Fatal("a zero-length approval was granted")
	}
	if _, err := h.p.Approve([]string{"0000:09:00.0"}, time.Hour, "me"); err == nil {
		t.Fatal("approved a device the host does not list")
	}
	c := newHost(t, "chymaera", gpu)
	c.device(gpu, "0x030000", false, gpu)
	denied2 := func() error { _, err := c.p.Approve([]string{gpu}, time.Hour, "me"); return err }()
	denied(t, denied2)
	if c.p.Approval() != nil {
		t.Fatal("an approval exists on Chymaera")
	}
}

func TestBusyDeviceBlocksApprovalAndReady(t *testing.T) {
	h := ready(t)
	h.open["firefox (4242)"] = []string{"/dev/dri/renderD129"}
	h.open["bash (1)"] = []string{"/dev/pts/0"}
	var busy *Busy
	if err := h.p.CanApprove([]string{gpu}); !errors.As(err, &busy) || len(busy.Who) != 1 || busy.Who[0] != "firefox (4242)" {
		t.Fatalf("want Busy naming firefox, got %v", err)
	}
	// Approved earlier, then an app grabbed the card: still refused at run time.
	h.open = map[string][]string{}
	if _, err := h.p.Approve([]string{gpu}, time.Hour, "me"); err != nil {
		t.Fatal(err)
	}
	h.open["steam (7)"] = []string{"/dev/nvidia0"}
	if err := h.p.Ready(guest(gpu)); !errors.As(err, &busy) {
		t.Fatalf("a process on /dev/nvidia0 must make the NVIDIA card busy, got %v", err)
	}
}

func TestAfterDetectsDeviceNotReturned(t *testing.T) {
	h := ready(t)
	before := h.p.Before(guest(gpu))
	if err := h.p.After(guest(gpu), before); err != nil {
		t.Fatalf("unchanged binding is fine: %v", err)
	}
	h.drv[gpu] = "vfio-pci" // libvirt could not give it back
	if err := h.p.After(guest(gpu), before); err == nil {
		t.Fatal("device left on vfio-pci not detected")
	}
	if !h.p.Blocked() {
		t.Fatal("no reboot marker was recorded")
	}
	var rb *RebootNeeded
	if err := h.p.Ready(guest(gpu)); !errors.As(err, &rb) {
		t.Fatalf("want RebootNeeded, got %v", err)
	}
	if err := h.p.Clear(); err != nil || h.p.Blocked() {
		t.Fatalf("clear failed: %v", err)
	}
}

func TestAfterWithoutRecordOnlyChecksVfio(t *testing.T) {
	h := ready(t)
	if err := h.p.After(guest(gpu), nil); err != nil {
		t.Fatalf("a normally bound device after a crash reap is fine: %v", err)
	}
	h.drv[gpu] = "vfio-pci"
	if err := h.p.After(guest(gpu), nil); err == nil {
		t.Fatal("vfio-pci after a crash reap must be flagged")
	}
}

func TestRevoke(t *testing.T) {
	h := ready(t)
	if _, err := h.p.Approve([]string{gpu}, time.Hour, "me"); err != nil {
		t.Fatal(err)
	}
	if err := h.p.Revoke(); err != nil || h.p.Approval() != nil {
		t.Fatalf("revoke failed: %v", err)
	}
}
