package hostpolicy

import (
	"errors"
	"fmt"
	"strings"
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
	for _, id := range []string{"lykanos", "chymaera"} {
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

const x4 = "5059:4040"

// usbHost is newHost with a usb_allow list and USB interface drivers.
func usbHost(t *testing.T, osID string, allow ...string) (*host, map[string]string) {
	t.Helper()
	h := newHost(t, osID)
	list := `{"pci_allow":[],"usb_allow":[`
	for i, a := range allow {
		if i > 0 {
			list += ","
		}
		list += `"` + a + `"`
	}
	h.file("etc/limbo/host-policy.json", list+`]}`)
	drv := map[string]string{}
	h.p.USBDriver = func(i string) string { return drv[i] }
	return h, drv
}

// usb adds a plugged-in USB device ("1-9") with one interface ("1-9:1.0").
func (h *host) usb(dev, id, class string, bus, num int) {
	v, p, _ := strings.Cut(id, ":")
	d := "sys/bus/usb/devices/" + dev + "/"
	h.file(d+"idVendor", v+"\n")
	h.file(d+"idProduct", p+"\n")
	h.file(d+"bDeviceClass", class+"\n")
	h.file(d+"busnum", fmt.Sprintf("%d\n", bus))
	h.file(d+"devnum", fmt.Sprintf("%d\n", num))
	h.file("sys/bus/usb/devices/"+dev+":1.0/bInterfaceClass", "ff\n")
}

func usbGuest(ids ...string) *manifest.Manifest {
	return &manifest.Manifest{Name: "lab", OS: manifest.OSLinux, Disposable: true, Devices: manifest.Devices{USB: ids}}
}

func TestUSBListedDeviceAllowed(t *testing.T) {
	h, _ := usbHost(t, "labyrinth", x4)
	h.usb("1-9", x4, "00", 1, 8)
	if err := h.p.Check(usbGuest(x4)); err != nil {
		t.Fatal(err)
	}
}

func TestUSBRefusals(t *testing.T) {
	h, _ := usbHost(t, "labyrinth", x4)
	denied(t, h.p.Check(usbGuest(x4))) // listed, not plugged in
	h.usb("1-9", x4, "00", 1, 8)
	denied(t, h.p.Check(usbGuest("0403:cc4c"))) // plugged in elsewhere, not listed
	h.usb("2-1", x4, "00", 2, 3)
	denied(t, h.p.Check(usbGuest(x4))) // two of them: which one would the guest get?

	hub, _ := usbHost(t, "labyrinth", "05e3:0610")
	hub.usb("1-4", "05e3:0610", "09", 1, 2)
	denied(t, hub.p.Check(usbGuest("05e3:0610")))

	for _, id := range []string{"lykanos", "chymaera", "arch"} {
		n, _ := usbHost(t, id, x4)
		n.usb("1-9", x4, "00", 1, 8)
		denied(t, n.p.Check(usbGuest(x4)))
	}
}

func TestUSBApproveThenReady(t *testing.T) {
	h, _ := usbHost(t, "labyrinth", x4)
	h.usb("1-9", x4, "00", 1, 8)
	var na *NeedsApproval
	if err := h.p.Ready(usbGuest(x4)); !errors.As(err, &na) {
		t.Fatalf("want NeedsApproval, got %v", err)
	}
	if _, err := h.p.Approve([]string{x4}, 30*time.Minute, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := h.p.Ready(usbGuest(x4)); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(31 * time.Minute)
	if err := h.p.Ready(usbGuest(x4)); !errors.As(err, &na) {
		t.Fatalf("an expired approval still counted: %v", err)
	}
}

func TestUSBBusy(t *testing.T) {
	h, drv := usbHost(t, "labyrinth", x4)
	h.usb("1-9", x4, "00", 1, 8)
	var busy *Busy
	h.open["SCTUpdater (412)"] = []string{"/dev/bus/usb/001/008"}
	if err := h.p.CanApprove([]string{x4}); !errors.As(err, &busy) || busy.Who[0] != "SCTUpdater (412)" {
		t.Fatalf("a program holding the device's node did not count: %v", err)
	}
	delete(h.open, "SCTUpdater (412)")
	drv["1-9:1.0"] = "usb-storage"
	if err := h.p.CanApprove([]string{x4}); !errors.As(err, &busy) || busy.Who[0] != "the host's usb-storage driver" {
		t.Fatalf("a kernel driver on the interface did not count: %v", err)
	}
	drv["1-9:1.0"] = "usbfs"
	if err := h.p.CanApprove([]string{x4}); err != nil {
		t.Fatalf("usbfs (a program's claim through libusb) is not a host driver: %v", err)
	}
}

func TestUSBStandingApproval(t *testing.T) {
	h, drv := usbHost(t, "labyrinth", x4)
	h.file("etc/limbo/host-policy.json", `{"usb_allow":["5059:4040"],"usb_standing":["5059:4040","0403:cc4c","0000:03:00.0"]}`)
	h.usb("1-9", x4, "00", 1, 8)
	if err := h.p.Ready(usbGuest(x4)); err != nil {
		t.Fatalf("a standing approval did not count: %v", err)
	}
	h.now = h.now.Add(400 * 24 * time.Hour)
	if err := h.p.Ready(usbGuest(x4)); err != nil {
		t.Fatalf("a standing approval expired: %v", err)
	}
	standing, ignored := h.p.Standing()
	if strings.Join(standing, ",") != x4 || strings.Join(ignored, ",") != "0403:cc4c,0000:03:00.0" {
		t.Fatalf("standing %v, ignored %v: only USB IDs on usb_allow count", standing, ignored)
	}
	var na *NeedsApproval
	h.usb("1-4", "0403:cc4c", "00", 1, 3)
	if err := h.p.Ready(usbGuest("0403:cc4c")); !errors.As(err, &na) {
		t.Fatalf("a device standing but not on usb_allow was approved: %v", err)
	}
	if err := h.p.Ready(usbGuest(x4, "0403:cc4c")); !errors.As(err, &na) {
		t.Fatalf("one standing device approved a guest asking for another too: %v", err)
	}
	var busy *Busy
	drv["1-9:1.0"] = "usb-storage"
	if err := h.p.Ready(usbGuest(x4)); !errors.As(err, &busy) {
		t.Fatalf("a standing approval skipped the in-use check: %v", err)
	}
	delete(drv, "1-9:1.0")
	h.p.block("test")
	var rb *RebootNeeded
	if err := h.p.Ready(usbGuest(x4)); !errors.As(err, &rb) {
		t.Fatalf("a standing approval skipped the reboot-needed marker: %v", err)
	}
}

func TestStandingNeverCoversPCI(t *testing.T) {
	h := newHost(t, "labyrinth", gpu)
	h.file("etc/limbo/host-policy.json", `{"pci_allow":["`+gpu+`"],"usb_allow":[],"usb_standing":["`+gpu+`"]}`)
	h.device(gpu, "0x030000", false, gpu)
	var na *NeedsApproval
	if err := h.p.Ready(guest(gpu)); !errors.As(err, &na) {
		t.Fatalf("a PCI device got a standing approval: %v", err)
	}
}
