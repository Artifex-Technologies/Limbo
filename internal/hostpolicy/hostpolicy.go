// Package hostpolicy decides whether the machine Limbo is running on permits a
// guest to be given real hardware (PCI passthrough, and single USB devices since
// 2026-11-08), and whether now is a safe moment to do it.
//
// A profile can only ask for a device. Whether the host grants it is settled
// here, from facts a profile cannot touch: the host's own os-release, a
// root-owned config file, the device's state in sysfs, a time-limited approval a
// human gave at a terminal, and what is running on the host right now.
// Everything fails closed: an unreadable file, an unknown OS or an odd sysfs
// layout is a refusal.
//
// The switch by host OS:
//
//   - LykanOS (formerly Niflheim OS and Chymaera OS) never allows passthrough. That is
//     hard-coded, under both IDs, so no config file, however edited, turns it
//     on there.
//   - Labyrinth OS allows it, but only for devices listed in the config's
//     pci_allow (PCI addresses) or usb_allow (USB vendor:product IDs), and only
//     if the device is safe to hand over (see Check).
//   - Any other OS is refused.
//
// Beyond "may this host ever" (Check) there is "may it be done right now"
// (Ready): a human must have approved a window, nothing on the host may be using
// the device, and the previous run must have left the card in a good state
// (consent.go).
package hostpolicy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

// Host locations. Paths given to the fs.FS in Policy.Root have no leading slash.
const (
	DefaultConfig = "/etc/limbo/host-policy.json"
	configRel     = "etc/limbo/host-policy.json"
	osReleaseRel  = "etc/os-release"
	pciRel        = "sys/bus/pci/devices"
	usbRel        = "sys/bus/usb/devices"
)

// neverOS are os-release IDs on which passthrough is refused regardless of config.
// LykanOS was Niflheim OS and Chymaera OS before that; all three IDs, so a rename
// never relies on the unknown-OS default.
var neverOS = map[string]bool{"lykanos": true, "niflheim": true, "chymaera": true}

// allowOS are os-release IDs on which passthrough is possible at all.
// Labyrinth is CachyOS-based and ships its own os-release with ID=labyrinth.
var allowOS = map[string]bool{"labyrinth": true}

// Denied is a refusal that no action of the user's at a terminal will change:
// this host or this device is not eligible. Reason is a fixed sentence with no
// host paths.
type Denied struct{ Reason string }

func (d *Denied) Error() string { return "hardware passthrough denied: " + d.Reason }

func deny(format string, a ...any) error { return &Denied{Reason: fmt.Sprintf(format, a...)} }

// Config is /etc/limbo/host-policy.json: root-written, never by Limbo or an agent.
type Config struct {
	// PCIAllow lists the only PCI devices that may ever be passed through on this host.
	PCIAllow []string `json:"pci_allow"`
	// USBAllow lists the only USB devices (vendor:product, "5059:4040") that may ever be passed through on this host.
	USBAllow []string `json:"usb_allow"`
}

// Policy checks guests against the host. The zero value uses the real host.
type Policy struct {
	// Root is the filesystem the host's files are read from; default the real root.
	Root fs.FS
	// StateDir holds the approval file. Empty means no approval can exist.
	StateDir string
	// RunDir holds the reboot-needed marker; default /run/limbo, a tmpfs, so the
	// marker disappears when the host reboots, which is exactly its meaning.
	RunDir string
	// Now, OpenFiles and Driver are seams for tests; production leaves them nil.
	Now func() time.Time
	// OpenFiles maps a process label ("firefox (1234)") to the files it holds open.
	OpenFiles func() map[string][]string
	// Driver names the host driver a PCI device is bound to ("" if none).
	Driver func(addr string) string
	// USBDriver names the host driver a USB interface ("1-9:1.0") is bound to ("" if none).
	USBDriver func(iface string) string
}

func (p *Policy) root() fs.FS {
	if p.Root != nil {
		return p.Root
	}
	return os.DirFS("/")
}

func (p *Policy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// HostID returns the host's os-release ID ("" if it cannot be read).
func (p *Policy) HostID() string {
	b, err := fs.ReadFile(p.root(), osReleaseRel)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "ID="); ok {
			return strings.ToLower(strings.Trim(v, `"'`))
		}
	}
	return ""
}

// Check returns nil if the guest asks for no hardware, or if every requested
// device may ever be handed over on this host. Otherwise it returns a *Denied.
// It says nothing about whether now is a good moment: see Ready.
//
// A device is eligible only if it is listed in pci_allow, it exists, it is not
// the host's boot display (taking it would blank the host), and its IOMMU
// group holds nothing but the requested devices and PCI bridges (a group is
// passed through whole; anything else in it would go to the guest too).
func (p *Policy) Check(m *manifest.Manifest) error {
	if !m.Devices.Any() {
		return nil
	}
	root := p.root()

	id := p.HostID()
	switch {
	case neverOS[id]:
		return deny("this host (%s) does not allow hardware passthrough", id)
	case !allowOS[id]:
		return deny("this host's OS does not allow hardware passthrough")
	}

	b, err := fs.ReadFile(root, configRel)
	if err != nil {
		return deny("the host has no passthrough device list")
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return deny("the host's passthrough device list is unreadable")
	}
	allowed := map[string]bool{}
	for _, a := range cfg.PCIAllow {
		allowed[strings.ToLower(a)] = true
	}
	if err := checkUSB(root, m.Devices.USB, cfg.USBAllow); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, a := range m.Devices.PCI {
		want[a] = true
	}

	for _, a := range m.Devices.PCI {
		if !allowed[a] {
			return deny("device %s is not on the host's passthrough list", a)
		}
		dev := pciRel + "/" + a
		if _, err := fs.Stat(root, dev); err != nil {
			return deny("device %s is not present on the host", a)
		}
		if readTrim(root, dev+"/boot_vga") == "1" {
			return deny("device %s is the host's boot display", a)
		}
		members, err := fs.ReadDir(root, dev+"/iommu_group/devices")
		if err != nil || len(members) == 0 {
			return deny("device %s has no IOMMU group (is the IOMMU enabled?)", a)
		}
		for _, e := range members {
			n := e.Name()
			if want[n] || isBridge(root, pciRel+"/"+n) {
				continue
			}
			return deny("device %s shares an IOMMU group with %s, which was not requested", a, n)
		}
	}
	return nil
}

// checkUSB refuses a USB device that is not on usb_allow, is not plugged in, is plugged in more than once (which one the
// guest would get is then a guess), or is a hub (a hub would take everything plugged into it along).
func checkUSB(root fs.FS, ids, allow []string) error {
	ok := map[string]bool{}
	for _, a := range allow {
		ok[strings.ToLower(a)] = true
	}
	for _, id := range ids {
		if !ok[id] {
			return deny("USB device %s is not on the host's passthrough list", id)
		}
		devs := usbDevices(root, id)
		switch {
		case len(devs) == 0:
			return deny("USB device %s is not plugged in", id)
		case len(devs) > 1:
			return deny("%d USB devices with ID %s are plugged in; leave only the one to pass through", len(devs), id)
		case readTrim(root, usbRel+"/"+devs[0]+"/bDeviceClass") == "09":
			return deny("USB device %s is a hub", id)
		}
	}
	return nil
}

// usbDevices names the sysfs entries ("1-9") of the plugged-in USB devices with this vendor:product ID. Interfaces
// ("1-9:1.0") and root hubs' controllers are skipped by their names.
func usbDevices(root fs.FS, id string) []string {
	vendor, product, _ := strings.Cut(id, ":")
	ents, err := fs.ReadDir(root, usbRel)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.Contains(n, ":") {
			continue
		}
		dir := usbRel + "/" + n
		if strings.ToLower(readTrim(root, dir+"/idVendor")) == vendor && strings.ToLower(readTrim(root, dir+"/idProduct")) == product {
			out = append(out, n)
		}
	}
	return out
}

// isBridge reports PCI class 0x0604xx (PCI-to-PCI bridge). Bridges in a group are
// not handed to the guest, so they do not count against it.
func isBridge(root fs.FS, dev string) bool {
	return strings.HasPrefix(readTrim(root, dev+"/class"), "0x0604")
}

func readTrim(root fs.FS, p string) string {
	b, err := fs.ReadFile(root, p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
