package hostpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

// MaxApproval caps how long one approval can last, so a forgotten one expires.
const MaxApproval = 2 * time.Hour

const (
	approvalFile = "passthrough-approval.json"
	blockedFile  = "passthrough.blocked"
	defaultRun   = "/run/limbo"
	maxWho       = 10
	// bootIDRel is the kernel's random id of this boot (a new one at every boot), read under Root.
	bootIDRel = "proc/sys/kernel/random/boot_id"
	// bootPrefix starts the state marker's first line; the boot id it was written in follows.
	bootPrefix = "boot_id "
)

// NeedsApproval means no human has approved a passthrough window (or it ran out).
// Only a person at a terminal can fix it: `limbo passthrough approve`.
type NeedsApproval struct{}

func (*NeedsApproval) Error() string { return "no passthrough approval is in effect" }

// Busy means something on the host is using the device. Who is for the operator
// (and the audit log); it is never shown to a model.
type Busy struct{ Who []string }

func (b *Busy) Error() string {
	return "the device is in use on the host by: " + strings.Join(b.Who, ", ")
}

// RebootNeeded means the last run left a device not back under its host driver.
type RebootNeeded struct{}

func (*RebootNeeded) Error() string {
	return "a passthrough device did not return to the host cleanly; reboot the host"
}

// Approval is a human's permission, for a limited time, to hand named devices to
// guests. It is written by `limbo passthrough approve` as root into the state
// directory; no socket route can create one.
type Approval struct {
	Devices []string  `json:"devices"`
	Expires time.Time `json:"expires"`
	By      string    `json:"by"`
}

func (p *Policy) approvalPath() string { return filepath.Join(p.StateDir, approvalFile) }

func (p *Policy) blockedPath() string {
	d := p.RunDir
	if d == "" {
		d = defaultRun
	}
	return filepath.Join(d, blockedFile)
}

// Approval returns the approval in effect, or nil. A file that is unreadable,
// malformed, expired or (on Linux) readable by anyone but its owner counts as none.
func (p *Policy) Approval() *Approval {
	if p.StateDir == "" {
		return nil
	}
	fi, err := os.Stat(p.approvalPath())
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	if runtime.GOOS == "linux" && fi.Mode().Perm()&0o077 != 0 {
		return nil
	}
	b, err := os.ReadFile(p.approvalPath())
	if err != nil {
		return nil
	}
	var a Approval
	if json.Unmarshal(b, &a) != nil || !p.now().Before(a.Expires) {
		return nil
	}
	return &a
}

// CanApprove says whether an approval for devs could be granted right now: the
// devices are eligible on this host (Check) and nothing on the host is using them.
// It writes nothing, so a person can be shown the result before deciding.
func (p *Policy) CanApprove(devs []string) error {
	if len(devs) == 0 {
		return errors.New("hostpolicy: no devices named")
	}
	if p.Blocked() {
		return &RebootNeeded{}
	}
	d := split(devs)
	if err := p.Check(&manifest.Manifest{Devices: d}); err != nil {
		return err
	}
	if who := p.busy(d); len(who) > 0 {
		return &Busy{Who: who}
	}
	return nil
}

// split sorts named devices into PCI addresses and USB IDs by their form (a USB ID is vendor:product, "5059:4040").
func split(devs []string) manifest.Devices {
	var d manifest.Devices
	for _, x := range devs {
		if manifest.USBRe.MatchString(x) {
			d.USB = append(d.USB, x)
		} else {
			d.PCI = append(d.PCI, x)
		}
	}
	return d
}

// Approve records a human's approval of devs for d, after the same checks as
// CanApprove, so an approval is never granted for a moment that would be unsafe.
func (p *Policy) Approve(devs []string, d time.Duration, by string) (*Approval, error) {
	if p.StateDir == "" {
		return nil, errors.New("hostpolicy: no state directory")
	}
	if d <= 0 || d > MaxApproval {
		return nil, fmt.Errorf("hostpolicy: an approval lasts between 1 minute and %s", MaxApproval)
	}
	if err := p.CanApprove(devs); err != nil {
		return nil, err
	}
	a := &Approval{Devices: append([]string(nil), devs...), Expires: p.now().Add(d).UTC(), By: by}
	b, _ := json.Marshal(a)
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return nil, err
	}
	tmp := p.approvalPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return nil, err
	}
	return a, os.Rename(tmp, p.approvalPath())
}

// Revoke ends any approval now.
func (p *Policy) Revoke() error {
	if p.StateDir == "" {
		return nil
	}
	if err := os.Remove(p.approvalPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Blocked reports whether a previous run left a device in a bad state and the host has not rebooted since.
//
// There are two markers. The one that counts is in the state folder (persistent, root-only): it names the boot it was
// written in, so it survives any restart of the daemon (systemd empties /run/limbo at every stop, a package upgrade
// restarts it) and stops counting only once the kernel's boot id differs, which takes a reboot. It counts unless that
// is proven: a marker that cannot be read, is damaged or names no boot, or a boot id this host cannot tell, all count
// (`limbo passthrough clear` after recovering the device by hand). The one in the run folder (tmpfs) is written too,
// for a state folder that cannot be written, and counts while it is there.
func (p *Policy) Blocked() bool {
	return present(p.blockedPath()) || p.stateBlocked()
}

// present: something is at path, or it cannot be told that nothing is (anything but "does not exist" counts).
func present(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

func (p *Policy) stateBlockedPath() string { return filepath.Join(p.StateDir, blockedFile) }

// stateBlocked: the state folder's marker is there and not proven to be from an earlier boot.
func (p *Policy) stateBlocked() bool {
	if p.StateDir == "" || !present(p.stateBlockedPath()) {
		return false
	}
	b, err := os.ReadFile(p.stateBlockedPath())
	if err != nil {
		return true
	}
	line, _, _ := strings.Cut(string(b), "\n")
	then, ok := strings.CutPrefix(line, bootPrefix)
	now := p.bootID()
	return !ok || !isBootID(then) || !isBootID(now) || then == now
}

// bootID is this boot's id as the kernel gives it ("" if unreadable).
func (p *Policy) bootID() string { return readTrim(p.root(), bootIDRel) }

// isBootID: the form the kernel writes a boot id in, a lower-case UUID (8-4-4-4-12 hex digits).
func isBootID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// Clear removes the reboot-needed markers (both). A reboot makes them count no more by itself; this is for an
// operator who has recovered the device by hand. Both are tried; the first failure is returned.
func (p *Policy) Clear() error {
	var first error
	if p.StateDir != "" {
		if err := os.Remove(p.stateBlockedPath()); err != nil && !os.IsNotExist(err) {
			first = err
		}
	}
	if err := os.Remove(p.blockedPath()); err != nil && !os.IsNotExist(err) && first == nil {
		first = err
	}
	return first
}

// block records that a device did not come back: the state folder's marker with this boot's id ("unknown" when it
// cannot be read: such a marker counts until cleared by hand), then the run folder's.
func (p *Policy) block(why string) {
	if p.StateDir != "" && os.MkdirAll(p.StateDir, 0o700) == nil {
		id := p.bootID()
		if !isBootID(id) {
			id = "unknown"
		}
		_ = os.WriteFile(p.stateBlockedPath(), []byte(bootPrefix+id+"\n"+why+"\n"), 0o600)
	}
	if os.MkdirAll(filepath.Dir(p.blockedPath()), 0o755) == nil {
		_ = os.WriteFile(p.blockedPath(), []byte(why+"\n"), 0o600)
	}
}

// Ready says whether handing the guest its devices right now is safe: no earlier
// run left a device in a bad state, a human approved this window (or, for a USB
// device, gave it a standing approval in the host policy: Standing), and nothing on
// the host is using the devices. It returns *RebootNeeded, *NeedsApproval or
// *Busy. A guest that asks for nothing is always ready.
func (p *Policy) Ready(m *manifest.Manifest) error {
	if !m.Devices.Any() {
		return nil
	}
	if p.Blocked() {
		return &RebootNeeded{}
	}
	have := map[string]bool{}
	if a := p.Approval(); a != nil {
		for _, d := range a.Devices {
			have[d] = true
		}
	}
	standing, _ := p.Standing()
	for _, d := range standing {
		have[d] = true
	}
	for _, d := range m.Devices.All() {
		if !have[d] {
			return &NeedsApproval{}
		}
	}
	if who := p.busy(m.Devices); len(who) > 0 {
		return &Busy{Who: who}
	}
	return nil
}

// busy lists host processes holding open a device node that belongs to one of the
// devices: its DRM nodes, the NVIDIA control nodes for an NVIDIA card, the sound
// card on an audio function, and a USB device's own node (/dev/bus/usb/BBB/DDD).
// Detaching a device from under such a process kills or wedges it, which is why a
// person is asked to close things first. A USB device whose interface a host
// kernel driver holds (a USB stick's storage driver, say) counts as busy too: the
// guest taking it would pull it from under that driver.
func (p *Policy) busy(d manifest.Devices) []string {
	root := p.root()
	exact := map[string]bool{}
	var prefix []string
	var who []string
	for _, id := range d.USB {
		for _, dev := range usbDevices(root, id) {
			dir := usbRel + "/" + dev
			bus, _ := strconv.Atoi(readTrim(root, dir+"/busnum"))
			num, _ := strconv.Atoi(readTrim(root, dir+"/devnum"))
			exact[fmt.Sprintf("/dev/bus/usb/%03d/%03d", bus, num)] = true
			ents, _ := fs.ReadDir(root, usbRel)
			for _, e := range ents {
				if !strings.HasPrefix(e.Name(), dev+":") {
					continue
				}
				if drv := p.usbDriver(e.Name()); drv != "" && drv != "usbfs" {
					who = append(who, "the host's "+drv+" driver")
				}
			}
		}
	}
	for _, a := range d.PCI {
		dev := pciRel + "/" + a
		if ents, err := fs.ReadDir(root, dev+"/drm"); err == nil {
			for _, e := range ents {
				exact["/dev/dri/"+e.Name()] = true
			}
		}
		if ents, err := fs.ReadDir(root, dev+"/sound"); err == nil {
			for _, e := range ents {
				if n, ok := strings.CutPrefix(e.Name(), "card"); ok {
					prefix = append(prefix, "/dev/snd/controlC"+n, "/dev/snd/pcmC"+n+"D")
				}
			}
		}
		if readTrim(root, dev+"/vendor") == "0x10de" {
			prefix = append(prefix, "/dev/nvidia")
		}
	}
	open := p.OpenFiles
	if open == nil {
		open = scanProc
	}
	for label, files := range open() {
		for _, f := range files {
			hit := exact[f]
			for _, pre := range prefix {
				hit = hit || strings.HasPrefix(f, pre)
			}
			if hit {
				who = append(who, label)
				break
			}
		}
	}
	sort.Strings(who)
	if len(who) > maxWho {
		who = append(who[:maxWho], fmt.Sprintf("and %d more", len(who)-maxWho))
	}
	return who
}

// scanProc lists, for every process this one may inspect, the files it holds open.
// Limbo serve runs as root, so that is every process.
func scanProc() map[string][]string {
	out := map[string][]string{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + pid + "/fd")
		if err != nil {
			continue
		}
		var files []string
		for _, fd := range fds {
			if t, err := os.Readlink("/proc/" + pid + "/fd/" + fd.Name()); err == nil {
				files = append(files, t)
			}
		}
		if len(files) == 0 {
			continue
		}
		comm, _ := os.ReadFile("/proc/" + pid + "/comm")
		out[strings.TrimSpace(string(comm))+" ("+pid+")"] = files
	}
	return out
}

// usbDriver names the host driver bound to a USB interface ("1-9:1.0"), "" if none.
func (p *Policy) usbDriver(iface string) string {
	if p.USBDriver != nil {
		return p.USBDriver(iface)
	}
	t, err := os.Readlink("/sys/bus/usb/devices/" + iface + "/driver")
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

func (p *Policy) driver(addr string) string {
	if p.Driver != nil {
		return p.Driver(addr)
	}
	t, err := os.Readlink("/sys/bus/pci/devices/" + addr + "/driver")
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// Before records which host driver each requested device is bound to, to compare
// against once the guest is gone.
func (p *Policy) Before(m *manifest.Manifest) map[string]string {
	out := map[string]string{}
	for _, a := range m.Devices.PCI {
		out[a] = p.driver(a)
	}
	return out
}

// After checks, once the guest is gone, that every device is back under the
// driver it had before. If one is not (libvirt could not hand it back, or the card
// did not reset), it records that a reboot is needed so no further run takes the
// device, and returns the reason. before may be nil (a guest left by a crash): the
// check is then only that the device is no longer held by vfio-pci.
func (p *Policy) After(m *manifest.Manifest, before map[string]string) error {
	for _, a := range m.Devices.PCI {
		now := p.driver(a)
		want, known := before[a]
		if (known && now != want) || (!known && now == "vfio-pci") {
			why := fmt.Sprintf("device %s is bound to %q after teardown", a, now)
			p.block(why)
			return errors.New(why)
		}
	}
	return nil
}
