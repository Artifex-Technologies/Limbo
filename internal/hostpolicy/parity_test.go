package hostpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/parity"
)

// PolicyScenario is one fake host for the Rust port (docs/RUST_PORT.md): its files (sysfs, os-release, the host
// policy, the boot id; paths without a leading slash), the approval file, the reboot markers (Blocked: written by
// block; Marker and RunMarker: written as they are, by hand or by an older build), the processes' open files and the
// drivers, and the questions asked of it in order. The Rust test makes the files a real folder and asks the same.
type PolicyScenario struct {
	Name      string              `json:"name"`
	Files     map[string]string   `json:"files"`
	Approval  *ApprovalFile       `json:"approval"`
	Blocked   bool                `json:"blocked"`
	Marker    *string             `json:"marker"`
	RunMarker *string             `json:"run_marker"`
	Now       string              `json:"now"`
	Open      map[string][]string `json:"open"`
	Drv       map[string]string   `json:"drv"`
	USBDrv    map[string]string   `json:"usb_drv"`
	Steps     []PolicyStep        `json:"steps"`
}

// ApprovalFile is the approval file as written: its bytes and mode.
type ApprovalFile struct {
	Body string `json:"body"`
	Mode int    `json:"mode"`
}

// PolicyStep is one question: check, ready, standing, host_id or after (Before with Drv, then the drivers become
// DrvAfter, then After with that record, or with none when NoRecord). Advance moves the clock first. Or an event:
// restart (the daemon starts again: a new Policy on the same folders, the run folder emptied as systemd does at every
// stop), reboot (the same, the drivers back to Drv and the host's boot id BootID; "-" leaves none), clear (Clear).
type PolicyStep struct {
	Op       string            `json:"op"`
	PCI      []string          `json:"pci"`
	USB      []string          `json:"usb"`
	Advance  int64             `json:"advance_seconds"`
	DrvAfter map[string]string `json:"drv_after"`
	NoRecord bool              `json:"no_record"`
	BootID   string            `json:"boot_id"`
}

// The boot ids of the fake hosts: every host starts in bootA.
const (
	bootA = "6f1c0a52-3c1e-4b8e-9d0a-2b7f4e5c8a11"
	bootB = "0b9e7d24-81f3-4c55-a6e2-93d1c4f7b260"
	bootC = "d3a8f6e1-5b2c-47d9-8e10-4f6a9c2b7e35"
)

// markerText is a marker file's bytes, or "<none>".
func markerText(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "<none>"
		}
		return "<unreadable>"
	}
	return string(b)
}

func refusalKind(err error) string {
	var (
		d  *Denied
		na *NeedsApproval
		bu *Busy
		rb *RebootNeeded
	)
	switch {
	case err == nil:
		return ""
	case errors.As(err, &d):
		return "denied"
	case errors.As(err, &na):
		return "needs_approval"
	case errors.As(err, &bu):
		return "busy"
	case errors.As(err, &rb):
		return "reboot"
	}
	return "other"
}

// runPolicyScenario asks a fake host the scenario's questions, as the Rust test will.
func runPolicyScenario(t *testing.T, sc PolicyScenario) []map[string]any {
	fsys := fstest.MapFS{}
	for p, b := range sc.Files {
		fsys[p] = &fstest.MapFile{Data: []byte(b)}
	}
	now, err := time.Parse(time.RFC3339Nano, sc.Now)
	if err != nil {
		t.Fatal(err)
	}
	drv := map[string]string{}
	for k, v := range sc.Drv {
		drv[k] = v
	}
	state, run := t.TempDir(), t.TempDir()
	start := func() *Policy {
		return &Policy{
			Root: fsys, StateDir: state, RunDir: run,
			Now:       func() time.Time { return now },
			OpenFiles: func() map[string][]string { return sc.Open },
			Driver:    func(a string) string { return drv[a] },
			USBDriver: func(i string) string { return sc.USBDrv[i] },
		}
	}
	p := start()
	if sc.Approval != nil {
		path := filepath.Join(p.StateDir, approvalFile)
		if err := os.WriteFile(path, []byte(sc.Approval.Body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, os.FileMode(sc.Approval.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	if sc.Blocked {
		p.block("earlier run")
	}
	for path, body := range map[string]*string{filepath.Join(state, blockedFile): sc.Marker, filepath.Join(run, blockedFile): sc.RunMarker} {
		if body != nil {
			if err := os.WriteFile(path, []byte(*body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	var out []map[string]any
	for _, st := range sc.Steps {
		now = now.Add(time.Duration(st.Advance) * time.Second)
		m := &manifest.Manifest{Name: "lab", OS: manifest.OSLinux, Disposable: true, Devices: manifest.Devices{PCI: st.PCI, USB: st.USB}}
		r := map[string]any{}
		switch st.Op {
		case "check":
			err := p.Check(m)
			r["kind"], r["err"] = refusalKind(err), parity.Err(err)
		case "ready":
			err := p.Ready(m)
			r["kind"], r["err"] = refusalKind(err), parity.Err(err)
		case "standing":
			s, i := p.Standing()
			r["standing"], r["ignored"] = strings.Join(s, ","), strings.Join(i, ",")
		case "host_id":
			r["id"] = p.HostID()
		case "after":
			before := p.Before(m)
			b, _ := json.Marshal(before)
			r["before"] = string(b)
			drv = map[string]string{}
			for k, v := range st.DrvAfter {
				drv[k] = v
			}
			if st.NoRecord {
				before = nil
			}
			r["err"] = parity.Err(p.After(m, before))
		case "restart", "reboot":
			if err := os.RemoveAll(run); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(run, 0o755); err != nil {
				t.Fatal(err)
			}
			if st.Op == "reboot" { // every device is back under the driver it boots with, and the boot id is new
				drv = map[string]string{}
				for k, v := range sc.Drv {
					drv[k] = v
				}
				delete(fsys, bootIDRel)
				if st.BootID != "-" {
					fsys[bootIDRel] = &fstest.MapFile{Data: []byte(st.BootID + "\n")}
				}
			}
			p = start()
		case "clear":
			r["err"] = parity.Err(p.Clear())
		}
		r["blocked"] = p.Blocked()
		r["marker"] = markerText(filepath.Join(state, blockedFile))
		r["run_marker"] = markerText(filepath.Join(run, blockedFile))
		out = append(out, r)
	}
	return out
}

const pGPU, pAudio, pNIC, pBridge = "0000:03:00.0", "0000:03:00.1", "0000:04:00.0", "0000:02:00.0"

// policyScenarios: every case of this package's tests, then generated hosts.
func policyScenarios() []PolicyScenario {
	base := func(name, osID, config string) PolicyScenario {
		f := map[string]string{"etc/limbo/host-policy.json": config, bootIDRel: bootA + "\n"}
		if osID != "-" {
			f["etc/os-release"] = "NAME=x\nID=" + osID + "\n"
		}
		return PolicyScenario{Name: name, Files: f, Now: "2026-10-10T12:00:00Z", Open: map[string][]string{}, Drv: map[string]string{}, USBDrv: map[string]string{}}
	}
	dev := func(sc *PolicyScenario, addr, class string, bootVGA bool, members ...string) {
		d := "sys/bus/pci/devices/" + addr + "/"
		sc.Files[d+"class"] = class + "\n"
		if bootVGA {
			sc.Files[d+"boot_vga"] = "1\n"
		}
		for _, m := range members {
			sc.Files[d+"iommu_group/devices/"+m] = ""
		}
	}
	usb := func(sc *PolicyScenario, d, id, class string, bus, num int) {
		v, pr, _ := strings.Cut(id, ":")
		p := "sys/bus/usb/devices/" + d + "/"
		sc.Files[p+"idVendor"] = v + "\n"
		sc.Files[p+"idProduct"] = pr + "\n"
		sc.Files[p+"bDeviceClass"] = class + "\n"
		sc.Files[p+"busnum"] = fmt.Sprintf("%d\n", bus)
		sc.Files[p+"devnum"] = fmt.Sprintf("%d\n", num)
		sc.Files["sys/bus/usb/devices/"+d+":1.0/bInterfaceClass"] = "ff\n"
	}
	approval := func(devs []string, expires string, mode int) *ApprovalFile {
		b, _ := json.Marshal(map[string]any{"devices": devs, "expires": expires, "by": "me"})
		return &ApprovalFile{Body: string(b), Mode: mode}
	}
	pci := func(a ...string) PolicyStep { return PolicyStep{Op: "check", PCI: a} }
	rdy := func(a ...string) PolicyStep { return PolicyStep{Op: "ready", PCI: a} }
	allow := func(a ...string) string {
		b, _ := json.Marshal(map[string]any{"pci_allow": a})
		return string(b)
	}
	var out []PolicyScenario

	// TestNoDevicesAlwaysPasses, TestChymaeraNeverAllowsEvenWhenListed, TestUnknownOrUnreadableOSDenies
	sc := base("no devices", "chymaera", allow())
	sc.Steps = []PolicyStep{pci(), rdy(), {Op: "host_id"}}
	out = append(out, sc)
	for _, id := range []string{"lykanos", "chymaera", "debian", "-", `"labyrinth"`, "'Labyrinth'", "", "labyrinthos"} {
		sc := base("os "+id, id, allow(pGPU))
		dev(&sc, pGPU, "0x030000", false, pGPU)
		sc.Steps = []PolicyStep{pci(pGPU), {Op: "host_id"}}
		out = append(out, sc)
	}
	// TestLabyrinthAllowsListedDevice, TestBridgeInGroupIsIgnored
	sc = base("listed pair", `"labyrinth"`, allow(pGPU, pAudio))
	dev(&sc, pGPU, "0x030000", false, pGPU, pAudio)
	dev(&sc, pAudio, "0x040300", false, pGPU, pAudio)
	sc.Steps = []PolicyStep{pci(pGPU, pAudio), pci(pGPU), pci(pAudio), pci(pAudio, pGPU)}
	out = append(out, sc)
	sc = base("bridge in group", "labyrinth", allow(pGPU))
	dev(&sc, pGPU, "0x030000", false, pGPU, pBridge)
	dev(&sc, pBridge, "0x060400", false)
	sc.Steps = []PolicyStep{pci(pGPU)}
	out = append(out, sc)
	// TestLabyrinthRefusals
	for name, cfg := range map[string]string{"not on the list": `{"pci_allow":[]}`, "no config file": "-", "malformed config": "{", "wrong type": `{"pci_allow":"x"}`, "upper-case list": allow(strings.ToUpper(pGPU))} {
		sc := base(name, "labyrinth", cfg)
		if cfg == "-" {
			delete(sc.Files, "etc/limbo/host-policy.json")
		}
		dev(&sc, pGPU, "0x030000", false, pGPU)
		sc.Steps = []PolicyStep{pci(pGPU)}
		out = append(out, sc)
	}
	for name, f := range map[string]func(*PolicyScenario){
		"not present":    func(*PolicyScenario) {},
		"boot display":   func(s *PolicyScenario) { dev(s, pGPU, "0x030000", true, pGPU) },
		"no iommu group": func(s *PolicyScenario) { dev(s, pGPU, "0x030000", false) },
		"unrequested member": func(s *PolicyScenario) {
			dev(s, pGPU, "0x030000", false, pGPU, pAudio)
			dev(s, pAudio, "0x040300", false, pGPU, pAudio)
		},
	} {
		sc := base(name, "labyrinth", allow(pGPU))
		f(&sc)
		sc.Steps = []PolicyStep{pci(pGPU)}
		out = append(out, sc)
	}
	// ready(): TestReadyNeedsApproval ... TestRevoke, as approval files
	ready := func(name string) PolicyScenario {
		sc := base(name, "labyrinth", allow(pGPU, pNIC))
		dev(&sc, pGPU, "0x030000", false, pGPU)
		dev(&sc, pNIC, "0x020000", false, pNIC)
		sc.Files["sys/bus/pci/devices/"+pGPU+"/vendor"] = "0x10de\n"
		sc.Files["sys/bus/pci/devices/"+pGPU+"/drm/renderD129"] = ""
		sc.Files["sys/bus/pci/devices/"+pGPU+"/sound/card1"] = ""
		sc.Drv[pGPU] = "nvidia"
		return sc
	}
	sc = ready("needs approval")
	sc.Steps = []PolicyStep{rdy(pGPU), pci(pGPU)}
	out = append(out, sc)
	sc = ready("approved then expires")
	sc.Approval = approval([]string{pGPU}, "2026-10-10T12:30:00Z", 0o600)
	sc.Steps = []PolicyStep{rdy(pGPU), rdy(pGPU, pNIC), {Op: "ready", PCI: []string{pGPU}, Advance: 1799}, {Op: "ready", PCI: []string{pGPU}, Advance: 1}}
	out = append(out, sc)
	for name, a := range map[string]*ApprovalFile{
		"approval readable by others": approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o644),
		"approval group-writable":     approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o620),
		"approval malformed":          {Body: `{"devices":["` + pGPU + `"],"expires":`, Mode: 0o600},
		"approval bad time":           {Body: `{"devices":["` + pGPU + `"],"expires":"tomorrow"}`, Mode: 0o600},
		"approval with nanoseconds":   approval([]string{pGPU}, "2026-10-10T12:00:00.000000001Z", 0o600),
		"approval at the second":      approval([]string{pGPU}, "2026-10-10T12:00:00Z", 0o600),
		"approval in an offset":       approval([]string{pGPU, pNIC}, "2026-10-10T14:00:00+02:00", 0o600),
		"approval no devices":         {Body: `{"expires":"2027-01-01T00:00:00Z"}`, Mode: 0o600},
	} {
		sc := ready(name)
		sc.Approval = a
		sc.Steps = []PolicyStep{rdy(pGPU), rdy(pNIC), rdy(pGPU, pNIC)}
		out = append(out, sc)
	}
	// TestBusyDeviceBlocksApprovalAndReady
	for i, open := range []map[string][]string{
		{"firefox (4242)": {"/dev/dri/renderD129"}, "bash (1)": {"/dev/pts/0"}},
		{"steam (7)": {"/dev/nvidia0"}},
		{"pipewire (9)": {"/dev/snd/pcmC1D0p"}, "wireplumber (10)": {"/dev/snd/controlC1"}, "x (11)": {"/dev/snd/pcmC10D0p"}},
		{"a (1)": {"/dev/nvidiactl"}, "b (2)": {"/dev/nvidia-uvm"}, "c (3)": {"/dev/nvidia1"}, "d (4)": {"/dev/nvidia2"}, "e (5)": {"/dev/nvidia3"}, "f (6)": {"/dev/nvidia4"},
			"g (7)": {"/dev/nvidia5"}, "h (8)": {"/dev/nvidia6"}, "i (9)": {"/dev/nvidia7"}, "j (10)": {"/dev/nvidia8"}, "k (11)": {"/dev/nvidia9"}, "l (12)": {"/dev/dri/renderD129"}},
	} {
		sc := ready(fmt.Sprintf("busy %d", i))
		sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
		sc.Open = open
		sc.Steps = []PolicyStep{rdy(pGPU)}
		out = append(out, sc)
	}
	// TestAfterDetectsDeviceNotReturned, TestAfterWithoutRecordOnlyChecksVfio
	sc = ready("after")
	sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
	sc.Steps = []PolicyStep{
		{Op: "after", PCI: []string{pGPU}, DrvAfter: map[string]string{pGPU: "nvidia"}},
		{Op: "after", PCI: []string{pGPU}, DrvAfter: map[string]string{pGPU: "nvidia"}, NoRecord: true},
		rdy(pGPU),
		{Op: "after", PCI: []string{pGPU}, DrvAfter: map[string]string{pGPU: "vfio-pci"}, NoRecord: true},
		rdy(pGPU),
	}
	out = append(out, sc)
	sc = ready("after changed")
	sc.Steps = []PolicyStep{{Op: "after", PCI: []string{pGPU}, DrvAfter: map[string]string{pGPU: "vfio-pci"}}, rdy(pGPU), pci(pGPU)}
	out = append(out, sc)
	sc = ready("after unbound")
	sc.Steps = []PolicyStep{{Op: "after", PCI: []string{pGPU, pNIC}, DrvAfter: map[string]string{pGPU: "nvidia", pNIC: "x\"y"}}}
	out = append(out, sc)
	sc = ready("blocked before")
	sc.Blocked = true
	sc.Steps = []PolicyStep{rdy(pGPU), rdy(), pci(pGPU)}
	out = append(out, sc)

	// The marker outlasts a restart of the daemon (systemd empties /run/limbo at every stop) and ends with a reboot.
	stuck := PolicyStep{Op: "after", PCI: []string{pGPU}, DrvAfter: map[string]string{pGPU: "vfio-pci"}}
	restart := PolicyStep{Op: "restart"}
	reboot := func(id string) PolicyStep { return PolicyStep{Op: "reboot", BootID: id} }
	sc = ready("restart keeps the block")
	sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
	sc.Steps = []PolicyStep{rdy(pGPU), stuck, rdy(pGPU), restart, rdy(pGPU), restart, rdy(pGPU), pci(pGPU)}
	out = append(out, sc)
	sc = ready("reboot ends the block")
	sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
	sc.Steps = []PolicyStep{stuck, restart, rdy(pGPU), reboot(bootB), rdy(pGPU), stuck, rdy(pGPU), restart, rdy(pGPU), reboot(bootC), rdy(pGPU)}
	out = append(out, sc)
	sc = ready("reboot without a boot id")
	sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
	sc.Steps = []PolicyStep{stuck, reboot("-"), rdy(pGPU), reboot("not a boot id"), rdy(pGPU), reboot(bootB), rdy(pGPU)}
	out = append(out, sc)
	sc = ready("block without a boot id")
	delete(sc.Files, bootIDRel)
	sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
	sc.Steps = []PolicyStep{stuck, rdy(pGPU), reboot(bootB), rdy(pGPU), restart, rdy(pGPU), {Op: "clear"}, rdy(pGPU)}
	out = append(out, sc)
	sc = ready("block twice")
	sc.Blocked = true
	sc.Steps = []PolicyStep{stuck, reboot(bootB), stuck, restart, rdy(pGPU)}
	out = append(out, sc)
	sc = ready("clear removes both")
	sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
	sc.Steps = []PolicyStep{stuck, {Op: "clear"}, rdy(pGPU), restart, rdy(pGPU), {Op: "clear"}, rdy(pGPU)}
	out = append(out, sc)
	sc = ready("old marker in the run folder")
	sc.RunMarker = new(string)
	*sc.RunMarker = "earlier run\n"
	sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
	sc.Steps = []PolicyStep{rdy(pGPU), restart, rdy(pGPU)}
	out = append(out, sc)
	for i, m := range []string{
		"boot_id " + bootA + "\nwhy\n", "boot_id " + bootB + "\nwhy\n", "boot_id " + bootB, "boot_id " + bootA,
		"", "earlier run\n", "boot_id \n", "boot_id unknown\nwhy\n", "boot_id " + bootB[:35] + "\n",
		"boot_id " + strings.ToUpper(bootB) + "\n", "boot_id  " + bootB + "\n", "boot_id " + bootB + "\r\n",
		"boot_id " + bootB + " \n", " boot_id " + bootB + "\n", "BOOT_ID " + bootB + "\n", "boot_id " + bootB + "x\n",
		"boot_id " + strings.Replace(bootB, "-", "_", 1) + "\n", "boot_id " + bootB[:8] + "g" + bootB[9:] + "\n",
		"\nboot_id " + bootB + "\n", "boot_id " + bootB + "\x00\n", "boot_id " + bootB + "\nboot_id " + bootA + "\n",
	} {
		sc := ready(fmt.Sprintf("marker %d", i))
		sc.Marker = &m
		sc.Approval = approval([]string{pGPU}, "2026-10-10T13:00:00Z", 0o600)
		sc.Steps = []PolicyStep{rdy(pGPU), restart, rdy(pGPU), reboot(bootC), rdy(pGPU), {Op: "clear"}, rdy(pGPU)}
		out = append(out, sc)
	}
	for i, id := range []string{"", bootA, strings.ToUpper(bootA), bootA[:35], " " + bootA + " \n\n", bootA + bootA, "\u0085" + bootA + "\u00a0"} {
		sc := ready(fmt.Sprintf("host boot id %d", i))
		sc.Files[bootIDRel] = id
		sc.Marker = new(string)
		*sc.Marker = "boot_id " + bootB + "\nwhy\n"
		sc.Steps = []PolicyStep{rdy(pGPU), stuck, reboot(bootC), rdy(pGPU)}
		out = append(out, sc)
	}

	// USB: TestUSBListedDeviceAllowed ... TestStandingNeverCoversPCI
	const x4 = "5059:4040"
	usbAllow := func(allow, standing []string) string {
		m := map[string]any{"pci_allow": []string{}, "usb_allow": allow}
		if standing != nil {
			m["usb_standing"] = standing
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	u := func(op string, ids ...string) PolicyStep { return PolicyStep{Op: op, USB: ids} }
	sc = base("usb listed", "labyrinth", usbAllow([]string{x4}, nil))
	sc.Steps = []PolicyStep{u("check", x4)}
	usb(&sc, "1-9", x4, "00", 1, 8)
	sc.Steps = append(sc.Steps, u("check", x4), u("check", "0403:cc4c"), u("ready", x4))
	out = append(out, sc)
	sc = base("usb not plugged in", "labyrinth", usbAllow([]string{x4}, nil))
	sc.Steps = []PolicyStep{u("check", x4)}
	out = append(out, sc)
	sc = base("usb twice", "labyrinth", usbAllow([]string{x4}, nil))
	usb(&sc, "1-9", x4, "00", 1, 8)
	usb(&sc, "2-1", x4, "00", 2, 3)
	sc.Steps = []PolicyStep{u("check", x4)}
	out = append(out, sc)
	sc = base("usb hub", "labyrinth", usbAllow([]string{"05e3:0610"}, nil))
	usb(&sc, "1-4", "05e3:0610", "09", 1, 2)
	sc.Steps = []PolicyStep{u("check", "05e3:0610")}
	out = append(out, sc)
	sc = base("usb upper-case sysfs", "labyrinth", usbAllow([]string{"0403:CC4C"}, nil))
	usb(&sc, "1-4", "0403:CC4C", "00", 1, 2)
	sc.Steps = []PolicyStep{u("check", "0403:cc4c")}
	out = append(out, sc)
	for _, id := range []string{"lykanos", "chymaera", "arch"} {
		sc := base("usb on "+id, id, usbAllow([]string{x4}, nil))
		usb(&sc, "1-9", x4, "00", 1, 8)
		sc.Steps = []PolicyStep{u("check", x4)}
		out = append(out, sc)
	}
	sc = base("usb approve then ready", "labyrinth", usbAllow([]string{x4}, nil))
	usb(&sc, "1-9", x4, "00", 1, 8)
	sc.Approval = approval([]string{x4}, "2026-10-10T12:30:00Z", 0o600)
	sc.Steps = []PolicyStep{u("ready", x4), {Op: "ready", USB: []string{x4}, Advance: 31 * 60}}
	out = append(out, sc)
	for i, c := range []struct {
		open map[string][]string
		drv  map[string]string
	}{
		{map[string][]string{"SCTUpdater (412)": {"/dev/bus/usb/001/008"}}, nil},
		{nil, map[string]string{"1-9:1.0": "usb-storage"}},
		{nil, map[string]string{"1-9:1.0": "usbfs"}},
		{map[string][]string{"x (1)": {"/dev/bus/usb/001/0080"}}, map[string]string{"1-9:1.0": "cdc_acm", "1-90:1.0": "other"}},
	} {
		sc := base(fmt.Sprintf("usb busy %d", i), "labyrinth", usbAllow([]string{x4}, nil))
		usb(&sc, "1-9", x4, "00", 1, 8)
		usb(&sc, "1-90", "1234:5678", "00", 1, 80)
		sc.Approval = approval([]string{x4}, "2026-10-10T13:00:00Z", 0o600)
		if c.open != nil {
			sc.Open = c.open
		}
		if c.drv != nil {
			sc.USBDrv = c.drv
		}
		sc.Steps = []PolicyStep{u("ready", x4)}
		out = append(out, sc)
	}
	sc = base("usb standing", "labyrinth", `{"usb_allow":["5059:4040"],"usb_standing":["5059:4040","0403:cc4c","0000:03:00.0","5059:4040 ","5059:4040"]}`)
	usb(&sc, "1-9", x4, "00", 1, 8)
	usb(&sc, "1-4", "0403:cc4c", "00", 1, 3)
	sc.Steps = []PolicyStep{u("ready", x4), {Op: "ready", USB: []string{x4}, Advance: 400 * 24 * 3600}, {Op: "standing"}, u("ready", "0403:cc4c"), u("ready", x4, "0403:cc4c")}
	out = append(out, sc)
	sc = base("usb standing busy", "labyrinth", `{"usb_allow":["5059:4040"],"usb_standing":["5059:4040"]}`)
	usb(&sc, "1-9", x4, "00", 1, 8)
	sc.USBDrv = map[string]string{"1-9:1.0": "usb-storage"}
	sc.Steps = []PolicyStep{u("ready", x4)}
	out = append(out, sc)
	sc = base("usb standing blocked", "labyrinth", `{"usb_allow":["5059:4040"],"usb_standing":["5059:4040"]}`)
	usb(&sc, "1-9", x4, "00", 1, 8)
	sc.Blocked = true
	sc.Steps = []PolicyStep{u("ready", x4)}
	out = append(out, sc)
	sc = base("standing never covers pci", "labyrinth", `{"pci_allow":["`+pGPU+`"],"usb_allow":[],"usb_standing":["`+pGPU+`"]}`)
	dev(&sc, pGPU, "0x030000", false, pGPU)
	sc.Steps = []PolicyStep{rdy(pGPU), {Op: "standing"}}
	out = append(out, sc)
	for i, cfg := range []string{"{", `{"usb_standing":"x"}`, `{"usb_allow":["5059:4040"],"usb_standing":["5059:4040","5059:4040"]}`, `{"usb_allow":["5059:4040"]}`, `{"usb_allow":["5059:4040"],"usb_standing":null}`, `{"usb_allow":["5059:4040"],"usb_standing":["5059:404G","5059:40400","1:2"]}`} {
		sc := base(fmt.Sprintf("standing %d", i), "labyrinth", cfg)
		sc.Steps = []PolicyStep{{Op: "standing"}}
		out = append(out, sc)
	}

	// generated hosts: random sysfs trees, lists, approvals, open files and drivers
	r := rand.New(rand.NewSource(20261111))
	ev := rand.New(rand.NewSource(20261112))
	pciPool := []string{pGPU, pAudio, pNIC, pBridge, "0000:05:00.0"}
	usbPool := []string{x4, "0403:cc4c", "05e3:0610", "1a86:7523"}
	pick := func(pool []string, max int) []string {
		var s []string
		for _, x := range pool {
			if r.Intn(len(pool)) < max {
				s = append(s, x)
			}
		}
		if r.Intn(6) == 0 && len(s) > 0 {
			s = append(s, s[0]) // a duplicate
		}
		return s
	}
	oses := []string{"labyrinth", "labyrinth", "labyrinth", `"labyrinth"`, "LABYRINTH", "lykanos", "debian", "-"}
	classes := []string{"0x030000", "0x040300", "0x020000", "0x060400", "0x0604", "0x060401"}
	for i := 0; i < 120; i++ {
		cfg := map[string]any{"pci_allow": pick(pciPool, 3), "usb_allow": pick(usbPool, 2)}
		if r.Intn(3) == 0 {
			cfg["usb_standing"] = pick(append(usbPool, pGPU), 2)
		}
		if r.Intn(4) == 0 {
			upper := []string{}
			for _, a := range cfg["pci_allow"].([]string) {
				upper = append(upper, strings.ToUpper(a))
			}
			cfg["pci_allow"] = upper
		}
		b, _ := json.Marshal(cfg)
		conf := string(b)
		if r.Intn(15) == 0 {
			conf = []string{"{", "[]", `{"pci_allow":[1]}`, ""}[r.Intn(4)]
		}
		sc := base(fmt.Sprintf("generated %d", i), oses[r.Intn(len(oses))], conf)
		if r.Intn(15) == 0 {
			delete(sc.Files, "etc/limbo/host-policy.json")
		}
		for _, a := range pciPool {
			if r.Intn(5) == 0 {
				continue // not present
			}
			dev(&sc, a, classes[r.Intn(len(classes))], r.Intn(8) == 0, pick(pciPool, 2)...)
			if r.Intn(3) == 0 {
				sc.Files["sys/bus/pci/devices/"+a+"/vendor"] = []string{"0x10de\n", "0x1002\n", "0x10de"}[r.Intn(3)]
			}
			if r.Intn(3) == 0 {
				sc.Files["sys/bus/pci/devices/"+a+"/drm/card"+fmt.Sprint(r.Intn(3))] = ""
			}
			if r.Intn(4) == 0 {
				sc.Files["sys/bus/pci/devices/"+a+"/sound/card"+fmt.Sprint(r.Intn(3))] = ""
			}
			if r.Intn(2) == 0 {
				sc.Drv[a] = []string{"nvidia", "vfio-pci", "amdgpu", "snd_hda_intel"}[r.Intn(4)]
			}
		}
		for j, id := range usbPool {
			for k := 0; k < r.Intn(3); k++ {
				d := fmt.Sprintf("%d-%d", k+1, j+1)
				usb(&sc, d, id, []string{"00", "09", "ef"}[r.Intn(3)], k+1, j+2)
				if r.Intn(3) == 0 {
					sc.USBDrv[d+":1.0"] = []string{"usbfs", "usb-storage", "", "ftdi_sio"}[r.Intn(4)]
				}
			}
		}
		nodes := []string{"/dev/dri/card0", "/dev/dri/card1", "/dev/nvidia0", "/dev/nvidiactl", "/dev/snd/pcmC0D0p", "/dev/snd/controlC2", "/dev/bus/usb/001/002", "/dev/bus/usb/002/003", "/dev/pts/1"}
		for k := 0; k < r.Intn(5); k++ {
			sc.Open[fmt.Sprintf("p%d (%d)", k, 100+k)] = []string{nodes[r.Intn(len(nodes))], nodes[r.Intn(len(nodes))]}
		}
		switch r.Intn(5) {
		case 1, 2:
			sc.Approval = approval(append(pick(pciPool, 3), pick(usbPool, 2)...), []string{"2026-10-10T13:00:00Z", "2026-10-10T11:00:00Z"}[r.Intn(2)], []int{0o600, 0o600, 0o640, 0o400}[r.Intn(4)])
		case 3:
			sc.Approval = &ApprovalFile{Body: []string{"", "{", `{"devices":"x"}`, "null"}[r.Intn(4)], Mode: 0o600}
		}
		sc.Blocked = r.Intn(10) == 0
		for k := 0; k < 6; k++ {
			op := []string{"check", "ready", "check", "ready", "standing", "after"}[r.Intn(6)]
			st := PolicyStep{Op: op, PCI: pick(pciPool, 2), USB: pick(usbPool, 1), Advance: int64(r.Intn(2)) * 3000}
			if op == "after" {
				st.USB = nil
				st.DrvAfter = map[string]string{}
				for _, a := range st.PCI {
					if r.Intn(2) == 0 {
						st.DrvAfter[a] = []string{"nvidia", "vfio-pci", ""}[r.Intn(3)]
					}
				}
				st.NoRecord = r.Intn(2) == 0
			}
			sc.Steps = append(sc.Steps, st)
		}
		// a restart or a reboot somewhere in a third of them (its own source: the hosts above stay as they were)
		if ev.Intn(3) == 0 {
			e := []PolicyStep{{Op: "restart"}, {Op: "reboot", BootID: bootB}, {Op: "reboot", BootID: "-"}, {Op: "clear"}}[ev.Intn(4)]
			at := ev.Intn(len(sc.Steps) + 1)
			sc.Steps = append(sc.Steps[:at], append([]PolicyStep{e}, sc.Steps[at:]...)...)
		}
		out = append(out, sc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// TestParityHostPolicy: the answers of Check, Ready, Standing, HostID, Before and After on fake hosts.
func TestParityHostPolicy(t *testing.T) {
	var cases []parity.Case
	for _, sc := range policyScenarios() {
		cases = append(cases, parity.Case{Fn: "Policy", In: sc, Out: runPolicyScenario(t, sc)})
	}
	parity.Fixture(t, "hostpolicy", cases)
}
