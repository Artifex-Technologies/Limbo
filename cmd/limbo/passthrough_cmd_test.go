package main

import (
	"bytes"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/hostpolicy"
)

const testGPU = "0000:03:00.0"

type nopLog struct{ kinds []string }

func (l *nopLog) Emit(kind, _ string, _ map[string]string) error {
	l.kinds = append(l.kinds, kind)
	return nil
}

func labyrinthHost(t *testing.T, openBy string) *hostpolicy.Policy {
	t.Helper()
	d := "sys/bus/pci/devices/" + testGPU + "/"
	fs := fstest.MapFS{
		"etc/os-release":                     {Data: []byte("ID=labyrinth\n")},
		"etc/limbo/host-policy.json":         {Data: []byte(`{"pci_allow":["` + testGPU + `"]}`)},
		d + "class":                          {Data: []byte("0x030000\n")},
		d + "iommu_group/devices/" + testGPU: {},
		d + "drm/renderD129":                 {},
	}
	return &hostpolicy.Policy{
		Root: fs, StateDir: t.TempDir(), RunDir: t.TempDir(),
		OpenFiles: func() map[string][]string {
			if openBy == "" {
				return nil
			}
			return map[string][]string{openBy: {"/dev/dri/renderD129"}}
		},
		Driver: func(string) string { return "nvidia" },
	}
}

func approve(p *hostpolicy.Policy, input string, tty bool) (string, error) {
	var out bytes.Buffer
	err := passthrough([]string{"approve", testGPU}, 30*time.Minute, p, &nopLog{}, strings.NewReader(input), &out, tty, "me")
	return out.String(), err
}

func TestApproveNeedsTypedYes(t *testing.T) {
	p := labyrinthHost(t, "")
	out, err := approve(p, "no\n", true)
	if err != nil || p.Approval() != nil {
		t.Fatalf("anything but yes must approve nothing: err=%v approval=%v", err, p.Approval())
	}
	if !strings.Contains(out, "not approved") || !strings.Contains(out, "reboot") {
		t.Fatalf("warning missing the reboot risk:\n%s", out)
	}
	if _, err := approve(p, "yes\n", true); err != nil || p.Approval() == nil {
		t.Fatalf("yes must approve: %v", err)
	}
}

func TestApproveRefusesWithoutTerminal(t *testing.T) {
	p := labyrinthHost(t, "")
	if _, err := approve(p, "yes\n", false); err == nil || p.Approval() != nil {
		t.Fatal("approval granted without a terminal")
	}
}

func TestApproveRefusesWhileDeviceInUse(t *testing.T) {
	p := labyrinthHost(t, "firefox (4242)")
	out, err := approve(p, "yes\n", true)
	if err == nil || p.Approval() != nil {
		t.Fatal("approval granted while an app uses the GPU")
	}
	if !strings.Contains(out, "firefox (4242)") || !strings.Contains(out, "close") {
		t.Fatalf("the person must be told what to close:\n%s", out)
	}
}

func TestApproveUSBShowsItsOwnWarning(t *testing.T) {
	fs := fstest.MapFS{
		"etc/os-release":                              {Data: []byte("ID=labyrinth\n")},
		"etc/limbo/host-policy.json":                  {Data: []byte(`{"usb_allow":["5059:4040"]}`)},
		"sys/bus/usb/devices/1-9/idVendor":            {Data: []byte("5059\n")},
		"sys/bus/usb/devices/1-9/idProduct":           {Data: []byte("4040\n")},
		"sys/bus/usb/devices/1-9/bDeviceClass":        {Data: []byte("00\n")},
		"sys/bus/usb/devices/1-9/busnum":              {Data: []byte("1\n")},
		"sys/bus/usb/devices/1-9/devnum":              {Data: []byte("8\n")},
		"sys/bus/usb/devices/1-9:1.0/bInterfaceClass": {Data: []byte("ff\n")},
	}
	p := &hostpolicy.Policy{Root: fs, StateDir: t.TempDir(), RunDir: t.TempDir(),
		OpenFiles: func() map[string][]string { return nil }, USBDriver: func(string) string { return "" }}
	var out bytes.Buffer
	if err := passthrough([]string{"approve", "5059:4040"}, 30*time.Minute, p, &nopLog{}, strings.NewReader("yes\n"), &out, true, "me"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "USB passthrough approval") || !strings.Contains(out.String(), "firmware") || strings.Contains(out.String(), "GPU") {
		t.Fatalf("the USB warning is not the one shown:\n%s", out.String())
	}
	if a := p.Approval(); a == nil || a.Devices[0] != "5059:4040" {
		t.Fatalf("not approved: %+v", a)
	}
}
