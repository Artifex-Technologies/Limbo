package virt

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

func parse(t *testing.T, extra string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse([]byte(`{
 "name":"lab","os":"linux",
 "image":{"path":"/var/lib/limbo/a&b.qcow2","sha256":"` + strings.Repeat("0", 64) + `"},
 "access":{"user":"analyst"},` + extra + `
 "app":{"name":"A","exec":"a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDomainXMLWellFormedAndMinimal(t *testing.T) {
	out, err := DomainXML(parse(t, ""), "/var/lib/limbo/a&b.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if err := xml.Unmarshal(out, new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("not well-formed: %v", err)
	}
	if !strings.Contains(s, "a&amp;b.qcow2") {
		t.Errorf("path not escaped:\n%s", s)
	}
	for _, banned := range []string{"<graphics", "<redirdev", "<sound", "<filesystem", "<transient", "spice"} {
		if strings.Contains(s, banned) {
			t.Errorf("default domain contains %q", banned)
		}
	}
	if !strings.Contains(s, `<target dev="vl-lab"`) {
		t.Errorf("tap name not pinned")
	}
}

func TestDomainXMLOptions(t *testing.T) {
	out, _ := DomainXML(parse(t, `"disposable":true,"exchange_dir":"/srv/limbo/lab",`), "/state/lab.overlay.qcow2")
	s := string(out)
	for _, want := range []string{`file="/state/lab.overlay.qcow2"`, `type="virtiofs"`, `dir="/srv/limbo/lab"`, `type="memfd"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestNetworkXMLIsolatedWhenNone(t *testing.T) {
	none, _ := NetworkXML(parse(t, ""))
	if strings.Contains(string(none), "<forward") {
		t.Errorf("mode none must not forward:\n%s", none)
	}
	nat, _ := NetworkXML(parse(t, `"network":{"mode":"internet-only"},`))
	if !strings.Contains(string(nat), `<forward mode="nat">`) {
		t.Errorf("internet-only should NAT:\n%s", nat)
	}
}

func TestAddrStable(t *testing.T) {
	m := parse(t, "")
	a, b := Addr(m), Addr(m)
	if a != b || !strings.HasPrefix(a.Guest.String(), "10.213.") {
		t.Fatalf("unstable or wrong range: %+v", a)
	}
}

func TestSeedISOAttachedReadOnly(t *testing.T) {
	out, err := DomainXML(parse(t, `"provision":{"seed_iso":"/var/lib/limbo/seed.iso"},`), "/x.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`device="cdrom"`, `file="/var/lib/limbo/seed.iso"`, "<readonly>"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
}

func TestConsoleLogIsFileBackedOutputOnly(t *testing.T) {
	off, _ := DomainXML(parse(t, ""), "/var/lib/limbo/a&b.qcow2")
	if strings.Contains(string(off), "<serial") {
		t.Error("no serial device unless console_log is set")
	}
	on, err := DomainXML(parse(t, `"console_log":"/var/log/limbo/lab.console",`), "/x.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	s := string(on)
	if !strings.Contains(s, `<serial type="file">`) || !strings.Contains(s, `path="/var/log/limbo/lab.console"`) {
		t.Errorf("serial file device missing:\n%s", s)
	}
}

func TestHostdevOnlyWhenRequested(t *testing.T) {
	off, _ := DomainXML(parse(t, ""), "/x.qcow2")
	if strings.Contains(string(off), "hostdev") {
		t.Fatalf("no device was requested but a hostdev appeared: %s", off)
	}
	out, err := DomainXML(parse(t, `"disposable":true,"devices":{"pci":["0000:03:00.0","0000:03:00.1"]},`), "/x.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if err := xml.Unmarshal(out, new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("not well-formed: %v", err)
	}
	for _, want := range []string{
		`<hostdev mode="subsystem" type="pci" managed="yes">`,
		`<address domain="0x0000" bus="0x03" slot="0x00" function="0x0">`,
		`<address domain="0x0000" bus="0x03" slot="0x00" function="0x1">`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in: %s", want, s)
		}
	}
}

func TestUSBHostdev(t *testing.T) {
	out, err := DomainXML(parse(t, `"disposable":true,"devices":{"usb":["5059:4040"]},`), "/x.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if err := xml.Unmarshal(out, new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("not well-formed: %v", err)
	}
	for _, want := range []string{`<hostdev mode="subsystem" type="usb">`, `<vendor id="0x5059"></vendor>`, `<product id="0x4040"></product>`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in: %s", want, s)
		}
	}
	if strings.Contains(s, "<address") || strings.Contains(s, `managed=`) {
		t.Errorf("a USB hostdev has no PCI address and no managed attribute: %s", s)
	}
	if _, err := usbHostdev("5059:4040'/><x"); err == nil {
		t.Error("a bad ID reached the XML")
	}
}

func TestTheShareIsReadOnlyUnlessAskedOtherwise(t *testing.T) {
	ro, _ := DomainXML(parse(t, `"exchange_dir":"/srv/limbo/lab",`), "/state/lab.overlay.qcow2")
	if !strings.Contains(string(ro), "<readonly></readonly>") {
		t.Errorf("a share is read-only on the host's side by default:\n%s", ro)
	}
	rw, _ := DomainXML(parse(t, `"exchange_dir":"/srv/limbo/lab","exchange_writable":true,`), "/state/lab.overlay.qcow2")
	if strings.Contains(string(rw), "<readonly") {
		t.Errorf("exchange_writable must leave it writable:\n%s", rw)
	}
}

func TestWindowsGuestBootsItsInstallationCD(t *testing.T) {
	m := &manifest.Manifest{Name: "win", OS: manifest.OSWindows, CPUs: 4, MemoryMB: 8192, Disposable: true,
		Network: manifest.Network{Mode: manifest.NetInternetOnly}}
	m.Windows.ISO = "/home/me/limbo-seeds/windows/win11.iso"
	m.Provision.SeedISO = "/home/me/limbo-seeds/windows/seed.iso"
	m.Devices.USB = []string{"5059:4040"}
	b, err := DomainXML(m, "/var/lib/limbo/state/win.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	x := string(b)
	for _, want := range []string{
		`<boot order="1"></boot>`, `<boot order="2"></boot>`,
		`<source file="/home/me/limbo-seeds/windows/win11.iso"></source>`,
		`<target dev="sda" bus="sata"></target>`, `<target dev="sdb" bus="sata"></target>`, `<target dev="sdc" bus="sata"></target>`,
		`<source file="/home/me/limbo-seeds/windows/seed.iso"></source>`,
		`<model type="vga"></model>`, `<model type="e1000e"></model>`,
		`<vendor id="0x5059"></vendor>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %s in\n%s", want, x)
		}
	}
	if strings.Contains(x, `dev="vda"`) {
		t.Error("a SATA disk named vda")
	}
	if strings.Contains(x, "<graphics") {
		t.Error("a display was attached")
	}
	// a Linux guest is unchanged: no boot order, no display adapter
	l := &manifest.Manifest{Name: "lin", OS: manifest.OSLinux, CPUs: 2, MemoryMB: 2048}
	lb, _ := DomainXML(l, "/x.qcow2")
	if strings.Contains(string(lb), "<boot") || !strings.Contains(string(lb), `<model type="none"></model>`) {
		t.Errorf("Linux guest changed:\n%s", lb)
	}
}
