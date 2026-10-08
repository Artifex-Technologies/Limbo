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
