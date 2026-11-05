package launch

import (
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

func m(os, extra string) *manifest.Manifest {
	mm, err := manifest.Parse([]byte(`{"name":"lab","os":"` + os + `",
 "image":{"path":"/x.qcow2","sha256":"` + strings.Repeat("0", 64) + `"},
 "access":{"user":"analyst"},` + extra + `
 "app":{"name":"Word","exec":"C:\\Program Files\\Word.exe"}}`))
	if err != nil {
		panic(err)
	}
	return mm
}

const pin = `"provision":{"host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl limbo-lab"},`

func TestLinuxUsesWaypipeWithThePinnedKeyOnly(t *testing.T) {
	mm := m("linux", `"clipboard":"text","subnet":7,`+pin)
	c, err := Build(mm, "/run/user/1000/limbo-known")
	if err != nil {
		t.Fatal(err)
	}
	if c.Args[0] != "waypipe" || c.PasswordPrompt {
		t.Fatalf("unexpected: %+v", c)
	}
	if c.Args[len(c.Args)-2] != "analyst@10.213.7.2" {
		t.Fatalf("host arg wrong: %v", c.Args)
	}
	joined := " " + strings.Join(c.Args, " ") + " "
	for _, want := range []string{" StrictHostKeyChecking=yes ", " UserKnownHostsFile=/run/user/1000/limbo-known ", " GlobalKnownHostsFile=/dev/null ", " HostKeyAlias=limbo-lab "} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q: %v", want, c.Args)
		}
	}
	if strings.Contains(joined, "accept-new") || strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Fatalf("trust on first use: %v", c.Args)
	}
	line, err := KnownHostsLine(mm)
	if err != nil || line != "limbo-lab ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n" {
		t.Fatalf("%q %v", line, err)
	}
}

// A guest with no pinned key is not launched at all (it used to be trusted on first use).
func TestLinuxRefusesAnUnpinnedGuest(t *testing.T) {
	if _, err := Build(m("linux", `"clipboard":"text",`), "/x"); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("err=%v", err)
	}
}

func TestWindowsRemoteAppIsLockedDown(t *testing.T) {
	c, _ := Build(m("windows", ""), "")
	joined := " " + strings.Join(c.Args, " ") + " "
	for _, want := range []string{" /from-stdin ", " -clipboard ", " -drives ", " -sound ", " -microphone ", `/app:program:C:\Program Files\Word.exe,name:Word`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, c.Args)
		}
	}
	if strings.Contains(joined, "/p:") || strings.Contains(joined, "home-drive") {
		t.Errorf("password or home drive on command line: %v", c.Args)
	}
	if !c.PasswordPrompt {
		t.Error("windows launch must take password on stdin")
	}
	c, _ = Build(m("windows", `"clipboard":"text",`), "")
	if !strings.Contains(strings.Join(c.Args, " "), "+clipboard") {
		t.Error("clipboard text not honoured")
	}
}

// waypipe cannot leave the clipboard out, so a manifest that says "off" (the default) is refused, not silently ignored.
func TestLinuxRefusesAClipboardItCannotSwitchOff(t *testing.T) {
	if _, err := Build(m("linux", pin), "/x"); err == nil || !strings.Contains(err.Error(), "clipboard") {
		t.Fatalf("err=%v", err)
	}
}
