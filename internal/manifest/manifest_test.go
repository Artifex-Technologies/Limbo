package manifest

import (
	"strings"
	"testing"
)

const good = `{
 "name":"lab","os":"linux",
 "image":{"path":"/var/lib/limbo/base.qcow2","sha256":"` + "0000000000000000000000000000000000000000000000000000000000000000" + `"},
 "access":{"user":"analyst"},
 "app":{"name":"Wireshark","exec":"wireshark"}
}`

func TestDefaultsAreRestrictive(t *testing.T) {
	m, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if m.Network.Mode != NetNone || m.Clipboard != ClipOff || m.ExchangeDir != "" {
		t.Fatalf("defaults not deny-first: %+v", m)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name, from, to, want string
	}{
		{"unknown field", `"os":"linux"`, `"os":"linux","clipbaord":"text"`, "unknown field"},
		{"macos", `"os":"linux"`, `"os":"macos"`, "os must be"},
		{"bad name", `"name":"lab"`, `"name":"Lab;rm"`, "name"},
		{"long name", `"name":"lab"`, `"name":"abcdefghijklm"`, "name"},
		{"relative image", `"/var/lib/limbo/base.qcow2"`, `"base.qcow2"`, "absolute"},
		{"bad sha", `"0000000000000000000000000000000000000000000000000000000000000000"`, `"zz"`, "sha256"},
		{"bad user", `"analyst"`, `"a b"`, "access.user"},
		{"allow without mode", `"app":`, `"network":{"allow":[{"addr":"1.2.3.4","port":80}]},"app":`, "only applies"},
		{"allowlist empty", `"app":`, `"network":{"mode":"allowlist"},"app":`, "at least one"},
		{"nft injection", `"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"1.1.1.1 accept; drop","port":80}]},"app":`, "not an IP"},
		{"bad port", `"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"1.1.1.1","port":0}]},"app":`, "port"},
		{"exchange traversal", `"app":`, `"exchange_dir":"/srv/../etc","app":`, "clean"},
		{"comma app name", `"Wireshark"`, `"a,b"`, "commas"},
		{"pci not disposable", `"app":`, `"devices":{"pci":["0000:03:00.0"]},"app":`, "disposable Linux"},
		{"pci windows", `"os":"linux"`, `"os":"windows","disposable":true,"devices":{"pci":["0000:03:00.0"]}`, "disposable Linux"},
		{"pci bad address", `"app":`, `"disposable":true,"devices":{"pci":["03:00.0"]},"app":`, "PCI address"},
		{"pci uppercase", `"app":`, `"disposable":true,"devices":{"pci":["0000:0A:00.0"]},"app":`, "PCI address"},
		{"pci duplicate", `"app":`, `"disposable":true,"devices":{"pci":["0000:03:00.0","0000:03:00.0"]},"app":`, "twice"},
		{"pci too many", `"app":`, `"disposable":true,"devices":{"pci":["0000:03:00.0","0000:03:00.1","0000:04:00.0","0000:04:00.1","0000:05:00.0"]},"app":`, "more than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(good, tc.from, tc.to, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAllowPrefix(t *testing.T) {
	p, err := Allow{Addr: "203.0.113.7/24"}.Prefix()
	if err != nil || p.String() != "203.0.113.0/24" {
		t.Fatalf("got %v %v", p, err)
	}
	p, err = Allow{Addr: "2001:db8::1"}.Prefix()
	if err != nil || p.Bits() != 128 {
		t.Fatalf("got %v %v", p, err)
	}
}

func TestNoDevicesByDefault(t *testing.T) {
	m, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Devices.PCI) != 0 {
		t.Fatalf("a manifest that names no devices got %v", m.Devices.PCI)
	}
}
