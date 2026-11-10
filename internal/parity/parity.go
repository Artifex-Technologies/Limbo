// Package parity writes the fixtures the Rust port of limbo serve runs (docs/RUST_PORT.md): what the Go code answers on
// the same inputs, recorded by each package's parity_test.go, in testdata/parity/<name>.json. Run
//
//	LIMBO_PARITY_UPDATE=1 go test ./internal/... -run Parity
//
// after a deliberate change, and review the diff; without the variable a test fails when its fixture is out of date, so
// the fixtures cannot drift from the Go code unnoticed.
package parity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Case is one recorded answer: a function name, its input and what Go returned.
type Case struct {
	Fn  string `json:"fn"`
	In  any    `json:"in"`
	Out any    `json:"out"`
}

// Root is the repository's root folder.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// Fixture compares cases with testdata/parity/<name>.json, or writes them when LIMBO_PARITY_UPDATE=1.
func Fixture(t *testing.T, name string, cases []Case) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(map[string]any{"fixture": name, "cases": cases}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(Root(), "testdata", "parity", name+".json")
	if os.Getenv("LIMBO_PARITY_UPDATE") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d cases)", path, len(cases))
		return
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (write it with LIMBO_PARITY_UPDATE=1)", path, err)
	}
	if !bytes.Equal(old, buf.Bytes()) {
		t.Fatalf("%s is out of date with the Go code: rerun with LIMBO_PARITY_UPDATE=1 and review the diff", path)
	}
}

// Err is an error's text, or "" for none.
func Err(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Good is a minimal valid manifest; Variants are the edits the manifest tests make to it, and more.
const Good = `{
 "name":"lab","os":"linux",
 "image":{"path":"/var/lib/limbo/base.qcow2","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},
 "access":{"user":"analyst"},
 "app":{"name":"Wireshark","exec":"wireshark"}
}`

// Variants: [from, to] replacements applied once to Good.
var Variants = [][2]string{
	{"", ""},
	{`"os":"linux"`, `"os":"linux","clipbaord":"text"`},
	{`"os":"linux"`, `"os":"macos"`},
	{`"name":"lab"`, `"name":"Lab;rm"`},
	{`"name":"lab"`, `"name":"abcdefghijklm"`},
	{`"name":"lab"`, `"name":"abcdefghijkl"`},
	{`"name":"lab"`, `"name":"a\u00e9"`},
	{`"name":"lab"`, `"name":"\ud800x"`},
	{`"name":"lab"`, `"NAME":"lab"`},
	{`"name":"lab"`, `"name":"lab","name":"lab2"`},
	{`"/var/lib/limbo/base.qcow2"`, `"base.qcow2"`},
	{`"0000000000000000000000000000000000000000000000000000000000000000"`, `"zz"`},
	{`"0000000000000000000000000000000000000000000000000000000000000000"`, `"000000000000000000000000000000000000000000000000000000000000000A"`},
	{`"analyst"`, `"a b"`},
	{`"analyst"`, `"_x-1"`},
	{`"app":`, `"network":{"allow":[{"addr":"1.2.3.4","port":80}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist"},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"1.1.1.1 accept; drop","port":80}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"1.1.1.1","port":0}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"1.1.1.1","port":65536}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"1.1.1.1","port":53,"proto":"sctp"}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"10.1.2.3/8","port":443},{"addr":"2001:db8::1","port":53,"proto":"udp"},{"addr":"::ffff:1.2.3.4","port":22},{"addr":"fe80::1%eth0","port":80},{"addr":"2001:DB8:0:0:1:0:0:1/64","port":8080}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"010.1.2.3","port":443}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"1.2.3.4/033","port":443}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"fe80::1%eth0/64","port":443}]},"app":`},
	{`"app":`, `"network":{"mode":"allowlist","allow":[{"addr":"1.2.3.4/33","port":443}]},"app":`},
	{`"app":`, `"network":{"mode":"internet-only"},"app":`},
	{`"app":`, `"network":{"mode":"bridged"},"app":`},
	{`"app":`, `"exchange_dir":"/srv/../etc","app":`},
	{`"app":`, `"exchange_dir":"/srv/x","exchange_writable":true,"app":`},
	{`"app":`, `"console_log":"relative.log","app":`},
	{`"app":`, `"console_log":"/var/log/limbo/lab.log","app":`},
	{`"app":`, `"provision":{"seed_iso":"/a/./b.iso"},"app":`},
	{`"app":`, `"provision":{"host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},"app":`},
	{`"app":`, `"provision":{"host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl lab@limbo"},"app":`},
	{`"app":`, `"provision":{"host_key":"ssh-rsa AAAA"},"app":`},
	{`"app":`, `"provision":{"host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\nx"},"app":`},
	{`"Wireshark"`, `"a,b"`},
	{`"wireshark"`, `""`},
	{`"os":"linux"`, `"os":"windows"`},
	{`"wireshark"`, `"C:\\Program Files\\a,b.exe"`},
	{`"app":`, `"cpus":0,"app":`},
	{`"app":`, `"cpus":65,"app":`},
	{`"app":`, `"cpus":"2","app":`},
	{`"app":`, `"cpus":2.5,"app":`},
	{`"app":`, `"cpus":1e3,"app":`},
	{`"app":`, `"memory_mb":511,"app":`},
	{`"app":`, `"memory_mb":-1,"app":`},
	{`"app":`, `"disk_gb":4097,"app":`},
	{`"app":`, `"disk_gb":64,"app":`},
	{`"app":`, `"subnet":255,"app":`},
	{`"app":`, `"subnet":7,"app":`},
	{`"app":`, `"clipboard":"html","app":`},
	{`"app":`, `"clipboard":"text","app":`},
	{`"app":`, `"disposable":"yes","app":`},
	{`"app":`, `"image":null,"app":`},
	{`"app":`, `"network":[],"app":`},
	{`"app":`, `"devices":{"pci":["0000:03:00.0"]},"app":`},
	{`"os":"linux"`, `"os":"windows","disposable":true,"devices":{"pci":["0000:03:00.0"]}`},
	{`"app":`, `"disposable":true,"devices":{"pci":["03:00.0"]},"app":`},
	{`"app":`, `"disposable":true,"devices":{"pci":["0000:0A:00.0"]},"app":`},
	{`"app":`, `"disposable":true,"devices":{"pci":["0000:03:00.0","0000:03:00.0"]},"app":`},
	{`"app":`, `"devices":{"usb":["5059:4040"]},"app":`},
	{`"os":"linux"`, `"os":"windows","devices":{"usb":["5059:4040"]}`},
	{`"app":`, `"disposable":true,"devices":{"usb":["5059-4040"]},"app":`},
	{`"app":`, `"disposable":true,"devices":{"usb":["5059:40AB"]},"app":`},
	{`"app":`, `"disposable":true,"devices":{"usb":["5059:4040","5059:4040"]},"app":`},
	{`"app":`, `"disposable":true,"devices":{"usb":["5059:4040","5059:4080","0403:cc4c","0403:6001","1a86:7523"]},"app":`},
	{`"app":`, `"disposable":true,"devices":{"pci":["0000:03:00.0","0000:03:00.1","0000:04:00.0","0000:04:00.1","0000:05:00.0"]},"app":`},
	{`"app":`, `"disposable":true,"devices":{"pci":["0000:03:00.0","0000:03:00.1"],"usb":["5059:4040"]},"app":`},
	{`"os":"linux"`, `"os":"windows","disposable":true,"devices":{"usb":["5059:4040"]},"windows":{"iso":"/isos/win.iso","license_file":"/etc/limbo/win.lic"}`},
	{`"app":`, `"devices":{"pci":[],"usb":null},"provision":{"packages":[]},"network":{"mode":"none","allow":[]},"app":`},
	{`"app":`, `"provision":{"ssh_public_key":"ssh-ed25519 AAAAC3Nza lab","packages":["nmap","python3-pip","bad pkg"],"seed_iso":"/var/lib/limbo/seed.iso"},"access":{"user":"analyst","sudo":true},"app":`},
	{`"app":`, `"provision":{"ssh_public_key":"ssh-ed25519 AAAAC3Nza lab","packages":["nmap","tcpdump"]},"app":`},
	{`"app":`, `"provision":{"ssh_public_key":"ecdsa-sha2-nistp256 AAAAE2 x"},"access":{"user":"analyst","sudo":true},"app":`},
	{`"app":`, `"provision":{"ssh_public_key":"ssh-ed25519 AAAA\nx"},"app":`},
	{`"app":`, `"app":{"name":"x\"<&>'y","exec":"/opt/a b/c"},"x":1,"app":`},
	{`{`, `[`},
	{`{`, ``},
	{`}`, `,}`},
	{`}`, `} trailing`},
	{`"lab"`, `"l\u0061b"`},
	{`"app":`, `"evil\u0000":1,"app":`},
}

// Manifests applies every variant to Good.
func Manifests() []string {
	out := make([]string, 0, len(Variants))
	for _, v := range Variants {
		out = append(out, strings.Replace(Good, v[0], v[1], 1))
	}
	return out
}
