package parity_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/hostfw"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/parity"
	"github.com/Artifex-Technologies/Limbo/internal/policy"
	"github.com/Artifex-Technologies/Limbo/internal/provision"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

// TestParityManifests: manifest.Parse on every variant, and for each one that parses, what virt, policy and provision
// make of it (Go's tests in manifest, virt, policy and provision check properties of these; the fixtures pin the bytes).
func TestParityManifests(t *testing.T) {
	var cases []parity.Case
	for _, doc := range parity.Manifests() {
		m, err := manifest.Parse([]byte(doc))
		out := map[string]any{"error": parity.Err(err)}
		if err == nil {
			b, _ := json.MarshalIndent(m, "", "  ")
			out["manifest"] = string(b)
		}
		cases = append(cases, parity.Case{Fn: "manifest.Parse", In: doc, Out: out})
		if err != nil {
			continue
		}
		for _, sub := range []int{0, 7, 254} {
			mm := *m
			mm.Subnet = sub
			dom, derr := virt.DomainXML(&mm, "/var/lib/limbo/state/"+virt.DiskName(&mm))
			net, nerr := virt.NetworkXML(&mm)
			a := virt.Addr(&mm)
			rules, rerr := policy.NFT(&mm)
			restrict, serr := policy.NFTRestrict(&mm)
			release, lerr := policy.NFTRelease(&mm)
			seed, berr := provision.Build(&mm)
			cases = append(cases, parity.Case{Fn: "derived", In: map[string]any{"manifest": doc, "subnet": sub}, Out: map[string]any{
				"domain": string(dom), "domain_error": parity.Err(derr), "network": string(net), "network_error": parity.Err(nerr),
				"gateway": a.Gateway.String(), "guest": a.Guest.String(), "mac": a.MAC,
				"nft": rules, "nft_error": parity.Err(rerr), "restrict": restrict, "restrict_error": parity.Err(serr),
				"release": release, "release_error": parity.Err(lerr),
				"user_data": seed.UserData, "meta_data": seed.MetaData, "seed_error": parity.Err(berr),
				"table": policy.TableName(&mm), "names": []string{virt.DomainName(&mm), virt.NetworkName(&mm), virt.BridgeName(&mm), virt.TapName(&mm), virt.DiskName(&mm)},
			}})
		}
	}
	// a Windows guest with its installation CD, a seed and every device kind (the XML a real run never sees together)
	win := `{"name":"win","os":"windows","disposable":true,"image":{"path":"/i/w.qcow2","sha256":"` + fmt.Sprintf("%064d", 1) + `"},
	 "access":{"user":"analyst"},"app":{"name":"Office","exec":"C:\\o.exe"},"windows":{"iso":"/i/w.iso","license_file":"/i/w.lic"},
	 "provision":{"seed_iso":"/s/seed.iso"},"devices":{"usb":["5059:4040"]},"console_log":"/l/c.log","exchange_dir":"/x/win","cpus":4,"memory_mb":8192}`
	m, err := manifest.Parse([]byte(win))
	if err != nil {
		t.Fatal(err)
	}
	dom, _ := virt.DomainXML(m, "/s/win.overlay.qcow2")
	cases = append(cases, parity.Case{Fn: "virt.DomainXML", In: win, Out: string(dom)})
	// the seeds with the guest's host key pair (limbo seed): a Linux guest's cloud-init, a Windows guest's answer file,
	// first-logon script and keys, with each option a seed can be given and the refusals
	priv := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n-----END OPENSSH PRIVATE KEY-----\n"
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtq1lTZ8bS0bYpDn3m0Yy3uKQ0o4m6F1rYqJcVv8hJX limbo-x"
	keys := []*provision.HostKey{nil, {Private: priv, Public: pub}, {Private: priv, Public: "  " + pub + "\n"},
		{Private: "PRIVATE KEY only", Public: pub}, {Private: priv, Public: "ssh-rsa AAAA x"}, {Private: priv, Public: "ssh-ed25519 short"}}
	seedDocs := []string{
		`{"name":"lab","os":"linux","image":{"path":"/i/a.qcow2","sha256":"` + fmt.Sprintf("%064d", 2) + `"},"access":{"user":"analyst","sudo":true},
		 "app":{"name":"a","exec":"a"},"provision":{"ssh_public_key":"ssh-ed25519 AAAAkey me@host","packages":["nmap"]}}`,
		`{"name":"win","os":"windows","image":{"path":"/i/w.qcow2","sha256":"` + fmt.Sprintf("%064d", 1) + `"},"access":{"user":"analyst"},
		 "app":{"name":"N","exec":"n.exe"},"provision":{"ssh_public_key":"ssh-ed25519 AAAAkey me@host  "},"windows":{"iso":"/i/w.iso","license_file":"/i/w.lic"}}`,
		`{"name":"abcdefghijkl","os":"windows","image":{"path":"/i/w.qcow2","sha256":"` + fmt.Sprintf("%064d", 1) + `"},"access":{"user":"_svc-1"},
		 "app":{"name":"N","exec":"n.exe"},"provision":{"ssh_public_key":"ecdsa-sha2-nistp256 AAAA"},"windows":{"iso":"/i/w.iso","license_file":"/i/w.lic"}}`,
		`{"name":"nokey","os":"windows","image":{"path":"/i/w.qcow2","sha256":"` + fmt.Sprintf("%064d", 1) + `"},"access":{"user":"analyst"},
		 "app":{"name":"N","exec":"n.exe"},"windows":{"iso":"/i/w.iso","license_file":"/i/w.lic"}}`,
	}
	opts := []provision.WindowsOptions{
		{Password: "Pa55word-is-long"}, {Password: "<a&b>\"q\" 'é' \t ok"}, {Password: "short"}, {Password: strings.Repeat("é", 127)},
		{Password: strings.Repeat("x", 128)}, {Password: "with a \x01 control"}, {Password: "Pa55word-is-long", ProductKey: "ABCDE-12345-FGHIJ-67890-KLMNO"},
		{Password: "Pa55word-is-long", ProductKey: "abcde-12345-FGHIJ-67890-KLMNO"}, {Password: "Pa55word-is-long", ImageIndex: 3},
		{Password: "Pa55word-is-long", ImageIndex: -2},
	}
	for _, doc := range seedDocs {
		m, err := manifest.Parse([]byte(doc))
		if err != nil {
			t.Fatal(doc, err)
		}
		for ki, hk := range keys {
			s, err := provision.BuildWithHostKey(m, hk)
			cases = append(cases, parity.Case{Fn: "seed.linux", In: map[string]any{"manifest": doc, "key": hk},
				Out: map[string]any{"user_data": s.UserData, "meta_data": s.MetaData, "error": parity.Err(err)}})
			for oi, o := range opts {
				if ki > 1 && oi > 0 {
					continue // the key refusals once each
				}
				o.HostKey = hk
				files, err := provision.BuildWindows(m, o)
				out := map[string]string{}
				for k, v := range files {
					out[k] = string(v)
				}
				o.HostKey = nil
				cases = append(cases, parity.Case{Fn: "seed.windows", In: map[string]any{"manifest": doc, "key": hk, "opts": o},
					Out: map[string]any{"files": out, "error": parity.Err(err)}})
			}
		}
	}
	for _, b := range []string{"lb-lab", "lb-a-b-c", "lb-x"} {
		cases = append(cases, parity.Case{Fn: "hostfw", In: b, Out: map[string]any{"open": hostfw.UFWOpen(b), "close": hostfw.UFWClose(b)}})
	}
	parity.Fixture(t, "manifests", cases)
}
