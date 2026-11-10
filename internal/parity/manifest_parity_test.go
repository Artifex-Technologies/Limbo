package parity_test

import (
	"encoding/json"
	"fmt"
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
	for _, b := range []string{"lb-lab", "lb-a-b-c", "lb-x"} {
		cases = append(cases, parity.Case{Fn: "hostfw", In: b, Out: map[string]any{"open": hostfw.UFWOpen(b), "close": hostfw.UFWClose(b)}})
	}
	parity.Fixture(t, "manifests", cases)
}
