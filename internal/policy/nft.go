// Package policy turns a manifest's network profile into an nftables ruleset.
//
// The ruleset is one table per guest, matched on the guest's private bridge, so
// adding or removing a guest never touches another guest's rules or the host's
// own firewall. It matches the bridge, not the tap: traffic a guest sends to the
// host or through it enters the host's IP stack on the bridge device, and an
// inet-family rule on the tap name never sees it (found by booting a real guest,
// where such rules loaded cleanly and blocked nothing). Each guest has its own
// bridge, so this is still per-guest. Chains hook at priority -10, ahead of the default
// filter priority, and only ever drop or "accept" within their own table: an
// accept here ends this table's evaluation, it does not override a drop in
// someone else's table.
package policy

import (
	"fmt"
	"strings"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

// TableName is the nftables table (family inet) owned by this guest.
func TableName(m *manifest.Manifest) string {
	return "limbo_" + strings.ReplaceAll(m.Name, "-", "_")
}

// Destinations a guest in internet-only mode must never reach: loopback,
// RFC1918, link-local, CGNAT, and the IPv6 equivalents. This is what keeps a
// compromised guest away from the user's LAN, router and other VMs.
var (
	privateV4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4"}
	privateV6 = []string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// NFT renders the ruleset, loadable with `nft -f -`.
//
// Host-bound traffic (input chain): the guest may only answer connections the
// host opened (established/related), may obtain its DHCP lease, and in
// internet-only mode may query DNS at its own gateway. Everything else addressed
// to the host is dropped, so the guest cannot probe services on the host.
//
// Forwarded traffic: replies to the guest are allowed; what the guest may
// initiate depends on the mode.
func NFT(m *manifest.Manifest) (string, error) {
	// Only what this generator depends on: a full Validate would also reject
	// manifests for reasons unrelated to the ruleset.
	if err := m.ValidateName(); err != nil {
		return "", err
	}
	if err := m.Network.Validate(); err != nil {
		return "", err
	}
	tap := virt.BridgeName(m) // see package comment: the bridge, not the tap
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("table inet %s {", TableName(m))
	w("  chain input {")
	w("    type filter hook input priority -10; policy accept;")
	w(`    iifname "%s" ct state established,related accept`, tap)
	// DHCP is a broadcast from 0.0.0.0, so it cannot be matched by gateway
	// address. Every mode needs it: the guest's fixed address arrives by lease.
	w(`    iifname "%s" udp sport 68 udp dport 67 accept`, tap)
	if m.Network.Mode == manifest.NetInternetOnly {
		// DNS only where the guest may resolve names at all. Allowlist mode
		// names IPs, and answering DNS there would be an exfiltration channel.
		gw := virt.Addr(m).Gateway
		w(`    iifname "%s" ip daddr %s udp dport 53 accept`, tap, gw)
		w(`    iifname "%s" ip daddr %s tcp dport 53 accept`, tap, gw)
	}
	w(`    iifname "%s" drop`, tap)
	w("  }")
	w("  chain forward {")
	w("    type filter hook forward priority -10; policy accept;")
	w(`    oifname "%s" ct state established,related accept`, tap)
	w(`    oifname "%s" drop`, tap)

	switch m.Network.Mode {
	case manifest.NetNone:
		// Nothing to allow; the final drop below covers it.
	case manifest.NetInternetOnly:
		w(`    iifname "%s" ip daddr { %s } drop`, tap, strings.Join(privateV4, ", "))
		w(`    iifname "%s" ip6 daddr { %s } drop`, tap, strings.Join(privateV6, ", "))
		w(`    iifname "%s" accept`, tap)
	case manifest.NetAllowlist:
		for _, a := range m.Network.Allow {
			p, err := a.Prefix()
			if err != nil {
				return "", err
			}
			fam := "ip"
			if p.Addr().Is6() {
				fam = "ip6"
			}
			w(`    iifname "%s" %s daddr %s %s dport %d accept`, tap, fam, p, a.Proto, a.Port)
		}
	}
	w(`    iifname "%s" drop`, tap)
	w("  }")
	w("}")
	return b.String(), nil
}

// NFTReplace renders a script that atomically replaces the guest's table with
// the given ruleset. The leading bare "table" line creates it if absent so the
// "delete" cannot fail, and nft applies the whole script as one transaction, so
// there is no instant at which the guest has no table.
func NFTReplace(m *manifest.Manifest, mode string) (string, error) {
	cp := *m
	cp.Network = manifest.Network{Mode: mode}
	if mode == manifest.NetAllowlist {
		cp.Network.Allow = m.Network.Allow
	}
	rules, err := NFT(&cp)
	if err != nil {
		return "", err
	}
	t := TableName(m)
	return fmt.Sprintf("table inet %s\ndelete table inet %s\n%s", t, t, rules), nil
}

// NFTRestrict is the quarantine ruleset: the deny-all one that mode "none" uses,
// regardless of what the manifest asked for.
func NFTRestrict(m *manifest.Manifest) (string, error) {
	return NFTReplace(m, manifest.NetNone)
}

// NFTRelease restores the ruleset the manifest asked for.
func NFTRelease(m *manifest.Manifest) (string, error) {
	return NFTReplace(m, m.Network.Mode)
}
