// Package virt turns a manifest into libvirt definitions.
//
// Output is built with encoding/xml rather than string templates so a manifest
// value can never break out of its element or attribute.
package virt

import (
	"crypto/sha256"
	"fmt"
	"net/netip"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

// Per-guest names. Prefixes plus the 12-character name cap keep interface names
// within Linux's 15-byte limit.

// DomainName is the libvirt domain name.
func DomainName(m *manifest.Manifest) string { return "limbo-" + m.Name }

// NetworkName is the libvirt network private to this guest.
func NetworkName(m *manifest.Manifest) string { return "limbo-" + m.Name }

// BridgeName is the host bridge for the guest's private network.
func BridgeName(m *manifest.Manifest) string { return "lb-" + m.Name }

// TapName is the guest's host-side interface, pinned in the domain XML instead
// of being left to libvirt's vnetN names so it is identifiable in logs. Firewall
// rules match the bridge (BridgeName), not this; see package policy.
func TapName(m *manifest.Manifest) string { return "vl-" + m.Name }

// Addressing is the fixed layout of a guest's private /24. Giving every guest
// one known address means the host never has to discover it, as WinApps' libvirt
// mode does by querying the hypervisor.
type Addressing struct {
	Gateway netip.Addr
	Guest   netip.Addr
	MAC     string
}

// Addr derives a stable 10.213.X.0/24 from the guest name. Two names can hash
// to the same X; libvirt refuses to define overlapping networks, so a collision
// surfaces as an error at `up` rather than as silent cross-talk.
func Addr(m *manifest.Manifest) Addressing {
	h := sha256.Sum256([]byte(m.Name))
	x := 1 + int(h[0])%254
	at := func(host byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 213, byte(x), host}) }
	return Addressing{
		Gateway: at(1),
		Guest:   at(2),
		MAC:     fmt.Sprintf("52:54:00:%02x:%02x:%02x", h[1], h[2], h[3]),
	}
}
