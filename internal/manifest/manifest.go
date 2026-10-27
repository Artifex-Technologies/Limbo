// Package manifest defines the per-guest description Limbo works from.
//
// It plays the role the per-OS variable files play in the
// macos-parallels-build-vms reference: one declarative file per guest, with
// everything else (libvirt XML, firewall rules, launch commands) derived from
// it. Every default is the restrictive one — a manifest that says nothing about
// networking gets no network, nothing about clipboard gets no clipboard.
package manifest

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"
)

// Guest OS values.
const (
	OSLinux   = "linux"
	OSWindows = "windows"
)

// Network modes, from most to least restrictive.
const (
	NetNone         = "none"          // isolated libvirt network, no forwarding
	NetAllowlist    = "allowlist"     // only listed destinations
	NetInternetOnly = "internet-only" // anything except private/host/LAN ranges
)

// Clipboard values.
const (
	ClipOff  = "off"
	ClipText = "text"
)

// nameRe keeps names usable as libvirt names, nftables identifiers and
// interface names (Linux caps those at 15 bytes; we prefix with "vl-"/"lb-").
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,11}$`)

// userRe is deliberately narrow: the user ends up in an ssh/RDP argument.
var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Manifest describes one guest and the single application shown from it.
type Manifest struct {
	Name        string  `json:"name"`
	OS          string  `json:"os"`
	Image       Image   `json:"image"`
	CPUs        int     `json:"cpus"`
	MemoryMB    int     `json:"memory_mb"`
	Network     Network `json:"network"`
	ExchangeDir string  `json:"exchange_dir"`
	// ExchangeWritable lets the guest write into ExchangeDir. Off by default: the share is read-only on the host's side (virtiofsd
	// --readonly), whatever the guest's own mount says. A writable share is accepted only on a nosuid,nodev host mount, because
	// the guest's root writes there as the host's root and could otherwise leave setuid-root programs or device nodes.
	ExchangeWritable bool   `json:"exchange_writable"`
	Clipboard        string `json:"clipboard"`
	Disposable       bool   `json:"disposable"`
	// ConsoleLog, if set, records the guest's serial console to this host file.
	// Output only: the guest can write to it but there is no input channel.
	ConsoleLog string    `json:"console_log"`
	Access     Access    `json:"access"`
	App        App       `json:"app"`
	Provision  Provision `json:"provision"`
	Windows    Windows   `json:"windows"`
	Devices    Devices   `json:"devices"`
}

// Devices is host hardware handed to the guest. Empty by default, and even when a
// profile names a device the host's own policy (package hostpolicy) decides
// whether it may be used: this section is a request, not a grant.
type Devices struct {
	// PCI lists whole host PCI devices passed through with VFIO, by address
	// ("0000:03:00.0"). Meant for driver testing only: the guest gets direct DMA-capable
	// access to the device, so it is limited to disposable Linux guests.
	PCI []string `json:"pci"`
}

// maxPCI bounds how many devices one guest may take; a GPU and its audio function is the usual need.
const maxPCI = 4

var pciRe = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-1][0-9a-f]\.[0-7]$`)

// Image is the base disk. SHA256 is mandatory so a swapped or corrupted image
// is caught before it boots, mirroring the checksum file the reference build
// emits alongside every VM archive.
type Image struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Network is the guest's egress policy.
type Network struct {
	Mode  string  `json:"mode"`
	Allow []Allow `json:"allow"`
}

// Allow is one permitted destination for NetAllowlist.
type Allow struct {
	Addr  string `json:"addr"` // IP or CIDR
	Port  int    `json:"port"`
	Proto string `json:"proto"` // tcp or udp
}

// Access says how the host reaches the guest to show its application.
type Access struct {
	User string `json:"user"`
	// Sudo gives User passwordless sudo inside the guest. Off by default. Validation
	// profiles need it: vetting a system update means running pacman, which needs
	// root, and the guest is disposable, so root there is the point. It does widen
	// what a hostile guest process can reach (virtual devices), so it is opt-in and
	// belongs on profiles, not on guests that handle untrusted files.
	Sudo bool `json:"sudo"`
}

// App is the application surfaced as a host window.
type App struct {
	Name string `json:"name"`
	Exec string `json:"exec"` // Linux: command. Windows: full path to the .exe
}

// Provision drives unattended Linux guest setup (cloud-init).
type Provision struct {
	SSHPublicKey string   `json:"ssh_public_key"`
	Packages     []string `json:"packages"`
	// SeedISO, if set, is attached read-only as a cloud-init "cidata" disk.
	// Build it with `limbo seed --iso`.
	SeedISO string `json:"seed_iso"`
}

// Windows holds what the user must supply before a Windows guest may exist.
// See package license.
type Windows struct {
	ISO         string `json:"iso"`
	LicenseFile string `json:"license_file"`
}

// Load reads, defaults and validates a manifest file.
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes JSON, rejecting unknown fields so a typo in a security setting
// ("clipbaord") cannot silently fall back to a default.
func Parse(b []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	m.applyDefaults()
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) applyDefaults() {
	if m.CPUs == 0 {
		m.CPUs = 2
	}
	if m.MemoryMB == 0 {
		m.MemoryMB = 4096
	}
	if m.Network.Mode == "" {
		m.Network.Mode = NetNone
	}
	if m.Clipboard == "" {
		m.Clipboard = ClipOff
	}
	for i := range m.Network.Allow {
		if m.Network.Allow[i].Proto == "" {
			m.Network.Allow[i].Proto = "tcp"
		}
	}
}

// Validate checks static properties only. Anything needing the filesystem
// (does the ISO exist?) belongs to the package that cares about it.
func (m *Manifest) Validate() error {
	if err := m.ValidateName(); err != nil {
		return err
	}
	if m.OS != OSLinux && m.OS != OSWindows {
		return fmt.Errorf("manifest: os must be %q or %q, got %q", OSLinux, OSWindows, m.OS)
	}
	if !path.IsAbs(m.Image.Path) {
		return fmt.Errorf("manifest: image.path must be absolute")
	}
	if len(m.Image.SHA256) != 64 || strings.Trim(m.Image.SHA256, "0123456789abcdef") != "" {
		return fmt.Errorf("manifest: image.sha256 must be 64 lowercase hex characters")
	}
	if m.CPUs < 1 || m.CPUs > 64 {
		return fmt.Errorf("manifest: cpus out of range")
	}
	if m.MemoryMB < 512 {
		return fmt.Errorf("manifest: memory_mb must be at least 512")
	}
	switch m.Clipboard {
	case ClipOff, ClipText:
	default:
		return fmt.Errorf("manifest: clipboard must be %q or %q", ClipOff, ClipText)
	}
	if m.ExchangeDir != "" {
		if !path.IsAbs(m.ExchangeDir) || path.Clean(m.ExchangeDir) != m.ExchangeDir {
			return fmt.Errorf("manifest: exchange_dir must be an absolute, clean path")
		}
	}
	if m.ConsoleLog != "" && (!path.IsAbs(m.ConsoleLog) || path.Clean(m.ConsoleLog) != m.ConsoleLog) {
		return fmt.Errorf("manifest: console_log must be an absolute, clean path")
	}
	if m.Provision.SeedISO != "" && (!path.IsAbs(m.Provision.SeedISO) || path.Clean(m.Provision.SeedISO) != m.Provision.SeedISO) {
		return fmt.Errorf("manifest: provision.seed_iso must be an absolute, clean path")
	}
	if !userRe.MatchString(m.Access.User) {
		return fmt.Errorf("manifest: access.user missing or invalid")
	}
	if m.App.Exec == "" || strings.ContainsAny(m.App.Name, ",\n\r") || m.App.Name == "" {
		return fmt.Errorf("manifest: app.name and app.exec are required (app.name may not contain commas)")
	}
	if m.OS == OSWindows && strings.Contains(m.App.Exec, ",") {
		// The path is embedded in FreeRDP's comma-separated /app option.
		return fmt.Errorf("manifest: app.exec may not contain commas for Windows guests")
	}
	if err := m.Devices.validate(m); err != nil {
		return err
	}
	return m.Network.Validate()
}

func (d Devices) validate(m *Manifest) error {
	if len(d.PCI) == 0 {
		return nil
	}
	if !m.Disposable || m.OS != OSLinux {
		return fmt.Errorf("manifest: devices.pci requires a disposable Linux guest")
	}
	if len(d.PCI) > maxPCI {
		return fmt.Errorf("manifest: devices.pci lists more than %d devices", maxPCI)
	}
	seen := map[string]bool{}
	for _, a := range d.PCI {
		if !pciRe.MatchString(a) {
			return fmt.Errorf("manifest: devices.pci %q is not a PCI address like 0000:03:00.0 (lowercase)", a)
		}
		if seen[a] {
			return fmt.Errorf("manifest: devices.pci lists %q twice", a)
		}
		seen[a] = true
	}
	return nil
}

// ValidateName checks the guest name alone. It is exported because the name is
// spliced into firewall and libvirt identifiers, so generators re-check it
// themselves rather than trusting that a caller validated the whole manifest.
func (m *Manifest) ValidateName() error {
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("manifest: name %q must match %s", m.Name, nameRe)
	}
	return nil
}

// Validate checks the network profile. Exported for the same reason as
// ValidateName: the firewall generator depends on exactly this section.
func (n Network) Validate() error {
	switch n.Mode {
	case NetNone, NetInternetOnly:
		if len(n.Allow) > 0 {
			return fmt.Errorf("manifest: network.allow only applies to mode %q", NetAllowlist)
		}
	case NetAllowlist:
		if len(n.Allow) == 0 {
			return fmt.Errorf("manifest: mode %q needs at least one network.allow entry", NetAllowlist)
		}
	default:
		return fmt.Errorf("manifest: network.mode must be none, allowlist or internet-only")
	}
	for _, a := range n.Allow {
		if _, err := a.Prefix(); err != nil {
			return err
		}
		if a.Port < 1 || a.Port > 65535 {
			return fmt.Errorf("manifest: allow %q: port out of range", a.Addr)
		}
		if a.Proto != "tcp" && a.Proto != "udp" {
			return fmt.Errorf("manifest: allow %q: proto must be tcp or udp", a.Addr)
		}
	}
	return nil
}

// Prefix parses Addr as a CIDR or a bare IP. Parsing (rather than passing the
// string through) is what stops a manifest value being spliced into nftables
// syntax.
func (a Allow) Prefix() (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(a.Addr); err == nil {
		return p.Masked(), nil
	}
	ip, err := netip.ParseAddr(a.Addr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("manifest: allow addr %q is not an IP or CIDR", a.Addr)
	}
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}
