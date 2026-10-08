// Package provision generates the unattended-setup files for a Linux guest.
//
// It is the counterpart of the reference build's Ansible stage: the base image
// stays generic and everything per-guest (user, key, tools) is applied from a
// seed at first boot. Output is cloud-init NoCloud user-data/meta-data. Turning
// the pair into a "cidata" ISO is left to the caller (xorriso/genisoimage), so
// Limbo carries no ISO-writing dependency.
//
// Windows is not handled here: an unattended answer file cannot be written
// honestly without a Windows ISO to test against. See package license.
package provision

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

var (
	pkgRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)
	keyRe = regexp.MustCompile(`^(ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/=]+( [^\r\n]*)?$`)
)

// Seed is the pair of cloud-init files.
type Seed struct {
	UserData string
	MetaData string
}

// Build renders the seed. Every manifest value is validated and then emitted as
// a JSON string; JSON is valid YAML, which removes any chance of a value
// changing the document's structure.
func Build(m *manifest.Manifest) (Seed, error) {
	if m.OS != manifest.OSLinux {
		return Seed{}, fmt.Errorf("provision: only Linux guests are supported")
	}
	if !keyRe.MatchString(m.Provision.SSHPublicKey) {
		return Seed{}, fmt.Errorf("provision: provision.ssh_public_key missing or not a single-line public key")
	}
	for _, p := range m.Provision.Packages {
		if !pkgRe.MatchString(p) {
			return Seed{}, fmt.Errorf("provision: invalid package name %q", p)
		}
	}
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }

	var b strings.Builder
	b.WriteString("#cloud-config\n")
	b.WriteString("users:\n")
	fmt.Fprintf(&b, "  - name: %s\n", q(m.Access.User))
	b.WriteString("    lock_passwd: true\n")
	b.WriteString("    shell: /bin/bash\n")
	if m.Access.Sudo {
		// Opt-in (manifest access.sudo): passwordless sudo for the unprivileged
		// user, so a validation run can do what an update needs (pacman).
		b.WriteString("    sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n")
	}
	fmt.Fprintf(&b, "    ssh_authorized_keys: [%s]\n", q(m.Provision.SSHPublicKey))
	b.WriteString("disable_root: true\n")
	b.WriteString("ssh_pwauth: false\n")
	// The guest's clock starts correct (libvirt sets the RTC from the host), so
	// do not make boot wait for NTP. systemd-time-wait-sync holds sshd (via
	// time-sync.target) until an NTP server answers, which a guest in network
	// mode "none" or "allowlist" can never reach: it booted fine, answered ping,
	// and never started sshd. internet-only only worked because NTP got through,
	// after a ~35s delay. Found on a real guest; bootcmd runs early on every boot.
	b.WriteString("bootcmd:\n  - [systemctl, mask, --now, systemd-time-wait-sync.service]\n")
	// Be explicit about package handling rather than inheriting the image's
	// default, so first boot never depends on the network. (Not the cause of the
	// hang described above, which was NTP; this is just determinism.)
	if len(m.Provision.Packages) == 0 {
		b.WriteString("package_update: false\npackage_upgrade: false\n")
	}
	if len(m.Provision.Packages) > 0 {
		b.WriteString("package_update: true\npackages:\n")
		for _, p := range m.Provision.Packages {
			fmt.Fprintf(&b, "  - %s\n", q(p))
		}
	}
	meta := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", q("limbo-"+m.Name), q(m.Name))
	return Seed{UserData: b.String(), MetaData: meta}, nil
}
