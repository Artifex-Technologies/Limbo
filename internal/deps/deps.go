// Package deps knows what Limbo needs installed on the host and can say what is
// missing. It exists so Limbo can ship in an image as a small package of its own
// and fetch the heavy runtime (libvirt, QEMU, ...) on first setup, rather than
// every system carrying them whether or not it ever runs a guest.
//
// The package is pure: it takes the lookup function as a parameter so it can be
// tested without touching the machine it runs on.
package deps

import (
	"fmt"
	"sort"
	"strings"
)

// Dep is one thing Limbo shells out to.
type Dep struct {
	Command string // the executable that proves it is installed
	Package string // the Arch package that provides it
	Purpose string // why Limbo needs it
}

// Required is everything Limbo runs as a separate program. Keep it in step with
// the PKGBUILD's optdepends and with what the engine, runs and CLI actually exec.
var Required = []Dep{
	{"virsh", "libvirt", "defines, starts and stops guests"},
	{"qemu-img", "qemu-base", "creates the per-guest disposable overlay"},
	{"qemu-system-x86_64", "qemu-base", "the hypervisor (KVM)"},
	{"dnsmasq", "dnsmasq", "DHCP and DNS on each guest's private network"},
	{"nft", "nftables", "each guest's firewall"},
	{"ssh", "openssh", "validation runs reach the guest over ssh"},
	{"xorriso", "libisoburn", "builds the cloud-init seed disk"},
}

// LookPath has the shape of exec.LookPath.
type LookPath func(file string) (string, error)

// Missing returns the dependencies whose command is not found.
func Missing(look LookPath) []Dep {
	var out []Dep
	for _, d := range Required {
		if _, err := look(d.Command); err != nil {
			out = append(out, d)
		}
	}
	return out
}

// Packages returns the distinct packages that would provide the missing
// commands, sorted, ready to hand to the package manager.
func Packages(missing []Dep) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range missing {
		if !seen[d.Package] {
			seen[d.Package] = true
			out = append(out, d.Package)
		}
	}
	sort.Strings(out)
	return out
}

// Preflight returns nil when everything is installed, otherwise an error that
// names what is missing and the one command that fixes it. Commands that act on
// guests call it first, so a freshly installed system fails with instructions
// instead of "exec: virsh: executable file not found in $PATH".
func Preflight(look LookPath) error {
	missing := Missing(look)
	if len(missing) == 0 {
		return nil
	}
	parts := make([]string, len(missing))
	for i, d := range missing {
		parts[i] = d.Command + " (" + d.Package + ")"
	}
	return fmt.Errorf("Limbo's runtime dependencies are not installed: %s. Run: sudo limbo setup", strings.Join(parts, ", "))
}
