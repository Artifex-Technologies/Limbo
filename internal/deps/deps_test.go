package deps

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// lookFrom returns a LookPath that finds only the named commands.
func lookFrom(found ...string) LookPath {
	have := map[string]bool{}
	for _, f := range found {
		have[f] = true
	}
	return func(file string) (string, error) {
		if have[file] {
			return "/usr/bin/" + file, nil
		}
		return "", errors.New("not found")
	}
}

func allCommands() []string {
	var out []string
	for _, d := range Required {
		out = append(out, d.Command)
	}
	return out
}

func TestNothingMissingWhenEverythingIsInstalled(t *testing.T) {
	look := lookFrom(allCommands()...)
	if m := Missing(look); len(m) != 0 {
		t.Fatalf("missing: %v", m)
	}
	if err := Preflight(look); err != nil {
		t.Fatal(err)
	}
}

func TestEverythingMissingOnAFreshSystem(t *testing.T) {
	m := Missing(lookFrom())
	if len(m) != len(Required) {
		t.Fatalf("got %d missing, want %d", len(m), len(Required))
	}
	err := Preflight(lookFrom())
	if err == nil || !strings.Contains(err.Error(), "sudo limbo setup") || !strings.Contains(err.Error(), "virsh (libvirt)") {
		t.Fatalf("the error must name what is missing and how to fix it: %v", err)
	}
}

func TestPackagesAreDeduplicatedAndSorted(t *testing.T) {
	// qemu-img and qemu-system-x86_64 both come from qemu-base.
	got := Packages(Missing(lookFrom()))
	want := []string{"dnsmasq", "libisoburn", "libvirt", "nftables", "openssh", "qemu-base"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOnlyWhatIsMissingIsRequested(t *testing.T) {
	look := lookFrom("virsh", "nft", "ssh", "dnsmasq", "xorriso") // qemu is absent
	got := Packages(Missing(look))
	if !reflect.DeepEqual(got, []string{"qemu-base"}) {
		t.Fatalf("got %v", got)
	}
	if err := Preflight(look); err == nil || strings.Contains(err.Error(), "virsh") {
		t.Fatalf("preflight must only mention the missing commands: %v", err)
	}
}

// Every dependency must name a package, or setup would install nothing for it.
func TestEveryDependencyIsWellFormed(t *testing.T) {
	for _, d := range Required {
		if d.Command == "" || d.Package == "" || d.Purpose == "" {
			t.Errorf("incomplete entry: %+v", d)
		}
		if strings.ContainsAny(d.Package, " ;|&$`") {
			t.Errorf("package name %q could be misread by a shell", d.Package)
		}
	}
}
