package deps

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The PKGBUILD advertises the runtime packages as optdepends so Limbo can ship
// without them. If internal/deps gains a package the PKGBUILD does not mention,
// `limbo setup` would install something the package never told anyone about.
func TestPKGBUILDOptdependsCoverEveryRequiredPackage(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "arch", "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	m := regexp.MustCompile(`(?s)optdepends=\((.*?)\n\)`).FindStringSubmatch(text)
	if m == nil {
		t.Fatal("no optdepends block in the PKGBUILD")
	}
	for _, d := range Required {
		if !strings.Contains(m[1], "'"+d.Package+":") {
			t.Errorf("package %q (needed for %s) is missing from the PKGBUILD's optdepends", d.Package, d.Command)
		}
	}
	// ... and they must NOT be hard dependencies, or the point of shipping small is lost.
	dep := regexp.MustCompile(`(?m)^depends=\((.*?)\)`).FindStringSubmatch(text)
	if dep == nil {
		t.Fatal("no depends line in the PKGBUILD")
	}
	for _, d := range Required {
		if strings.Contains(dep[1], "'"+d.Package+"'") {
			t.Errorf("%q is a hard dependency; Limbo is meant to ship without its runtime", d.Package)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", "packaging", "arch", "limbo.install")); err != nil {
		t.Errorf("the PKGBUILD references limbo.install but it is missing: %v", err)
	}
}
