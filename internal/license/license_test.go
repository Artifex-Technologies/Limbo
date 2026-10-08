package license

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	iso, lic, empty := write("w.iso", "x"), write("w.lic", "x"), write("empty", "")

	tests := []struct {
		name    string
		m       manifest.Manifest
		wantErr bool
	}{
		{"linux needs nothing", manifest.Manifest{OS: manifest.OSLinux}, false},
		{"windows with nothing", manifest.Manifest{OS: manifest.OSWindows}, true},
		{"windows missing license", manifest.Manifest{OS: manifest.OSWindows, Windows: manifest.Windows{ISO: iso}}, true},
		{"windows missing file", manifest.Manifest{OS: manifest.OSWindows, Windows: manifest.Windows{ISO: iso, LicenseFile: filepath.Join(dir, "nope")}}, true},
		{"windows empty file", manifest.Manifest{OS: manifest.OSWindows, Windows: manifest.Windows{ISO: iso, LicenseFile: empty}}, true},
		{"windows directory", manifest.Manifest{OS: manifest.OSWindows, Windows: manifest.Windows{ISO: dir, LicenseFile: lic}}, true},
		{"windows configured", manifest.Manifest{OS: manifest.OSWindows, Windows: manifest.Windows{ISO: iso, LicenseFile: lic}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(&tc.m)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrWindowsNotConfigured) {
				t.Fatalf("error does not wrap ErrWindowsNotConfigured: %v", err)
			}
		})
	}
}
