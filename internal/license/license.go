// Package license is the gate in front of Windows guests.
//
// Limbo never downloads, bundles or installs Windows. A Windows guest may only
// be created from an installation ISO and a license record the user supplies,
// and Check is the single place that enforces it: every code path that would
// touch a Windows guest must call it first and stop on error. Without those two
// files Windows support is inert, and until it has been run end to end with
// them, everything Windows-specific in Limbo is UNVERIFIED.
package license

import (
	"errors"
	"fmt"
	"os"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

// ErrWindowsNotConfigured is returned when a Windows guest lacks the
// user-supplied ISO or license file.
var ErrWindowsNotConfigured = errors.New("Windows guest not configured: supply windows.iso and windows.license_file in the manifest")

// Check returns nil for non-Windows guests. For Windows guests it requires both
// files to exist and be non-empty regular files. It does not (and cannot) judge
// whether the license is valid; that remains between the user and Microsoft.
func Check(m *manifest.Manifest) error {
	if m.OS != manifest.OSWindows {
		return nil
	}
	if m.Windows.ISO == "" || m.Windows.LicenseFile == "" {
		return ErrWindowsNotConfigured
	}
	// In this order (a map's order varied, so which missing file was named first did too).
	for _, f := range [][2]string{{"windows.iso", m.Windows.ISO}, {"windows.license_file", m.Windows.LicenseFile}} {
		label, p := f[0], f[1]
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
			return fmt.Errorf("%w (%s %q is missing or empty)", ErrWindowsNotConfigured, label, p)
		}
	}
	return nil
}
