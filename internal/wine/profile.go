package wine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// Profile is a prefix's own settings: ~/.config/limbo/wine/NAME.json, written by the person. It lives outside every
// sandbox (no share may overlap that folder), so a program can never rewrite the rules it runs under. Every field is
// optional and a missing one is the restrictive default, except that the display, sound and graphics card are on
// unless switched off (a desktop program needs them). Unknown fields are refused, so a typo in a setting cannot quietly
// fall back to a default.
type Profile struct {
	Network string            `json:"network,omitempty"` // "none" (default) or "host"
	GPU     *bool             `json:"gpu,omitempty"`
	Audio   *bool             `json:"audio,omitempty"`
	Display *bool             `json:"display,omitempty"`
	X11     *bool             `json:"x11,omitempty"`
	Share   []string          `json:"share,omitempty"`    // read-only
	ShareRW []string          `json:"share_rw,omitempty"` // writable
	Env     map[string]string `json:"env,omitempty"`
	Windows string            `json:"windows,omitempty"` // the Windows version the prefix reports (default win10)
	Arch    string            `json:"arch,omitempty"`    // "win64" (default) or "win32", when the prefix is made
	Trace   bool              `json:"trace,omitempty"`   // record Wine's behaviour trace in each run's folder
	Program string            `json:"program,omitempty"` // what `limbo wine --prefix NAME` runs with no program given
	Args    []string          `json:"args,omitempty"`
}

// maxProfile bounds a profile file.
const maxProfile = 64 << 10

// LoadProfile reads a prefix's profile. A missing file is no profile (nil, "", nil). The file must be the person's own
// and not writable by anyone else: whoever can write it decides what the sandbox may reach. The second value is the
// file's SHA-256, for the run record.
func LoadProfile(path string) (*Profile, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, "", fmt.Errorf("wine: profile %s is not yours (owner uid %d); whoever can write it decides what the sandbox may reach", path, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, "", fmt.Errorf("wine: profile %s is writable by others (%v); chmod go-w it", path, fi.Mode().Perm())
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxProfile {
		return nil, "", fmt.Errorf("wine: profile %s is not a regular file under %d KiB", path, maxProfile>>10)
	}
	b := make([]byte, fi.Size())
	if _, err := f.ReadAt(b, 0); err != nil && fi.Size() > 0 {
		return nil, "", err
	}
	p, err := ParseProfile(b)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	sum := sha256.Sum256(b)
	return p, hex.EncodeToString(sum[:]), nil
}

// ParseProfile decodes and checks a profile.
func ParseProfile(b []byte) (*Profile, error) {
	var p Profile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("wine profile: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("wine profile: more than one JSON value")
	}
	if p.Network != "" && p.Network != NetNone && p.Network != NetHost {
		return nil, fmt.Errorf("wine profile: network must be %q or %q (finer network rules are not built yet)", NetNone, NetHost)
	}
	if p.Windows != "" {
		if err := ValidWindows(p.Windows); err != nil {
			return nil, err
		}
	}
	if p.Arch != "" {
		if err := ValidArch(p.Arch); err != nil {
			return nil, err
		}
	}
	for k := range p.Env {
		if err := ValidEnvName(k); err != nil {
			return nil, err
		}
	}
	if len(p.Share)+len(p.ShareRW) > maxShares {
		return nil, fmt.Errorf("wine profile: more than %d shares", maxShares)
	}
	return &p, nil
}

// on reads an optional switch whose default is on.
func on(b *bool) bool { return b == nil || *b }
