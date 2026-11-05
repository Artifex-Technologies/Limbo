// Package settings holds the one choice a person makes about Limbo itself: whether changes to guests made through
// user.sock need their password (docs/SETTINGS_PAGE.md).
//
// The file is root's (/etc/limbo/settings.json). Only root writes it, through the admin socket. Anything unexpected
// about it (unreadable, malformed, not owned by root, writable by others) reads as "ask for the password", which is
// how Limbo has always worked: the switch can only be turned off on purpose, never by accident or by tampering.
package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// DefaultPath is where limbo serve keeps the settings.
const DefaultPath = "/etc/limbo/settings.json"

// Settings is the file's content.
type Settings struct {
	// AskPassword: every change to a guest needs root (sudo or pkexec). On by default. When off, members of the
	// limbo-users group may start and stop their guests and change their processors, memory, disk, shared folder,
	// clipboard and devices through user.sock. Some things need root whatever this says (see the api package).
	AskPassword bool `json:"ask_password"`
}

// Default is today's behaviour.
func Default() Settings { return Settings{AskPassword: true} }

// requireRoot is replaced in tests (which do not run as root).
var requireRoot = true

// Load reads the file. A missing file is the default. Any other problem is returned together with the default, so a
// caller that ignores the error still fails closed.
func Load(path string) (Settings, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return Default(), fmt.Errorf("settings: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Default(), fmt.Errorf("settings: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Default(), fmt.Errorf("settings: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return Default(), fmt.Errorf("settings: %s is writable by others than its owner", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && requireRoot && st.Uid != 0 {
		return Default(), fmt.Errorf("settings: %s is not owned by root", path)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(&limited{f, 4096}); err != nil {
		return Default(), fmt.Errorf("settings: %w", err)
	}
	s := Default()
	dec := json.NewDecoder(&buf)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Default(), fmt.Errorf("settings: %s: %w", path, err)
	}
	return s, nil
}

// Save writes the file atomically (mode 0644: the choice is not secret, and the Settings page may read it).
func Save(path string, s Settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// limited reads at most n bytes: the file is tiny, and a huge one is not ours.
type limited struct {
	f *os.File
	n int64
}

func (l *limited) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("file too large")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.f.Read(p)
	l.n -= int64(n)
	return n, err
}
