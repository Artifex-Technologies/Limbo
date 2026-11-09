//go:build linux

package wine

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// prefixRecord is what Limbo last set in a prefix, kept beside it (Root/.NAME.json), outside the sandbox: the program
// can change its Windows version itself, but cannot make Limbo believe something else about what Limbo did.
type prefixRecord struct {
	Arch    string    `json:"arch"`
	Windows string    `json:"windows"`
	Updated time.Time `json:"updated"`
}

func readPrefixRecord(path string) (prefixRecord, bool) {
	var r prefixRecord
	b, err := readSmall(path, 4<<10)
	if err != nil || json.Unmarshal(b, &r) != nil {
		return prefixRecord{}, false
	}
	return r, true
}

func writePrefixRecord(path string, r prefixRecord) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'))
}

// prefixExists reports whether Wine has made the prefix (its machine registry exists).
func prefixExists(prefix string) bool {
	fi, err := os.Stat(filepath.Join(prefix, "system.reg"))
	return err == nil && fi.Mode().IsRegular()
}

// prefixArch reads the architecture Wine wrote at the top of the prefix's registry ("#arch=win64"), or "".
func prefixArch(prefix string) string {
	f, err := os.Open(filepath.Join(prefix, "system.reg"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for i := 0; i < 10 && sc.Scan(); i++ {
		if a, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "#arch="); ok {
			return a
		}
	}
	return ""
}

// ErrBusy is a prefix already running in another `limbo wine`.
var ErrBusy = errors.New("prefix in use")

// lockPrefix holds the prefix for one run. Two sandboxes must never share a prefix: each has its own /tmp, so each
// would start its own wineserver on the same registry and corrupt it. The lock file is beside the prefixes, where no
// sandbox can reach it; the lock goes when the process does.
func lockPrefix(d Dirs, name string) (*os.File, error) {
	f, err := os.OpenFile(d.lockFile(name), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		b := make([]byte, 16)
		n, _ := f.ReadAt(b, 0)
		f.Close()
		holder := strings.TrimSpace(string(b[:n]))
		if _, perr := strconv.Atoi(holder); perr != nil {
			holder = "another process"
		} else {
			holder = "pid " + holder
		}
		return nil, fmt.Errorf("wine: prefix %q is already running in another limbo wine (%s), and Wine cannot share a prefix between "+
			"two sandboxes: wait for it to finish (or stop it), or use another --prefix (%w)", name, holder, ErrBusy)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return f, nil
}

// ensureDir makes a directory of Limbo's (mode 0700) and refuses one that is a symlink or not the person's: Limbo
// mounts these into the sandbox, so they must be exactly what they look like.
func ensureDir(p string) error {
	if err := os.MkdirAll(p, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("wine: %s is not a folder (a symlink is not accepted)", p)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("wine: %s belongs to uid %d, not you", p, st.Uid)
	}
	return nil
}

func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

func exists(p string) bool { _, err := os.Lstat(p); return !errors.Is(err, fs.ErrNotExist) }
