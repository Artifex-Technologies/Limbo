// Package disk answers two questions about a guest's disk files without running anything: how much of the host's
// disk a file really takes, and how big a qcow2 disk looks from inside the guest.
package disk

import (
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Allocated is the space a file takes on the host's disk (its allocated blocks, not its apparent size: a qcow2
// overlay is sparse). 0 for a missing file.
func Allocated(path string) int64 {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return fi.Size()
}

// ErrNotQcow2 is returned for a file that is not a qcow2 image.
var ErrNotQcow2 = errors.New("disk: not a qcow2 image")

// VirtualSize reads the disk size the guest sees from a qcow2 header (bytes 24-31, big-endian, after the "QFI\xfb"
// magic). It never follows a link.
func VirtualSize(path string) (int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var h [32]byte
	if _, err := io.ReadFull(f, h[:]); err != nil {
		return 0, ErrNotQcow2
	}
	if string(h[0:4]) != "QFI\xfb" {
		return 0, ErrNotQcow2
	}
	return int64(binary.BigEndian.Uint64(h[24:32])), nil
}

// maxWalk bounds how many entries Usage looks at, so a folder full of junk cannot make a status request slow.
const maxWalk = 100000

// Usage adds up the allocated space of every regular file under dir, without following links. A missing folder is 0.
func Usage(dir string) int64 {
	var total int64
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		n++
		if n > maxWalk {
			return fs.SkipAll
		}
		if d.Type().IsRegular() {
			total += Allocated(p)
		}
		return nil
	})
	return total
}
