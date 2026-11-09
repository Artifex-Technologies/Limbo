// Package image verifies a guest's base disk before it is used.
//
// A base image is hashed in full once; what that proved is kept in a root-owned record file (proofs.go), and a later
// start skips the hash only while the file is provably the one that was hashed. Every full hash reads the file without
// leaving it in the page cache (a 12 GB image would otherwise push everyone else's cache out).
package image

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// SHA256 streams the file and returns its SHA-256 (lowercase hex), as a manifest's image.sha256 wants it.
func SHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return hashOpen(f)
}

// Verify streams the file and compares its SHA-256 with want (lowercase hex). It always hashes in full; a start goes
// through Proofs.Check, which skips the hash only on a proof.
func Verify(path, want string) error {
	got, err := SHA256(path)
	if err != nil {
		return err
	}
	if got != want {
		return mismatch(path, want, got)
	}
	return nil
}

// ErrMismatch is returned (wrapped) when the file's checksum is not the expected one.
var ErrMismatch = errors.New("image: checksum mismatch")

func mismatch(path, want, got string) error {
	return fmt.Errorf("%w: %s: manifest says %s, file is %s", ErrMismatch, path, want, got)
}

// readChunk is how much is read at a time, and dropChunk how much is read before it is dropped from the page cache.
const (
	readChunk = 1 << 20
	dropChunk = 8 << 20
)

// hashOpen hashes f from its current offset to the end. As it goes it tells the kernel it will not need what it has
// read again (posix_fadvise DONTNEED), so at most a few MiB of the image sit in the page cache at any time instead of
// the whole image, which would evict other programs' cached files. Pages of the file that were cached before (a
// running guest's) are dropped too: they are read again from disk when needed. Go's SHA-256 already runs at disk speed
// or better, so the time saved comes from hashing less often (Proofs), not from hashing faster.
func hashOpen(f *os.File) (string, error) {
	fd := int(f.Fd())
	fadvise(fd, 0, 0, fadvSequential)
	h := sha256.New()
	buf := make([]byte, readChunk)
	var off, kept int64
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			off += int64(n)
			if off-kept >= dropChunk {
				fadvise(fd, kept, off-kept, fadvDontNeed)
				kept = off
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fadvise(fd, 0, 0, fadvDontNeed)
			return "", err
		}
	}
	fadvise(fd, 0, 0, fadvDontNeed) // the tail, and whatever read-ahead fetched past it
	return hex.EncodeToString(h.Sum(nil)), nil
}
