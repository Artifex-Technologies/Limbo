// Package image verifies a guest's base disk before it is used.
package image

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// Verify streams the file and compares its SHA-256 with want (lowercase hex).
// Streaming matters: base images are gigabytes. Called before every define so
// an image swapped or damaged since the manifest was written never boots.
func Verify(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: %s: manifest says %s, file is %s", ErrMismatch, path, want, got)
	}
	return nil
}

// ErrMismatch is returned (wrapped) when the file's checksum is not the expected one.
var ErrMismatch = errors.New("image: checksum mismatch")
