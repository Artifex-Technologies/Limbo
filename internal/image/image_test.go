package image

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerify(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.img")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if err := Verify(p, abc); err != nil {
		t.Fatalf("good checksum rejected: %v", err)
	}
	if err := Verify(p, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("bad checksum accepted: %v", err)
	}
	if err := Verify(filepath.Join(t.TempDir(), "missing"), abc); err == nil {
		t.Fatal("missing file accepted")
	}
}
