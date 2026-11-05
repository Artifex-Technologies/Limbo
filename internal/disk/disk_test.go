package disk

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestVirtualSizeReadsTheQcow2Header(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.qcow2")
	h := make([]byte, 104)
	copy(h, "QFI\xfb")
	binary.BigEndian.PutUint32(h[4:], 3)
	binary.BigEndian.PutUint64(h[24:], 20<<30)
	if err := os.WriteFile(p, h, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := VirtualSize(p)
	if err != nil || n != 20<<30 {
		t.Fatalf("%d %v", n, err)
	}
	raw := filepath.Join(t.TempDir(), "raw")
	os.WriteFile(raw, make([]byte, 64), 0o600)
	if _, err := VirtualSize(raw); err != ErrNotQcow2 {
		t.Fatalf("raw file: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(p, link)
	if _, err := VirtualSize(link); err == nil {
		t.Fatal("followed a link")
	}
}

func TestUsageCountsRegularFilesOnly(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "a"), make([]byte, 8192), 0o600)
	os.MkdirAll(filepath.Join(d, "sub"), 0o700)
	os.WriteFile(filepath.Join(d, "sub", "b"), make([]byte, 8192), 0o600)
	os.Symlink("/usr", filepath.Join(d, "link"))
	if u := Usage(d); u < 16384 || u > 1<<20 {
		t.Fatalf("usage %d", u)
	}
	if Usage(filepath.Join(d, "missing")) != 0 || Allocated(filepath.Join(d, "missing")) != 0 {
		t.Fatal("missing must be 0")
	}
}
