//go:build linux

package image

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestMeasureLargeSparseImage is a measurement, not a check: with LIMBO_IMAGE_MEASURE=DIR it makes a sparse image of
// LIMBO_IMAGE_MEASURE_GIB GiB (default 12, about the Windows base) in DIR and prints what a start's image check costs
// before (the full hash every start did: os.Open and io.Copy into SHA-256, the old image.Verify) and after (the
// record's stat path), plus how much of the image each full hash leaves in the page cache. On tmpfs a hole is never
// cached, so measure the cache on a disk filesystem.
func TestMeasureLargeSparseImage(t *testing.T) {
	root := os.Getenv("LIMBO_IMAGE_MEASURE")
	if root == "" {
		t.Skip("set LIMBO_IMAGE_MEASURE=DIR (or tmp: the temp folder) and LIMBO_IMAGE_MEASURE_GIB to measure")
	}
	if root == "tmp" {
		root = os.TempDir()
	}
	gib := int64(12)
	if s := os.Getenv("LIMBO_IMAGE_MEASURE_GIB"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 1 {
			t.Fatalf("LIMBO_IMAGE_MEASURE_GIB=%q", s)
		}
		gib = n
	}
	dir, err := os.MkdirTemp(root, "limbo-image-measure-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(dir, "sparse.qcow2")
	f, err := os.OpenFile(img, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(gib << 30); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chmod(img, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("image: %d GiB sparse file in %s", gib, root)

	// Before: what every start did.
	t0 := time.Now()
	sum := oldVerifyHash(t, img)
	before := time.Since(t0)
	cachedOld := residentPages(t, img)
	dropCache(t, img)

	// After, first start: a full hash (sparing the page cache) that records the proof.
	p := &Proofs{Path: filepath.Join(dir, ProofsFile), Owner: uint32(os.Getuid())}
	t1 := time.Now()
	how, err := p.Check(img, sum)
	first := time.Since(t1)
	if err != nil || how != ByHash {
		t.Fatalf("first check: %q %v", how, err)
	}
	cachedNew := residentPages(t, img)

	// After, every later start: the stat path.
	var ds []time.Duration
	for range 1000 {
		t2 := time.Now()
		how, err := p.Check(img, sum)
		ds = append(ds, time.Since(t2))
		if err != nil || how != ByRecord {
			t.Fatalf("later check: %q %v", how, err)
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	pages := (gib << 30) / int64(os.Getpagesize())
	t.Logf("before, every start (full hash, old code):  %8.0f ms  (%.0f MB/s); left in the page cache: %d of %d pages",
		ms(before), float64(gib<<30)/before.Seconds()/1e6, cachedOld, pages)
	t.Logf("after, first start (full hash, recorded):    %8.0f ms; left in the page cache: %d pages", ms(first), cachedNew)
	t.Logf("after, later starts (stat path), 1000 runs:  median %.3f ms, 99th %.3f ms, max %.3f ms",
		ms(ds[len(ds)/2]), ms(ds[len(ds)*99/100]), ms(ds[len(ds)-1]))
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// oldVerifyHash is the pre-2026-11-09 image.SHA256, kept here only to measure against.
func oldVerifyHash(t *testing.T, path string) string {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// residentPages counts the file's pages in the page cache (mincore on a read-only mapping).
func residentPages(t *testing.T, path string) int {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	data, err := syscall.Mmap(int(f.Fd()), 0, int(fi.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(data)
	ps := os.Getpagesize()
	vec := make([]byte, (len(data)+ps-1)/ps)
	if _, _, e := syscall.Syscall(syscall.SYS_MINCORE, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&vec[0]))); e != 0 {
		t.Fatal(e)
	}
	n := 0
	for _, v := range vec {
		n += int(v & 1)
	}
	return n
}

func dropCache(t *testing.T, path string) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fadvise(int(f.Fd()), 0, 0, fadvDontNeed)
}
