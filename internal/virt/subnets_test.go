package virt

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSubnetsNeverCollide(t *testing.T) {
	s := Subnets{Path: filepath.Join(t.TempDir(), "subnets.json"), InUse: func() map[int]bool { return map[int]bool{} }}
	seen := map[int]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 254; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "g" + itoa(i)
			x, err := s.Allocate(name)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if other, dup := seen[x]; dup {
				t.Errorf("%s and %s both got %d", name, other, x)
			}
			seen[x] = name
		}(i)
	}
	wg.Wait()
	if _, err := s.Allocate("extra"); err != ErrNoSubnet {
		t.Fatalf("255th: %v", err)
	}
	if err := s.Release("g7"); err != nil {
		t.Fatal(err)
	}
	if x, err := s.Allocate("extra"); err != nil || seen[x] != "g7" {
		t.Fatalf("freed subnet not reused: %d %v", x, err)
	}
	if fi, _ := os.Stat(s.Path); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestSubnetsAreStableAndSkipHostInterfaces(t *testing.T) {
	s := Subnets{Path: filepath.Join(t.TempDir(), "subnets.json"), InUse: func() map[int]bool { return map[int]bool{1: true, 2: true} }}
	a, _ := s.Allocate("lab")
	b, _ := s.Allocate("lab")
	if a != 3 || b != 3 {
		t.Fatalf("%d %d", a, b)
	}
	if x, ok := s.Lookup("lab"); !ok || x != 3 {
		t.Fatal("lookup")
	}
	if _, err := s.Allocate("../x"); err == nil {
		t.Fatal("bad name")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
