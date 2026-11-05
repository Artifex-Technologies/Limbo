package license

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "ABCDE-12345-FGHIJ-67890-7K2QF"

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := openStore(filepath.Join(t.TempDir(), "licenses"), false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAddStoresRootOnlyAndShowsOnlyMasked(t *testing.T) {
	s := testStore(t)
	m, err := s.Add("Windows 11 Pro, from my old PC", "abcde-12345-fghij-67890-7k2qf ")
	if err != nil {
		t.Fatal(err)
	}
	if m.Masked != "XXXXX-XXXXX-XXXXX-XXXXX-7K2QF" {
		t.Fatalf("masked = %q", m.Masked)
	}
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "ABCDE") || strings.Contains(string(b), "12345") {
		t.Fatalf("the masked view carries the key: %s", b)
	}
	fi, err := os.Stat(filepath.Join(s.Dir, m.ID+".json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", fi.Mode(), err)
	}
	if di, _ := os.Stat(s.Dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode %v", di.Mode())
	}
	list, _ := s.List()
	if len(list) != 1 || list[0].Assigned == nil {
		t.Fatalf("list: %+v", list)
	}
	k, err := s.Reveal(m.ID)
	if err != nil || k != testKey {
		t.Fatalf("reveal: %q %v", k, err)
	}
}

func TestBadKeysAndNamesAreRefusedWithoutEchoingThem(t *testing.T) {
	s := testStore(t)
	for _, k := range []string{"", "ABCDE-12345", "ABCDE-12345-FGHIJ-67890-7K2Q!", "ABCDE12345FGHIJ678907K2QF"} {
		_, err := s.Add("x", k)
		if err == nil {
			t.Fatalf("key %q accepted", k)
		}
		if k != "" && strings.Contains(err.Error(), k) {
			t.Fatalf("error echoes the key: %v", err)
		}
	}
	// A key typed into the name box.
	if _, err := s.Add("my key "+testKey, testKey); err != ErrBadName {
		t.Fatalf("a name holding a key: %v", err)
	}
	if _, err := s.Add("bell\a", testKey); err != ErrBadName {
		t.Fatalf("control character in name: %v", err)
	}
	if _, err := s.Add("ok", testKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("again", testKey); err != ErrDuplicate {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestAssignMovesAGuestAndUnassigns(t *testing.T) {
	s := testStore(t)
	a, _ := s.Add("a", testKey)
	b, _ := s.Add("b", "BBBBB-12345-FGHIJ-67890-7K2QF")
	if _, err := s.Assign(a.ID, "win11"); err != nil {
		t.Fatal(err)
	}
	if got := s.AssignedTo("win11"); got != a.ID {
		t.Fatalf("assigned to %q", got)
	}
	if _, err := s.Assign(b.ID, "win11"); err != nil {
		t.Fatal(err)
	}
	if got := s.AssignedTo("win11"); got != b.ID {
		t.Fatalf("a guest uses one license; got %q", got)
	}
	if m, _ := s.Get(a.ID); len(m.Assigned) != 0 {
		t.Fatalf("old assignment kept: %v", m.Assigned)
	}
	if k, err := s.KeyForInstall("win11"); err != nil || !strings.HasPrefix(k, "BBBBB") {
		t.Fatalf("install key: %v", err)
	}
	if _, err := s.Unassign(b.ID, "win11"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.KeyForInstall("win11"); err != ErrNoLicense {
		t.Fatalf("no license expected: %v", err)
	}
	if _, err := s.Assign(a.ID, "../x"); err != ErrBadGuest {
		t.Fatalf("bad guest: %v", err)
	}
	if err := s.Remove("lic-00000000"); err != ErrNoLicense {
		t.Fatalf("remove unknown: %v", err)
	}
	if err := s.Remove("../../etc/passwd"); err != ErrNoLicense {
		t.Fatalf("remove path: %v", err)
	}
	if err := s.Remove(a.ID); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesAFolderOthersCanRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lic")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(dir, false); err != ErrUnsafeStore {
		t.Fatalf("got %v", err)
	}
}
