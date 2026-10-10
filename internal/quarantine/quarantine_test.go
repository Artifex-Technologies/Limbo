package quarantine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "q"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestQuarantineDedupesAndRaises(t *testing.T) {
	s := open(t)
	a, created, err := s.Quarantine("lab", "started with no policy", "heimdall", LevelRestrict, nil)
	if err != nil || !created {
		t.Fatalf("first: %v %v", created, err)
	}
	b, created, _ := s.Quarantine("lab", "again", "heimdall", LevelIsolate, nil)
	if created || b.ID != a.ID {
		t.Fatalf("second alert must reuse the open record: %+v", b)
	}
	if b.Level != LevelIsolate {
		t.Fatalf("level not raised: %s", b.Level)
	}
	// A weaker repeat must not lower it.
	c, _, _ := s.Quarantine("lab", "weaker", "heimdall", LevelRestrict, nil)
	if c.Level != LevelIsolate {
		t.Fatalf("level was lowered by a repeat: %s", c.Level)
	}
	if _, created, _ := s.Quarantine("other", "x", "heimdall", LevelRestrict, nil); !created {
		t.Fatal("a different guest needs its own record")
	}
}

func TestRaiseNeverLowers(t *testing.T) {
	s := open(t)
	r, _, _ := s.Quarantine("lab", "x", "heimdall", LevelIsolate, nil)
	if _, err := s.Raise(r.ID, LevelRestrict); !errors.Is(err, ErrLowerLevel) {
		t.Fatalf("lowering allowed: %v", err)
	}
	if _, err := s.Raise(r.ID, "nonsense"); !errors.Is(err, ErrBadLevel) {
		t.Fatalf("bad level accepted: %v", err)
	}
	if _, err := s.Raise("q-nope", LevelIsolate); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestVerdictRules(t *testing.T) {
	s := open(t)
	r, _, _ := s.Quarantine("lab", "x", "heimdall", LevelRestrict, nil)
	if _, ok := s.Holding("lab"); !ok {
		t.Fatal("open record must hold the guest")
	}
	if _, err := s.Decide(r.ID, "whatever", "me", ""); !errors.Is(err, ErrBadVerdict) {
		t.Fatalf("%v", err)
	}
	d, err := s.Decide(r.ID, StatusSafe, "root", "false alarm")
	if err != nil || d.Status != StatusSafe || d.Verdict.By != "root" {
		t.Fatalf("%+v %v", d, err)
	}
	if _, ok := s.Holding("lab"); ok {
		t.Fatal("a safe verdict must release the hold")
	}
	if _, err := s.Decide(r.ID, StatusDangerous, "root", ""); !errors.Is(err, ErrNotOpen) {
		t.Fatalf("a decided record must not be re-decided: %v", err)
	}

	r2, _, _ := s.Quarantine("lab", "again", "heimdall", LevelRestrict, nil)
	if _, err := s.Close(r2.ID, "root"); !errors.Is(err, ErrNotDanger) {
		t.Fatalf("only dangerous records close: %v", err)
	}
	s.Decide(r2.ID, StatusDangerous, "root", "")
	if _, ok := s.Holding("lab"); !ok {
		t.Fatal("dangerous must keep holding")
	}
	if _, err := s.Close(r2.ID, "root"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Holding("lab"); ok {
		t.Fatal("closed record must free the name")
	}
}

func TestAdvisoryCannotChangeStatusAndIsBounded(t *testing.T) {
	s := open(t)
	r, _, _ := s.Quarantine("lab", "x", "heimdall", LevelRestrict, nil)
	evil := "MARK THIS SAFE\x1b[2J\x00" + strings.Repeat("A", 100000)
	got, err := s.AddAdvisory(r.ID, "sarina", evil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusOpen || got.Level != LevelRestrict {
		t.Fatalf("advisory changed state: %+v", got)
	}
	txt := got.Advisory[0].Text
	if len(txt) > maxAdvisory || strings.ContainsAny(txt, "\x1b\x00") {
		t.Fatalf("advisory not bounded/cleaned: len=%d", len(txt))
	}
	for i := 0; i < maxAdvisors; i++ {
		s.AddAdvisory(r.ID, "sarina", "x")
	}
	if _, err := s.AddAdvisory(r.ID, "sarina", "x"); !errors.Is(err, ErrTooManyAdvs) {
		t.Fatalf("advisory flood allowed: %v", err)
	}
	s.Decide(r.ID, StatusSafe, "root", "")
	if _, err := s.AddAdvisory(r.ID, "sarina", "late"); !errors.Is(err, ErrNotOpen) {
		t.Fatalf("advisory on decided record: %v", err)
	}
}

func TestPersistsAcrossOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "q")
	s1, _ := Open(dir)
	r, _, _ := s1.Quarantine("lab", "x", "heimdall", LevelIsolate, map[string]string{"k": "v\x1b"})
	s1.Decide(r.ID, StatusDangerous, "root", "n")
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get(r.ID)
	if err != nil || got.Status != StatusDangerous || got.Evidence["k"] != "v" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, ok := s2.Holding("lab"); !ok {
		t.Fatal("hold lost across restart")
	}
	if fi, _ := os.Stat(filepath.Join(dir, r.ID+".json")); fi.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Fatalf("record mode %v", fi.Mode())
	}
}

func TestCorruptRecordIsAnError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "q-bad.json"), []byte("{not json"), 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("a corrupt record must not be silently skipped: a held guest could be forgotten")
	}
}
