package exchange

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type fakeScanner struct {
	result, sig string
	err         error
	seen        []string
}

func (f *fakeScanner) Scan(_ context.Context, p string) (string, string, error) {
	f.seen = append(f.seen, p)
	return f.result, f.sig, f.err
}

type rec struct{ kinds []string }

func (r *rec) Emit(kind, _ string, _ map[string]string) error {
	r.kinds = append(r.kinds, kind)
	return nil
}

func setup(t *testing.T) (*Service, *fakeScanner, *rec, string) {
	t.Helper()
	d := t.TempDir()
	sc, ev := &fakeScanner{result: Clean}, &rec{}
	s := &Service{Root: filepath.Join(d, "exchange"), Scratch: filepath.Join(d, "state", "scratch"), Held: filepath.Join(d, "state", "held"), Scanner: sc, Events: ev}
	if err := Prepare(s.Root, "lab"); err != nil {
		t.Fatal(err)
	}
	return s, sc, ev, d
}

func TestPrepareMakesARootOnlyOutbox(t *testing.T) {
	s, _, _, _ := setup(t)
	for _, d := range []string{s.Root, s.Outbox("lab")} {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, fi.Mode(), err)
		}
	}
	if err := Prepare(s.Root, "../x"); err == nil {
		t.Fatal("bad name accepted")
	}
}

func TestListShowsOnlyPlainFilesWithSafeNames(t *testing.T) {
	s, _, _, d := setup(t)
	ob := s.Outbox("lab")
	os.WriteFile(filepath.Join(ob, "report.txt"), []byte("hello"), 0o644)
	os.MkdirAll(filepath.Join(ob, "sub"), 0o755)
	os.WriteFile(filepath.Join(ob, "sub", "b.csv"), []byte("1,2"), 0o644)
	os.WriteFile(filepath.Join(ob, "evil\x1b[31m.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(ob, "rtl‮.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(d, "secret"), []byte("host file"), 0o600)
	os.Symlink(filepath.Join(d, "secret"), filepath.Join(ob, "link"))
	l, err := s.List("lab")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Files) != 2 || l.Files[0].Path != "report.txt" || l.Files[1].Path != "sub/b.csv" || l.Unlisted != 3 {
		t.Fatalf("%+v", l)
	}
	if _, err := s.List("other"); err == nil {
		t.Fatal("a guest without an outbox")
	}
}

func TestTakeScansAPrivateCopyAndHandsItOut(t *testing.T) {
	s, sc, ev, _ := setup(t)
	os.WriteFile(filepath.Join(s.Outbox("lab"), "report.txt"), []byte("hello"), 0o644)
	tk, err := s.Take(context.Background(), "lab", "report.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(tk.File)
	if string(b) != "hello" || tk.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("%q %s", b, tk.SHA256)
	}
	if len(sc.seen) != 1 || filepath.Dir(sc.seen[0]) != s.Scratch {
		t.Fatalf("the scan must be of the private copy, not the guest's file: %v", sc.seen)
	}
	tk.Close()
	if ents, _ := os.ReadDir(s.Scratch); len(ents) != 0 {
		t.Fatal("copy left behind")
	}
	if len(ev.kinds) != 1 || ev.kinds[0] != EventFile {
		t.Fatalf("%v", ev.kinds)
	}
}

func TestInfectedFilesAreHeldAndNeverHandedOut(t *testing.T) {
	s, sc, ev, _ := setup(t)
	p := filepath.Join(s.Outbox("lab"), "eicar.com")
	os.WriteFile(p, []byte("X5O!P%@AP"), 0o644)
	sc.result, sc.sig = Infected, "Eicar-Test-Signature"
	_, err := s.Take(context.Background(), "lab", "eicar.com", nil)
	var e *Error
	if !errors.As(err, &e) || e.Code != "infected" {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("still in the outbox")
	}
	held, _ := os.ReadDir(s.Held)
	if len(held) != 1 {
		t.Fatal("not held")
	}
	if ev.kinds[0] != EventHeld {
		t.Fatalf("%v", ev.kinds)
	}
}

func TestNoScanNoFile(t *testing.T) {
	s, sc, ev, _ := setup(t)
	os.WriteFile(filepath.Join(s.Outbox("lab"), "a"), []byte("a"), 0o644)
	sc.err = errors.New("clamd is not running")
	_, err := s.Take(context.Background(), "lab", "a", nil)
	var e *Error
	if !errors.As(err, &e) || e.Code != "scanner_unavailable" {
		t.Fatalf("%v", err)
	}
	if ev.kinds[0] != EventFail {
		t.Fatalf("%v", ev.kinds)
	}
	s.Scanner = nil
	if _, err := s.Take(context.Background(), "lab", "a", nil); err == nil {
		t.Fatal("handed out without a scanner")
	}
}

func TestTakeNeverLeavesTheOutbox(t *testing.T) {
	s, _, _, d := setup(t)
	os.WriteFile(filepath.Join(d, "secret"), []byte("host file"), 0o600)
	os.Symlink(filepath.Join(d, "secret"), filepath.Join(s.Outbox("lab"), "link"))
	os.Symlink("..", filepath.Join(s.Outbox("lab"), "up"))
	syscall.Mkfifo(filepath.Join(s.Outbox("lab"), "fifo"), 0o644)
	for _, p := range []string{"link", "up/secret", "../secret", "/etc/passwd", "./link", "fifo", ""} {
		if tk, err := s.Take(context.Background(), "lab", p, nil); err == nil {
			tk.Close()
			t.Errorf("%q handed out", p)
		}
	}
}
