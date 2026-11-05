package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func init() { requireRoot = false }

func TestMissingFileAsksForThePassword(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil || !s.AskPassword {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestSaveAndLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "etc", "settings.json")
	if err := Save(p, Settings{AskPassword: false}); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil || s.AskPassword {
		t.Fatalf("%+v %v", s, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

// Anything odd about the file means the password is asked: the switch is only ever off on purpose.
func TestTamperingFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]func(p string){
		"malformed":      func(p string) { os.WriteFile(p, []byte(`{"ask_password": fals`), 0o644) },
		"unknown field":  func(p string) { os.WriteFile(p, []byte(`{"ask_password": false, "x": 1}`), 0o644) },
		"group writable": func(p string) { os.WriteFile(p, []byte(`{"ask_password": false}`), 0o664); os.Chmod(p, 0o664) },
		"world writable": func(p string) { os.WriteFile(p, []byte(`{"ask_password": false}`), 0o646); os.Chmod(p, 0o646) },
		"symlink": func(p string) {
			real := p + ".real"
			os.WriteFile(real, []byte(`{"ask_password": false}`), 0o644)
			os.Symlink(real, p)
		},
		"directory": func(p string) { os.Mkdir(p, 0o755) },
	}
	for name, setup := range cases {
		p := filepath.Join(dir, name+".json")
		setup(p)
		s, err := Load(p)
		if err == nil || !s.AskPassword {
			t.Errorf("%s: %+v %v", name, s, err)
		}
	}
}
