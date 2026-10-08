//go:build linux

package runs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func skippedOf(t *testing.T, m *Manager) []SkippedProfile {
	t.Helper()
	return m.Skipped().([]SkippedProfile)
}

func (e *fakeEvents) count(code string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, c := range e.codes {
		if c == "run.error:"+code {
			n++
		}
	}
	return n
}

// validBody returns the arch-update profile with its image path swapped.
func validBody(t *testing.T, x *env, mutate func(string) string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(x.m.ProfileDir, "arch-update.json"))
	if err != nil {
		t.Fatal(err)
	}
	return mutate(string(b))
}

func put(t *testing.T, x *env, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(x.m.ProfileDir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestValidProfileIsListedAndNotSkipped(t *testing.T) {
	x := setup(t, true)
	if got := x.m.Profiles(); len(got) != 1 || got[0] != "arch-update" {
		t.Fatalf("%v", got)
	}
	sk := skippedOf(t, x.m)
	if sk == nil || len(sk) != 0 {
		t.Fatalf("a valid profile must not be skipped, and the list is never nil: %#v", sk)
	}
}

func TestEachFailureKindIsSkippedWithItsCodeAndNoHostPath(t *testing.T) {
	x := setup(t, true)
	dir := filepath.Dir(x.m.StateDir)
	put(t, x, "broken.json", `{"manifest": `+dir) // malformed JSON that quotes the host path
	put(t, x, "extra.json", `{"bogus":1}`)
	put(t, x, "nodisp.json", validBody(t, x, func(s string) string { return strings.Replace(s, `"disposable":true`, `"disposable":false`, 1) }))
	put(t, x, "relkey.json", validBody(t, x, func(s string) string { return strings.Replace(s, `/etc/limbo/keys/validation`, `keys/validation`, 1) }))
	put(t, x, "badmanifest.json", validBody(t, x, func(s string) string { return strings.Replace(s, `"os":"linux"`, `"os":"linux","extra_field_x":1`, 1) }))
	put(t, x, "gone.json", validBody(t, x, func(s string) string { return strings.Replace(s, dir+"/base.img", dir+"/missing.img", 1) }))
	os.WriteFile(filepath.Join(dir, "other.img"), []byte("not abc"), 0o600)
	put(t, x, "swapped.json", validBody(t, x, func(s string) string { return strings.Replace(s, dir+"/base.img", dir+"/other.img", 1) }))
	put(t, x, "Bad Name.json", "{}")

	want := map[string]string{
		"broken": CodeProfileInvalid, "extra": CodeProfileInvalid, "nodisp": CodeProfileInvalid,
		"relkey": CodeProfileInvalid, "badmanifest": CodeProfileInvalid,
		"gone": CodeImageMissing, "swapped": CodeImageMismatch, "": CodeProfileInvalid,
	}
	got := map[string]string{}
	for _, s := range skippedOf(t, x.m) {
		got[s.Name] = s.Code
		if len(s.Reason) == 0 || len(s.Reason) > 120 || s.Remedy == "" {
			t.Errorf("bad reason/remedy: %+v", s)
		}
		for _, f := range []string{dir, "/", "invalid character", "unknown field \"", "json:", "line "} {
			if strings.Contains(s.Reason, f) || strings.Contains(s.Remedy, f) {
				t.Errorf("%q leaks %q: %+v", s.Name, f, s)
			}
		}
	}
	for n, c := range want {
		if got[n] != c {
			t.Errorf("%q: want %s, got %q (all: %v)", n, c, got[n], got)
		}
	}
	if names := x.m.Profiles(); len(names) != 1 || names[0] != "arch-update" {
		t.Fatalf("only the valid profile is offered: %v", names)
	}
}

func TestSkippedIsCappedAtTwentyWithAMoreEntry(t *testing.T) {
	x := setup(t, true)
	for i := 0; i < 25; i++ {
		put(t, x, fmt.Sprintf("p%02d.json", i), "{")
	}
	sk := skippedOf(t, x.m)
	if len(sk) != 21 {
		t.Fatalf("got %d entries", len(sk))
	}
	last := sk[20]
	if last.Name != "" || last.Code != "more" || last.Reason != "5 more profiles skipped" || last.Remedy != "see the Limbo log or 'limbo doctor'" {
		t.Fatalf("%+v", last)
	}
	if sk[0].Name != "p00" || sk[19].Name != "p19" {
		t.Fatalf("sorted by name: %v ... %v", sk[0], sk[19])
	}
}

func TestSkippedProfileRecoversWhenFixed(t *testing.T) {
	x := setup(t, true)
	good := validBody(t, x, func(s string) string { return s })
	put(t, x, "later.json", "{")
	if sk := skippedOf(t, x.m); len(sk) != 1 || sk[0].Name != "later" {
		t.Fatalf("%+v", sk)
	}
	put(t, x, "later.json", good)
	if sk := skippedOf(t, x.m); len(sk) != 0 {
		t.Fatalf("a fixed profile must leave the list: %+v", sk)
	}
	if got := x.m.Profiles(); len(got) != 2 {
		t.Fatalf("%v", got)
	}
}

func TestAMissingImageComesBackWhenTheImageIsRestored(t *testing.T) {
	x := setup(t, true)
	img := filepath.Join(filepath.Dir(x.m.StateDir), "base.img")
	os.Remove(img)
	if sk := skippedOf(t, x.m); len(sk) != 1 || sk[0].Code != CodeImageMissing || sk[0].Name != "arch-update" {
		t.Fatalf("%+v", sk)
	}
	os.WriteFile(img, []byte("abc"), 0o600)
	if sk := skippedOf(t, x.m); len(sk) != 0 {
		t.Fatalf("%+v", sk)
	}
}

func TestEachDistinctFailureIsLoggedOnceNotPerRequest(t *testing.T) {
	x := setup(t, true)
	put(t, x, "later.json", "{")
	for i := 0; i < 5; i++ {
		x.m.Skipped()
		x.m.Profiles()
	}
	if n := x.ev.count(CodeProfileInvalid); n != 1 {
		t.Fatalf("logged %d times, want once (%v)", n, x.ev.codes)
	}
	// Another failure with the same code on the same file is not a new event.
	put(t, x, "later.json", validBody(t, x, func(s string) string { return strings.Replace(s, `"disposable":true`, `"disposable":false`, 1) }))
	put(t, x, "later.json", validBody(t, x, func(s string) string { return strings.Replace(s, `/etc/limbo/keys/validation`, `x`, 1) }))
	x.m.Skipped()
	x.m.Skipped()
	// Fixed, then broken again: a regression is logged again.
	put(t, x, "later.json", validBody(t, x, func(s string) string { return s }))
	x.m.Skipped()
	put(t, x, "later.json", "{")
	x.m.Skipped()
	if n := x.ev.count(CodeProfileInvalid); n != 2 {
		t.Fatalf("logged %d times, want 2 (%v)", n, x.ev.codes)
	}
}
