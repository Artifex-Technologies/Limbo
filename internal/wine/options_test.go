package wine

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharesThatAreRefused(t *testing.T) {
	d := testDirs()
	for _, c := range []struct {
		path     string
		writable bool
		why      string
	}{
		{"/", false, "home"},
		{"/home", false, "home"},
		{home, false, "home"},
		{"/proc/self", false, "system"},
		{"/sys", false, "system"},
		{"/dev/input", false, "system"},
		{"/run/user/1000", false, "system"},
		{"/tmp", true, "temporary"},
		{"/var/tmp", false, "temporary"},
		{home + "/.config", false, "hidden"},
		{home + "/.local", false, "hidden"},
		{home + "/.ssh", false, "hidden"},
		{home + "/.ssh/keys", false, "keys"},
		{home + "/.gnupg/private-keys-v1.d", false, "keys"},
		{home + "/.local/share/applications", true, "writable"},
		{home + "/.config/autostart", true, "writable"},
		{d.Root, false, "Limbo"},
		{d.Prefix("other"), false, "Limbo"},
		{home + "/.local/share/limbo", false, "Limbo"},
		{d.Config, true, "Limbo"},
		{d.Config + "/game.json", false, "Limbo"},
		{d.State, false, "Limbo"},
		{d.PrefixCache("game"), true, "Limbo"},
	} {
		err := CheckShare(Share{Path: c.path, Source: c.path, Writable: c.writable}, home, d)
		if err == nil {
			t.Errorf("%s (writable %v) accepted", c.path, c.writable)
			continue
		}
		msg := strings.ToLower(err.Error())
		if want := strings.ToLower(c.why); !strings.Contains(msg, want) {
			t.Errorf("%s: %q does not say %q", c.path, err, c.why)
		}
	}
	for _, c := range []struct {
		path     string
		writable bool
	}{
		{home + "/Downloads", false}, {home + "/Games/Foo", true}, {"/mnt/data/Games", true}, {"/tmp/installer", true},
		{home + "/.cache/winetricks", false}, {home + "/.local/share/Steam/steamapps/common/Game", false},
	} {
		if err := CheckShare(Share{Path: c.path, Source: c.path, Writable: c.writable}, home, d); err != nil {
			t.Errorf("%s refused: %v", c.path, err)
		}
	}
	// The resolved source is checked too: a harmless-looking link to the home is still the home.
	if err := CheckShare(Share{Path: home + "/Games/link", Source: home}, home, d); err == nil {
		t.Error("a link to the home folder accepted")
	}
}

func TestResolveShareFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	sh, err := ResolveShare("link", dir, true)
	if err != nil || sh.Path != filepath.Join(dir, "link") || sh.Source != real || !sh.Writable {
		t.Fatalf("%+v %v", sh, err)
	}
	if _, err := ResolveShare(filepath.Join(dir, "missing"), dir, false); err == nil {
		t.Fatal("a missing share accepted")
	}
}

func TestProfileIsStrict(t *testing.T) {
	for _, bad := range []string{
		`{"netwrk": "host"}`,
		`{"network": "internet-only"}`,
		`{"windows": "win12"}`,
		`{"arch": "arm64"}`,
		`{"env": {"WINEPREFIX": "/x"}}`,
		`{"env": {"HOME": "/x"}}`,
		`{} {}`,
	} {
		if _, err := ParseProfile([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	p, err := ParseProfile([]byte(`{"gpu": false, "share": ["~/Games/Installers"], "share_rw": ["/mnt/x"], "windows": "win7", "program": "C:\\x.exe"}`))
	if err != nil || on(p.GPU) || !on(p.Audio) || p.Windows != "win7" || p.Program != `C:\x.exe` {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestProfileFileMustBeYoursAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "game.json")
	if p, sum, err := LoadProfile(path); p != nil || sum != "" || err != nil {
		t.Fatalf("a missing profile is no profile: %v %q %v", p, sum, err)
	}
	if err := os.WriteFile(path, []byte(`{"network":"host"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, sum, err := LoadProfile(path)
	if err != nil || p.Network != NetHost || len(sum) != 64 {
		t.Fatalf("%+v %q %v", p, sum, err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadProfile(path); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a world-writable profile: %v", err)
	}
}

func TestMergeOrder(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"ro", "rw", "cli"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f := false
	p := &Profile{Network: NetHost, GPU: &f, Share: []string{filepath.Join(dir, "ro")}, ShareRW: []string{filepath.Join(dir, "rw")},
		Env: map[string]string{"DXVK_HUD": "fps", "MANGOHUD": "1"}, Windows: "win7", Trace: true}
	o, err := Merge("game", p, Flags{NoAudio: true, Share: []string{"cli"}, Env: []string{"DXVK_HUD=full"}, Windows: "win11"}, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if o.Network != NetHost || o.GPU || o.Audio || !o.Display || !o.X11 || o.Windows != "win11" || !o.Trace ||
		o.Env["DXVK_HUD"] != "full" || o.Env["MANGOHUD"] != "1" || len(o.Shares) != 3 {
		t.Fatalf("%+v", o)
	}
	writable := map[string]bool{}
	for _, sh := range o.Shares {
		writable[filepath.Base(sh.Path)] = sh.Writable
	}
	if w, ok := writable["ro"]; !ok || w {
		t.Fatalf("shares %+v", o.Shares)
	}
	if w, ok := writable["cli"]; !ok || w {
		t.Fatalf("shares %+v", o.Shares)
	}
	if w, ok := writable["rw"]; !ok || !w {
		t.Fatalf("shares %+v", o.Shares)
	}
	// The same folder read-only in one place and writable in another is a contradiction, not a choice.
	if _, err := Merge("game", &Profile{Share: []string{filepath.Join(dir, "ro")}}, Flags{ShareRW: []string{filepath.Join(dir, "ro")}}, dir, dir); err == nil {
		t.Fatal("ro and rw of one folder accepted")
	}
	// "~/" in a profile is the home folder; any other relative path is refused.
	if o, err := Merge("game", &Profile{Share: []string{"~/ro"}}, Flags{}, "/", dir); err != nil || o.Shares[0].Path != filepath.Join(dir, "ro") {
		t.Fatalf("%+v %v", o.Shares, err)
	}
	if _, err := Merge("game", &Profile{Share: []string{"ro"}}, Flags{}, dir, dir); err == nil {
		t.Fatal("a relative share in a profile accepted")
	}
	// No profile: the defaults.
	o, err = Merge("game", nil, Flags{}, dir, dir)
	if err != nil || o.Network != NetNone || !o.GPU || !o.Audio || !o.Display || !o.X11 || len(o.Shares) != 0 || o.Trace || o.Windows != "" || o.Arch != "" {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestShimPrefixComesOnlyFromLimbosFolder(t *testing.T) {
	d := testDirs()
	for in, want := range map[string]string{"": DefaultPrefix, d.Root + "/steamgame": "steamgame", d.Root + "/tools/": "tools"} {
		if got, err := ShimPrefix(in, d); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{home + "/.wine", home + "/Games/foo", d.Root, d.Root + "/a/b", d.Root + "/.hidden", "relative/path", d.Root + "/../x"} {
		if got, err := ShimPrefix(in, d); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func xauthEntry(family uint16, addr, num, name, data string) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, family)
	for _, f := range []string{addr, num, name, data} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(f)))
		b = append(b, f...)
	}
	return b
}

func TestXauthKeepsOnlyThisDisplayAndForgetsTheHostName(t *testing.T) {
	in := append(append(append(xauthEntry(xauthLocal, "realhost", "0", "MIT-MAGIC-COOKIE-1", "AAAA"),
		xauthEntry(xauthLocal, "realhost", "1", "MIT-MAGIC-COOKIE-1", "BBBB")...),
		xauthEntry(0, "\x0a\x00\x00\x01", "0", "MIT-MAGIC-COOKIE-1", "CCCC")...), // an Internet entry
		xauthEntry(xauthWild, "", "", "MIT-MAGIC-COOKIE-1", "DDDD")...)
	out := FilterXauth(in, 0)
	want := append(xauthEntry(xauthWild, "", "0", "MIT-MAGIC-COOKIE-1", "AAAA"), xauthEntry(xauthWild, "", "", "MIT-MAGIC-COOKIE-1", "DDDD")...)
	if !bytes.Equal(out, want) {
		t.Fatalf("got %q\nwant %q", out, want)
	}
	if bytes.Contains(out, []byte("realhost")) {
		t.Fatal("the host's name reached the sandbox")
	}
	// A damaged file: what parsed before the damage.
	if got := FilterXauth(append(xauthEntry(xauthLocal, "h", "0", "M", "AAAA"), 0x01, 0x00, 0xff), 0); !bytes.Equal(got, xauthEntry(xauthWild, "", "0", "M", "AAAA")) {
		t.Fatalf("damaged: %q", got)
	}
}

func TestTraceSplitsWinesLinesFromTheProgramsOwn(t *testing.T) {
	in := strings.Join([]string{
		"1234.567:0020:0024:trace:loaddll:build_module Loaded L\"C:\\\\windows\\\\system32\\\\kernel32.dll\" : builtin",
		"the program's own error text",
		"0024:err:ole:CoGetClassObject class not registered",
		"0024:fixme:ntdll:NtQuerySystemInformation stub",
		"warning: not a wine line",
	}, "\n") + "\n" + "0028:trace:winsock:connect " + strings.Repeat("x", 100<<10) + "\n" + "tail without newline"
	var trace, other bytes.Buffer
	n, cut := splitTrace(strings.NewReader(in), &trace, &other, TraceLimit)
	if cut || n != int64(trace.Len()) {
		t.Fatalf("n=%d cut=%v len=%d", n, cut, trace.Len())
	}
	if got := other.String(); got != "the program's own error text\nwarning: not a wine line\ntail without newline" {
		t.Fatalf("other: %q", got)
	}
	if lines := strings.Count(trace.String(), "\n"); lines != 4 || !strings.Contains(trace.String(), "winsock:connect xxx") {
		t.Fatalf("trace has %d lines", lines)
	}
	// The cap: what fits, then one line saying it was cut, then nothing.
	trace.Reset()
	other.Reset()
	n, cut = splitTrace(strings.NewReader(strings.Repeat("0024:trace:process:x 0123456789\n", 1000)), &trace, &other, 1000)
	if !cut || !strings.HasSuffix(trace.String(), "[limbo: trace cut here, at its limit]\n") || n > 1100 || other.Len() != 0 {
		t.Fatalf("n=%d cut=%v trace %d bytes, other %d", n, cut, trace.Len(), other.Len())
	}
}

func TestWindowsAndArchNames(t *testing.T) {
	for _, v := range []string{"win11", "win10", "win7", "winxp", "winxp64"} {
		if ValidWindows(v) != nil {
			t.Errorf("%s refused", v)
		}
	}
	for _, v := range []string{"", "win12", "win10; rm", "WIN10"} {
		if ValidWindows(v) == nil {
			t.Errorf("%q accepted", v)
		}
	}
	if ValidArch(ArchWin64) != nil || ValidArch(ArchWin32) != nil || ValidArch("x86") == nil {
		t.Error("arch names")
	}
}
