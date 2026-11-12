//go:build linux

package wine

// The fixture for the Rust port of `limbo wine` (docs/RUST_PORT.md): what the Go code answers, in
// testdata/parity/wine.json. The parts that do not touch the host are recorded here: names, folders, profiles, the
// merge of a profile with the command line, shares (resolved against a folder tree made for the test, which the Rust
// test makes the same way; "{R}" stands for its root in every input and answer), the X authority filter, the trace
// splitter, the sandbox for hand-written hosts, the dry run, the records, the lock's message. Probe and the runs
// themselves are compared by rust/parity/cli-differential.py on a made-up host.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/parity"
)

// treeEntry is one entry of the folder tree the file cases run in: a folder, a file, a symlink or a named pipe, with
// its mode; a body or link target may hold "{R}".
type treeEntry struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	Body string `json:"body,omitempty"`
	Pad  int    `json:"pad,omitempty"` // a file's body starts with this many spaces
	Mode int    `json:"mode"`
}

const parityHome = "home"

func parityTree() []treeEntry {
	d := func(p string, mode int) treeEntry { return treeEntry{Path: p, Kind: "dir", Mode: mode} }
	f := func(p, body string, mode int) treeEntry {
		return treeEntry{Path: p, Kind: "file", Body: body, Mode: mode}
	}
	l := func(p, target string) treeEntry { return treeEntry{Path: p, Kind: "link", Body: target} }
	w := "home/.local/share/limbo/wine/"
	return []treeEntry{
		d("home", 0o700), d("home/Games", 0o755), d("home/Games/Foo", 0o755), d("home/Downloads", 0o755), d("home/.ssh", 0o700),
		d("home/.config", 0o755), d("home/.config/autostart", 0o755), d("home/.cache", 0o755), d("home/.cache/winetricks", 0o755),
		d("ro", 0o755), d("rw", 0o755), d("cli", 0o755), d("mnt", 0o755), d("mnt/data", 0o755), d("a", 0o755), d("a/b", 0o755),
		d("a/b/c", 0o755), d("x,y%z", 0o755),
		f("file.txt", "hello\n", 0o644), f("prog.exe", "MZ fake program\n", 0o644), f("notdir", "x", 0o644),
		l("link", "ro"), l("abslink", "{R}/rw"), l("homelink", "{R}/home"), l("dangling", "missing"), l("loop", "loop"),
		l("chain", "link"), l("up", "a/b/../../ro"), l("filelink", "file.txt"), l("dotlink", "."), l("a/b/back", "../../cli"),
		l("home/Games/sshlink", "../.ssh"), l("rootlink", "/"),
		{Path: "pipe", Kind: "fifo", Mode: 0o644},
		d("cfg", 0o755), f("cfg/good.json", `{"network":"host"}`, 0o600), f("cfg/ww.json", `{}`, 0o666),
		f("cfg/gw.json", `{}`, 0o620), f("cfg/ow.json", `{}`, 0o602), d("cfg/dir.json", 0o700), {Path: "cfg/big.json", Kind: "file", Body: "{}", Pad: maxProfile, Mode: 0o600},
		{Path: "cfg/fits.json", Kind: "file", Body: "{}", Pad: maxProfile - 2, Mode: 0o600}, f("cfg/bad.json", "{", 0o600), f("cfg/empty.json", "", 0o600),
		f("cfg/two.json", "{} {}", 0o600), f("cfg/closing.json", "{} }", 0o600), f("cfg/full.json",
			`{"network":"none","gpu":false,"audio":true,"display":false,"x11":false,"share":["~/Games"],"share_rw":["/mnt/data"],`+
				`"env":{"DXVK_HUD":"fps"},"windows":"win7","arch":"win32","trace":true,"program":"C:\\x.exe","args":["-a","b c"]}`, 0o644),
		f("cfg/typo.json", `{"gpu":"no"}`, 0o600), f("cfg/unknown.json", `{"netwrk":"host"}`, 0o600), l("cfg/link.json", "good.json"),
		f("cfg/ro.json", `{"trace":true}`, 0o400),
		d("home/.config/limbo", 0o700), d("home/.config/limbo/wine", 0o700),
		f("home/.config/limbo/wine/game.json", `{"share":["~/Games/Foo"],"env":{"DXVK_HUD":"fps"}}`, 0o600),
		d("home/.local", 0o755), d("home/.local/share", 0o755), d("home/.local/share/limbo", 0o700), d(w[:len(w)-1], 0o700),
		d(w+"game", 0o700), f(w+"game/system.reg", "WINE REGISTRY Version 2\n;; All keys relative to \\\\Machine\n\n#arch=win64\n", 0o644),
		d(w+"game/drive_c", 0o755), d(w+"game/drive_c/Program Files", 0o755), d(w+"game/drive_c/Program Files/App", 0o755),
		f(w+"game/drive_c/Program Files/App/app.exe", "MZ app\n", 0o644), l(w+"game/drive_c/out.exe", "{R}/prog.exe"),
		l(w+"game/drive_c/in.exe", "Program Files/App/app.exe"),
		f(w+".game.json", `{"arch":"win64","windows":"win10","updated":"2026-11-08T10:00:00Z"}`+"\n", 0o600),
		d(w+"new", 0o700), d(w+"half", 0o700), f(w+"half/system.reg", "#arch=win64\n", 0o644), f(w+".half.creating", "", 0o600),
		d(w+"w32", 0o700), f(w+"w32/system.reg", "#arch=win32\n", 0o644), d(w+"regdir", 0o700), d(w+"regdir/system.reg", 0o700),
		d("home/.local/state", 0o755), d("home/.local/state/limbo", 0o700),
		d("locks", 0o700), d("runs", 0o700),
	}
}

// makeTree makes the tree in a new temporary folder and returns its root with every symlink resolved.
func makeTree(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range parityTree() {
		p := filepath.Join(root, e.Path)
		body := strings.ReplaceAll(e.Body, "{R}", root)
		var err error
		switch e.Kind {
		case "dir":
			err = os.MkdirAll(p, 0o700)
		case "file":
			err = os.WriteFile(p, []byte(strings.Repeat(" ", e.Pad)+body), 0o600)
		case "link":
			err = os.Symlink(body, p)
		case "fifo":
			err = syscall.Mkfifo(p, 0o600)
		}
		if err == nil && e.Kind != "link" {
			err = os.Chmod(p, os.FileMode(e.Mode))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func hostJSON(h Host) map[string]any {
	return map[string]any{
		"uid": h.UID, "gid": h.GID, "user": h.User, "group": h.Group, "home": h.Home, "env": h.Env,
		"root_links": h.RootLinks, "root_dirs": h.RootDirs, "etc": h.Etc, "localtime": h.Localtime,
		"ntsync": h.NTSync, "cpuinfo": h.CPUInfo, "fontcache": h.FontCache,
		"wayland": h.Wayland, "x11_display": h.X11Display, "x11_socket": h.X11Socket, "xauth": hex.EncodeToString(h.Xauth),
		"xauth_nil": h.Xauth == nil, "pulse": h.Pulse, "pipewire": h.PipeWire, "pulse_cookie": hex.EncodeToString(h.PulseCookie),
		"gpu_nodes": h.GPUNodes, "gpu_sys": h.GPUSys, "driver_dirs": h.DriverDirs,
	}
}

func sharesJSON(shares []Share) []map[string]any {
	out := []map[string]any{}
	for _, sh := range shares {
		out = append(out, map[string]any{"path": sh.Path, "source": sh.Source, "writable": sh.Writable})
	}
	return out
}

func optionsJSON(o Options) map[string]any {
	return map[string]any{"prefix": o.Prefix, "network": o.Network, "gpu": o.GPU, "audio": o.Audio, "display": o.Display,
		"x11": o.X11, "shares": sharesJSON(o.Shares), "env": o.Env, "arch": o.Arch, "windows": o.Windows, "trace": o.Trace}
}

func dirsJSON(d Dirs) map[string]any {
	return map[string]any{"root": d.Root, "cache": d.Cache, "config": d.Config, "state": d.State}
}

func flagsJSON(f Flags) map[string]any {
	return map[string]any{"network": f.Network, "no_gpu": f.NoGPU, "no_audio": f.NoAudio, "no_x11": f.NoX11,
		"no_display": f.NoDisplay, "headless": f.Headless, "share": f.Share, "share_rw": f.ShareRW, "env": f.Env,
		"windows": f.Windows, "arch": f.Arch, "trace": f.Trace}
}

func profileJSON(p *Profile) any {
	if p == nil {
		return nil
	}
	b := func(x *bool) any {
		if x == nil {
			return nil
		}
		return *x
	}
	return map[string]any{"network": p.Network, "gpu": b(p.GPU), "audio": b(p.Audio), "display": b(p.Display), "x11": b(p.X11),
		"share": p.Share, "share_rw": p.ShareRW, "env": p.Env, "windows": p.Windows, "arch": p.Arch, "trace": p.Trace,
		"program": p.Program, "args": p.Args}
}

func sandboxJSON(s *Sandbox, err error) map[string]any {
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	data := []map[string]any{}
	for _, d := range s.Data {
		data = append(data, map[string]any{"dest": d.Dest, "content": hex.EncodeToString(d.Content)})
	}
	display := append([]string{}, s.Display...)
	return map[string]any{"args": append([]string{}, s.Args...), "env": append([]string{}, s.Env...), "data": data, "display": display, "audio": s.Audio, "gpu": s.GPU,
		"chdir": s.Chdir, "error": ""}
}

// unroot puts "{R}" back for the tree's root in an answer.
func unroot(v any, root string) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(bytes.ReplaceAll(b, []byte(root), []byte("{R}")), &out)
	return out
}

func reroot(s, root string) string { return strings.ReplaceAll(s, "{R}", root) }

func rerootAll(l []string, root string) []string {
	if l == nil {
		return nil
	}
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = reroot(s, root)
	}
	return out
}

func xauthBytes(entries ...[]byte) []byte { return bytes.Join(entries, nil) }

// parityHost is a described machine like testHost, with its home at h.
func parityHost(h string) Host {
	host := testHost()
	host.Home = h
	return host
}

func genHost(r *rand.Rand) Host {
	pick := func(p float64) bool { return r.Float64() < p }
	one := func(l ...string) string { return l[r.Intn(len(l))] }
	some := func(l []string) []string {
		var out []string
		for _, s := range l {
			if pick(0.5) {
				out = append(out, s)
			}
		}
		return out
	}
	h := Host{UID: r.Intn(70000), GID: r.Intn(70000), User: one("ada", "bob", "", "a b", "x:y"), Group: one("ada", "users", ""),
		Home: one("/home/ada", "/home/ada", "/", "", "rel/home", "/home/ada/", "/srv/x y", "/home/ada/../bob"),
		Env:  map[string]string{}, RootLinks: map[string]string{}, Etc: map[string]bool{}}
	if h.User == "" && pick(0.7) {
		h.User = "carol"
	}
	pool := []string{"LANG", "LANGUAGE", "TZ", "LC_ALL", "LC_", "WINEDEBUG", "WINE_X", "WINEPREFIX", "HOME", "PATH", "DXVK_HUD",
		"VKD3D_CONFIG", "VK_ICD_FILENAMES", "__GL_SYNC", "__NV_PRIME", "MESA_X", "ENABLE_KAIROS", "DISABLE_LAYER", "KAIROS_M",
		"LABYRINTH_FRAMEGEN_X", "MANGOHUD", "MANGOHUD_CONFIG", "GITHUB_TOKEN", "LD_PRELOAD", "DISPLAY", "PULSE_LATENCY_MSEC",
		"WINEUSERNAME", "WINEESYNC", "XAUTHORITY", "SSH_AUTH_SOCK", "lang", "WINEDLLOVERRIDES", "PULSE_SERVER", "ENABLE"}
	for _, k := range some(pool) {
		h.Env[k] = one("1", "", "a=b", "x y", "é")
	}
	for _, n := range some([]string{"/bin", "/sbin", "/lib", "/lib64", "/lib32"}) {
		h.RootLinks[n] = "usr" + n
	}
	h.RootDirs = some([]string{"/bin", "/lib", "/lib64"})
	h.DriverDirs = some([]string{"/opt/amdgpu/lib", "/opt/x"})
	for _, n := range some(append(etcAll(), "localtime", "passwd")) {
		h.Etc[n] = true
	}
	h.Localtime = one("", "/usr/share/zoneinfo/UTC", "/usr/share/zoneinfo/America/St_Johns")
	h.NTSync, h.CPUInfo, h.FontCache = pick(0.5), pick(0.5), pick(0.5)
	run := "/run/user/" + fmt.Sprint(h.UID)
	h.Wayland = one("", run+"/wayland-0", "/tmp/wl sock", run+"/wayland-1")
	if pick(0.6) {
		h.X11Display = r.Intn(12)
		h.X11Socket = "/tmp/.X11-unix/X" + fmt.Sprint(h.X11Display)
		switch r.Intn(3) {
		case 1:
			h.Xauth = []byte{}
		case 2:
			h.Xauth = []byte{0, 1, 2, 0xff}
		}
	}
	h.Pulse = one("", run+"/pulse/native", "/tmp/pulse-x/native")
	h.PipeWire = one("", run+"/pipewire-0")
	if pick(0.5) {
		h.PulseCookie = []byte("cookie\x00")
	}
	h.GPUNodes = some([]string{"/dev/dri", "/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"})
	h.GPUSys = some([]string{"/sys/devices/pci0000:00/0000:00:02.0", "/sys/dev/char", "/sys/module/nvidia"})
	return h
}

func genOptions(r *rand.Rand) Options {
	pick := func(p float64) bool { return r.Float64() < p }
	one := func(l ...string) string { return l[r.Intn(len(l))] }
	o := Options{Prefix: one("game", "default", "x_1-y", "", "UPPER", ".hidden", "a/b", strings.Repeat("z", 48), strings.Repeat("z", 49)),
		Network: one(NetNone, NetHost, NetNone, "internet-only", ""), GPU: pick(0.7), Audio: pick(0.7), Display: pick(0.7), X11: pick(0.7),
		Env: map[string]string{}, Trace: pick(0.3)}
	for i := r.Intn(3); i > 0; i-- {
		o.Env[one("DXVK_ASYNC", "LD_PRELOAD", "FOO", "WINEDEBUG", "A1")] = one("1", "", "x y")
	}
	if pick(0.1) {
		o.Env[one("HOME", "1X", "A-B", "")] = "bad"
	}
	paths := []string{"/mnt/data", "/mnt/data/games", "/mnt", "/home/ada/Games", "/home/ada/Games/Foo/Bar", "/tmp/i", "/srv/a b"}
	for i := r.Intn(4); i > 0; i-- {
		p := paths[r.Intn(len(paths))]
		src := p
		if pick(0.3) {
			src = "/real" + p
		}
		o.Shares = append(o.Shares, Share{Path: p, Source: src, Writable: pick(0.5)})
	}
	return o
}

func TestParityWine(t *testing.T) {
	var cases []parity.Case
	add := func(fn string, in, out any) { cases = append(cases, parity.Case{Fn: fn, In: in, Out: out}) }
	errs := func(err error) string { return parity.Err(err) }
	r := rand.New(rand.NewSource(20261111))

	// the tree the file cases run in
	add("tree", parityTree(), nil)
	root := makeTree(t)

	// names
	names := []string{"", "game", "default", "a", "0", "-a", "_a", "a-", "a_b-c9", "UPPER", "a.b", ".hidden", "a/b", "../up", "a b",
		strings.Repeat("x", 48), strings.Repeat("x", 49), "é", "a\n", "win10", "win11", "win12", "WIN10", "win10; rm", "vista",
		"winxp64", "win98", "win64", "win32", "x86", "HOME", "PATH", "WINEPREFIX", "XAUTHORITY", "PULSE_COOKIE", "LANG", "LC_ALL",
		"LC_", "WINE_X", "WINEDEBUG", "WINEUSERNAME", "DXVK_HUD", "1X", "A-B", "A B", "_", "_1", "a1", "MANGOHUD", "MANGOHUDX",
		"ENABLE_KAIROS", "KAIROS_X", "LABYRINTH_FRAMEGEN_Y", "__GL_X", "__NV_Y", "MESA_Z", "VK_A", "VKD3D_B", "DISABLE_C", "LD_PRELOAD",
		"GITHUB_TOKEN", "WINEARCH", "WINESERVER", "WINELOADER", "WINEDLLPATH", "PULSE_LATENCY_MSEC", "TZ", "LANGUAGE", "é_X", "Ä"}
	for _, n := range names {
		add("names", n, map[string]any{"name": errs(ValidName(n)), "windows": errs(ValidWindows(n)), "arch": errs(ValidArch(n)),
			"env": errs(ValidEnvName(n)), "pass": passEnv(n), "guest": Guest(n)})
	}

	// folders
	for _, env := range []map[string]string{{}, {"XDG_DATA_HOME": "/d", "XDG_CACHE_HOME": "/c/", "XDG_CONFIG_HOME": "/x/../cfg"},
		{"XDG_DATA_HOME": "rel", "XDG_CACHE_HOME": "./c", "XDG_CONFIG_HOME": "//cfg//"}, {"XDG_DATA_HOME": "/"}} {
		for _, hs := range [][2]string{{"/home/ada", "/home/ada/.local/state/limbo"}, {"/home/ada/", "state/"}, {"", ""}, {"rel", "/s/../t"}} {
			d := DefaultDirs(func(k string) string { return env[k] }, hs[0], hs[1])
			add("dirs", map[string]any{"env": env, "home": hs[0], "state": hs[1]}, map[string]any{"dirs": dirsJSON(d),
				"prefix": d.Prefix("game"), "cache": d.PrefixCache("game"), "profile": d.Profile("game"), "lock": d.lockFile("game"),
				"record": d.recordFile("game"), "creating": d.creatingFile("game"), "runs": RunsDir(d.State)})
		}
	}

	// profiles
	profiles := []string{`{}`, `{"netwrk": "host"}`, `{"network": "internet-only"}`, `{"network": "host"}`, `{"network": ""}`,
		`{"windows": "win12"}`, `{"windows": "win7"}`, `{"arch": "arm64"}`, `{"arch": "win32"}`, `{"env": {"WINEPREFIX": "/x"}}`,
		`{"env": {"HOME": "/x"}}`, `{"env": {"HOME": "/x", "PATH": "/y", "A-B": "z"}}`, `{"env": {"DXVK_HUD": "fps", "1X": "y"}}`,
		`{} {}`, `{} }`, `{}]`, `{} x`, `{}  `, ``, ` `, `{`, `[]`, `null`, `"x"`, `5`, `{"gpu": false, "share": ["~/Games/Installers"], ` +
			`"share_rw": ["/mnt/x"], "windows": "win7", "program": "C:\\x.exe"}`, `{"gpu": null, "audio": true, "display": false, "x11": true}`,
		`{"GPU": false, "Network": "host"}`, `{"gpu": "no"}`, `{"share": "x"}`, `{"share": [1]}`, `{"env": {"A": 1}}`, `{"env": []}`,
		`{"trace": 1}`, `{"args": ["a", null]}`, `{"share": null, "env": null}`, `{"network": "host", "network": "none"}`,
		`{"share": ["/a","/b","/c","/d","/e","/f","/g","/h","/i","/j","/k","/l","/m","/n","/o","/p"], "share_rw": ["/a","/b","/c","/d","/e","/f","/g","/h","/i","/j","/k","/l","/m","/n","/o","/p"]}`,
		`{"share": ["/a","/b","/c","/d","/e","/f","/g","/h","/i","/j","/k","/l","/m","/n","/o","/p","/q"], "share_rw": ["/a","/b","/c","/d","/e","/f","/g","/h","/i","/j","/k","/l","/m","/n","/o","/p"]}`,
		`{"gpu": false, "netwrk": 1}`, `{"netwrk": 1, "gpu": "x"}`, `{"gpu": "x", "netwrk": 1}`, `{"program": "\u00e9\ud800"}`,
		`{"env": {"\u017fX": "1"}}`, `{"ARGS": ["x"], "Program": "y"}`, `{"windows": "win10", "arch": "win64", "network": "x"}`,
		`{"env": {"A": "1", "a": "2"}}`, "{\"program\": \"a\xffb\"}", `{"trace": true, "trace": false}`, `{"x11": false}  ` + "\n",
		`{"gpu": tru}`, `{"gpu": false,}`, `{"gpu"`, `{"gpu":`, `{"gpu": 1e5}`, `{"display": [true]}`}
	for _, doc := range profiles {
		p, err := ParseProfile([]byte(doc))
		add("profile", doc, map[string]any{"profile": profileJSON(p), "error": errs(err)})
	}
	for _, name := range []string{"good", "ww", "gw", "ow", "dir", "big", "fits", "bad", "empty", "two", "closing", "full", "typo", "unknown",
		"link", "ro", "missing"} {
		p, sum, err := LoadProfile(filepath.Join(root, "cfg", name+".json"))
		add("load_profile", "{R}/cfg/"+name+".json", unroot(map[string]any{"profile": profileJSON(p), "sha256": sum, "error": errs(err)}, root))
	}
	for _, path := range []string{"{R}/cfg", "{R}/notdir/x.json", "{R}/loop"} {
		p, sum, err := LoadProfile(reroot(path, root))
		add("load_profile", path, unroot(map[string]any{"profile": profileJSON(p), "sha256": sum, "error": errs(err)}, root))
	}

	// Merge: a profile, the command line, cwd and home, against the tree
	mergeProfiles := []string{"", `{}`, `{"share": ["~/Games/Foo"]}`, `{"share": ["{R}/ro"], "share_rw": ["{R}/rw"], "network": "host", ` +
		`"gpu": false, "env": {"DXVK_HUD": "fps", "MANGOHUD": "1"}, "windows": "win7", "trace": true}`, `{"share": ["ro"]}`,
		`{"share": ["~/missing"]}`, `{"share": ["~"]}`, `{"share": ["~/"]}`, `{"share_rw": ["~/../rw"]}`, `{"display": false, "audio": false, "x11": false, "gpu": true}`,
		`{"share": ["{R}/ro"]}`, `{"share": ["{R}/link"]}`, `{"arch": "win32", "windows": "win81"}`, `{"env": {"A": "1"}}`,
		`{"share": ["{R}/a","{R}/a/b","{R}/a/b/c","{R}/ro","{R}/rw","{R}/cli","{R}/mnt","{R}/mnt/data","{R}/home/Games","{R}/home/Games/Foo","{R}/home/Downloads","{R}/file.txt","{R}/link","{R}/abslink","{R}/chain","{R}/up"]}`}
	mergeFlags := []Flags{{}, {Network: true}, {NoGPU: true, NoAudio: true}, {Headless: true}, {NoDisplay: true, NoX11: true},
		{Windows: "win11", Arch: "win64", Trace: true}, {Share: []string{"cli"}}, {Share: []string{"{R}/rw"}, ShareRW: []string{"{R}/rw"}},
		{ShareRW: []string{"{R}/ro"}}, {Share: []string{"link", "./ro", "{R}/ro/"}}, {Share: []string{"dangling"}}, {Share: []string{"loop"}},
		{Share: []string{"pipe"}}, {Share: []string{"file.txt"}}, {Share: []string{""}}, {Share: []string{"notdir/x"}}, {Share: []string{"filelink"}},
		{Share: []string{"up", "a/b/back", "dotlink", "rootlink"}}, {Env: []string{"DXVK_HUD=full"}}, {Env: []string{"A=1", "A=2", "B="}},
		{Env: []string{"NOEQUALS"}}, {Env: []string{"HOME=/x"}}, {Env: []string{"=x"}}, {Env: []string{"1X=y"}},
		{Env: []string{"A=b=c"}}, {ShareRW: []string{"homelink", "x,y%z"}}, {Share: []string{"a", "a/b", "a/b/c", "mnt", "mnt/data", "ro", "rw", "cli", "x,y%z", "link", "abslink", "chain", "up", "file.txt", "home", "home/Games", "home/Games/Foo"}},
		{Share: []string{"{R}/home/Games/sshlink"}}}
	for _, pdoc := range mergeProfiles {
		for fi, f := range mergeFlags {
			for _, cwdHome := range [][2]string{{"{R}", "{R}/home"}, {"{R}/a", "{R}/a/b"}} {
				if pdoc != "" && pdoc != `{}` && fi%3 != 0 && cwdHome[0] != "{R}" {
					continue
				}
				var p *Profile
				if pdoc != "" {
					var err error
					if p, err = ParseProfile([]byte(reroot(pdoc, root))); err != nil {
						t.Fatal(err)
					}
				}
				ff := f
				ff.Share, ff.ShareRW = rerootAll(f.Share, root), rerootAll(f.ShareRW, root)
				o, err := Merge("game", p, ff, reroot(cwdHome[0], root), reroot(cwdHome[1], root))
				out := map[string]any{"error": errs(err)}
				if err == nil {
					out["options"] = optionsJSON(o)
				}
				add("merge", map[string]any{"profile": pdoc, "flags": flagsJSON(f), "cwd": cwdHome[0], "home": cwdHome[1]}, unroot(out, root))
			}
		}
	}

	// shares: CheckShare against a home and Limbo's folders (no files involved)
	d := testDirs()
	other := DefaultDirs(func(k string) string {
		return map[string]string{"XDG_DATA_HOME": "/data", "XDG_CACHE_HOME": "/home/ada/.cache", "XDG_CONFIG_HOME": "/home/ada/cfg"}[k]
	}, home, "/var/lib/limbo/state")
	sharePaths := []string{"/", "/home", home, home + "/", "/home/ad", "/home/adam", "/home/ada/Games", "/proc", "/proc/self", "/sys", "/sysx",
		"/dev/input", "/devices", "/run/user/1000", "/run", "/runx", "/tmp", "/var/tmp", "/tmp/installer", "/var/tmp/x", home + "/.config",
		home + "/.local", home + "/.ssh", home + "/.ssh/keys", home + "/.gnupg/private-keys-v1.d", home + "/.gnupg", home + "/.local/share/applications",
		home + "/.config/autostart", d.Root, d.Prefix("other"), home + "/.local/share/limbo", d.Config, d.Config + "/game.json", d.State,
		d.PrefixCache("game"), home + "/Downloads", home + "/Games/Foo", "/mnt/data/Games", home + "/.cache/winetricks",
		home + "/.local/share/Steam/steamapps/common/Game", "relative", "/a/../b", "/a/", "", home + "/..x", home + "/...", home + "/.",
		home + "/Games/.hidden", "/data", "/data/limbo/wine/x", home + "/cfg", home + "/cfg/limbo", "/var/lib/limbo", "/var/lib/limbo/state/x",
		home + "/.cache", home + "/.cache/limbo/wine", "/mnt/.ssh"}
	for _, dirs := range []Dirs{d, other, {}} {
		for _, hm := range []string{home, "/", "/home/ada/"} {
			for _, p := range sharePaths {
				for _, wr := range []bool{false, true} {
					for _, src := range []string{p, "/mnt/real"} {
						if hm != home && (src != p || wr) {
							continue
						}
						sh := Share{Path: p, Source: src, Writable: wr}
						add("check_share", map[string]any{"share": sharesJSON([]Share{sh})[0], "home": hm, "dirs": dirsJSON(dirs)},
							map[string]any{"error": errs(CheckShare(sh, hm, dirs)), "within": within(p, hm), "within_rev": within(hm, p)})
					}
				}
			}
		}
	}
	for _, c := range [][2]string{{"/a", "/a"}, {"/a/b", "/a"}, {"/ab", "/a"}, {"/a", "/"}, {"/", "/"}, {"", ""}, {"a", ""}, {"/a", "/a/"}} {
		add("within", c, within(c[0], c[1]))
	}

	// ShimPrefix
	for _, dirs := range []Dirs{d, other} {
		for _, in := range []string{"", d.Root + "/steamgame", d.Root + "/tools/", home + "/.wine", home + "/Games/foo", d.Root, d.Root + "/a/b",
			d.Root + "/.hidden", "relative/path", d.Root + "/../x", d.Root + "/UPPER", d.Root + "//x", d.Root + "/./y", "/data/limbo/wine/z", d.Root + "/" + strings.Repeat("q", 49)} {
			name, err := ShimPrefix(in, dirs)
			add("shim_prefix", map[string]any{"wineprefix": in, "dirs": dirsJSON(dirs)}, map[string]any{"prefix": name, "error": errs(err)})
		}
	}

	// the X authority filter
	xa := [][]byte{
		xauthBytes(xauthEntry(xauthLocal, "realhost", "0", "MIT-MAGIC-COOKIE-1", "AAAA"), xauthEntry(xauthLocal, "realhost", "1", "MIT-MAGIC-COOKIE-1", "BBBB"),
			xauthEntry(0, "\x0a\x00\x00\x01", "0", "MIT-MAGIC-COOKIE-1", "CCCC"), xauthEntry(xauthWild, "", "", "MIT-MAGIC-COOKIE-1", "DDDD")),
		append(xauthEntry(xauthLocal, "h", "0", "M", "AAAA"), 0x01, 0x00, 0xff), nil, {0}, {1, 0}, {1, 0, 0}, {1, 0, 0, 1},
		xauthEntry(xauthLocal, "h", "10", "M", "X"), xauthEntry(xauthLocal, "h", "00", "M", "X"), xauthEntry(6, "", "0", "M", "X"),
		xauthEntry(xauthWild, "addr", "", "", ""), xauthEntry(xauthLocal, strings.Repeat("a", 300), "0", "M", strings.Repeat("d", 1000)),
	}
	for i := 0; i < 60; i++ {
		var b []byte
		for j := r.Intn(4); j > 0; j-- {
			fam := []uint16{xauthLocal, xauthWild, 0, 6, 257}[r.Intn(5)]
			num := []string{"", "0", "1", "12", "x"}[r.Intn(5)]
			b = append(b, xauthEntry(fam, strings.Repeat("h", r.Intn(5)), num, "MIT-MAGIC-COOKIE-1", strings.Repeat("k", r.Intn(20)))...)
		}
		if r.Intn(3) == 0 && len(b) > 0 {
			b = b[:r.Intn(len(b))]
		}
		if r.Intn(4) == 0 {
			junk := make([]byte, r.Intn(12))
			r.Read(junk)
			b = append(b, junk...)
		}
		xa = append(xa, b)
	}
	for _, in := range xa {
		for _, n := range []int{0, 1, 12} {
			add("xauth", map[string]any{"in": hex.EncodeToString(in), "n": n}, hex.EncodeToString(FilterXauth(in, n)))
		}
	}

	// the trace splitter: an input made of parts (text, repeated), a limit
	type part struct {
		Text string `json:"text"`
		N    int    `json:"n"`
	}
	traceInputs := [][]part{
		{{"1234.567:0020:0024:trace:loaddll:build_module Loaded L\"C:\\\\windows\\\\system32\\\\kernel32.dll\" : builtin\n", 1},
			{"the program's own error text\n", 1}, {"0024:err:ole:CoGetClassObject class not registered\n", 1},
			{"0024:fixme:ntdll:NtQuerySystemInformation stub\n", 1}, {"warning: not a wine line\n", 1}, {"0028:trace:winsock:connect ", 1},
			{"x", 100 << 10}, {"\n", 1}, {"tail without newline", 1}},
		{{"0024:trace:process:x 0123456789\n", 1000}},
		{{"", 1}}, {{"\n", 3}}, {{"0024:warn:x\n", 1}}, {{"002:trace:x\n", 1}}, {{"0024:0025:0026:trace:x\n", 1}}, {{"00240:trace:x\n", 1}},
		{{"123456789:trace:x\n", 1}}, {{"0024:TRACE:x\n", 1}}, {{"0024:info:x\n", 1}}, {{"1.:0024:trace:x\n", 1}}, {{".5:0024:trace:x\n", 1}},
		{{"1.5:0024:err:x\n", 1}}, {{"1.5:trace:x\n", 1}}, {{"1.5:00ab:00cd:fixme:x", 1}}, {{"00AB:trace:x\n", 1}}, {{"0024:trace:", 1}},
		{{"0024:trace", 1}}, {{"12345678:abcdef01:err:y\n", 1}}, {{"1.2:3.4:0024:trace:x\n", 1}},
		{{"0024:trace:a", 70000}, {"\nplain\n", 1}}, {{"plain", 70000}, {"\n0024:trace:b\n", 1}},
		{{"0024:trace:", 1}, {"z", 65536 - 11}, {"\n", 1}, {"0024:trace:next\n", 1}},
		{{"0024:trace:", 1}, {"z", 65536 - 12}, {"\n", 1}, {"0024:err:next\n", 1}},
		{{"0024:trace:", 1}, {"z", 65536 - 10}, {"\n", 1}, {"0024:err:next\n", 1}},
		{{"0024:trace:x\r\n", 5}, {"a\x00b\n", 2}, {"\u00e90024:trace:\n", 1}},
		{{"0024:trace:process:x 0123456789\n", 3}, {"other\n", 2}, {"0024:trace:process:y\n", 3}},
	}
	for _, in := range traceInputs {
		var b strings.Builder
		for _, p := range in {
			b.WriteString(strings.Repeat(p.Text, p.N))
		}
		for _, limit := range []int64{TraceLimit, 0, 1, 31, 32, 33, 64, 1000, 65536, 70000, 100 << 10} {
			var trace, other bytes.Buffer
			n, cut := splitTrace(strings.NewReader(b.String()), &trace, &other, limit)
			ts, os := sha256.Sum256(trace.Bytes()), sha256.Sum256(other.Bytes())
			add("split_trace", map[string]any{"parts": in, "limit": limit}, map[string]any{"n": n, "cut": cut,
				"trace": hex.EncodeToString(ts[:]), "trace_len": trace.Len(), "other": hex.EncodeToString(os[:]), "other_len": other.Len()})
		}
	}
	for _, l := range []string{"0024:trace:x", "1234.567:0020:0024:trace:loaddll:", "002:trace:x", "0024:0025:0026:trace:x", "1.5:trace:x",
		"0024:fixme:", "abcd:err:", "ABCD:err:", "abcdefgh:err:", "abcdefghi:err:", "1.2:abcd:abcd:warn:", "1:abcd:warn:", "", "\n"} {
		add("trace_line", l, traceLine.MatchString(l))
	}

	// the sandbox, for hand-written hosts
	hosts := []Host{testHost(), parityHost("/home/ada/"), {UID: 1000, GID: 100, User: "ada", Group: "users", Home: "/home/ada"}}
	h := testHost()
	h.Pulse = ""
	hosts = append(hosts, h)
	h = testHost()
	h.Xauth, h.Localtime, h.Etc = nil, "", map[string]bool{"localtime": true, "ssl": true, "resolv.conf": true}
	hosts = append(hosts, h)
	h = testHost()
	h.Home, h.User = "", "ada"
	hosts = append(hosts, h)
	h = testHost()
	h.Home = "/"
	hosts = append(hosts, h)
	h = testHost()
	h.User = ""
	hosts = append(hosts, h)
	h = testHost()
	h.Home = "relative"
	hosts = append(hosts, h)
	for i := 0; i < 70; i++ {
		hosts = append(hosts, genHost(r))
	}
	optSets := []Options{}
	for _, f := range []Flags{{}, {Network: true}, {NoGPU: true}, {NoX11: true}, {Headless: true}, {NoDisplay: true}, {NoAudio: true},
		{Env: []string{"DXVK_ASYNC=1", "LD_PRELOAD=/usr/lib/libgamemodeauto.so.0", "WINEDEBUG=+all"}}} {
		o, err := Merge("game", nil, f, home, home)
		if err != nil {
			t.Fatal(err)
		}
		optSets = append(optSets, o)
	}
	o := optSets[0]
	o.Shares = []Share{{Path: "/mnt/data/games/x", Source: "/mnt/data/games/x"}, {Path: "/mnt/data", Source: "/srv/data", Writable: true},
		{Path: "/home/ada/Games", Source: "/home/ada/Games"}, {Path: "/mnt/data/games", Source: "/mnt/data/games", Writable: true}, {Path: "/mnt/b/", Source: "/mnt/b"}}
	optSets = append(optSets, o)
	for i := 0; i < 40; i++ {
		optSets = append(optSets, genOptions(r))
	}
	dirSets := []Dirs{d, other}
	for hi, h := range hosts {
		for oi, o := range optSets {
			// the hand-written hosts with the first ten option sets and some generated ones; a generated host with two
			if hi < 9 && oi >= 10 && (hi+oi)%4 != 0 || hi >= 9 && oi != (hi*3)%len(optSets) && oi != (hi*7+1)%len(optSets) {
				continue
			}
			ds := dirSets[(hi+oi)%2]
			s, err := Build(o, h, ds)
			out := sandboxJSON(s, err)
			if err == nil && (hi+oi)%3 == 0 {
				s.SetChdir("/mnt/data/x")
				out["set_chdir"] = append([]string{}, s.Args...)
				out["chdir_after"] = s.Chdir
				out["with_arch"] = s.WithEnv("WINEARCH", "win32")
				out["with_debug"] = s.WithEnv("WINEDEBUG", TraceChannels)
				out["command"] = s.Command(script(bodyRun), []string{`x"; rm -rf ~; echo "`, "$(id)", ""})
			}
			add("build", map[string]any{"host": hostJSON(h), "options": optionsJSON(o), "dirs": dirsJSON(ds)}, out)
		}
	}
	add("scripts", nil, map[string]any{"run": script(bodyRun), "create": script(bodyCreate), "windows": script(bodyWindows),
		"trace_channels": TraceChannels, "trace_limit": TraceLimit})
	for _, s := range []string{"", "a", "abc-_./:=,+@%", "a b", "it's", "'", "$(id)", "a\nb", "é", "--x", "A9", "a*b", "~", "#"} {
		add("quote", s, quote(s))
	}

	// the dry run and the program file, against the tree: the home is {R}/home, Limbo's folders the defaults there
	add("test_host", nil, hostJSON(testHost()))
	rhome := filepath.Join(root, parityHome)
	rdirs := DefaultDirs(func(string) string { return "" }, rhome, filepath.Join(rhome, ".local/state/limbo"))
	programs := []string{"notepad", `C:\Program Files\App\app.exe`, `c:\Program Files\App\app.exe`, `C:\out.exe`, `C:\in.exe`, `C:\missing.exe`,
		`C:\..\..\..\prog.exe`, `C:\`, `C:x.exe`, `D:\x.exe`, "{R}/prog.exe", "{R}/ro/x.exe", "./prog.exe", "prog.exe", "ro/../prog.exe",
		"{R}/home/.local/share/limbo/wine/game/drive_c/Program Files/App/app.exe", "{R}/home/.local/share/limbo/wine/game/drive_c/out.exe",
		"{R}/link/x.exe", "/usr/limbo-parity-missing.exe", ""}
	runFlags := []Flags{{}, {Share: []string{"{R}/ro"}}, {Share: []string{"{R}"}}, {Trace: true, Windows: "win81"}, {Arch: "win32"},
		{Headless: true, Network: true}, {Windows: "bogus"}, {ShareRW: []string{"{R}/home/.ssh"}}, {Share: []string{"{R}/home/Games"}, ShareRW: []string{"{R}/x,y%z"}}}
	for _, prefix := range []string{"game", "new", "half", "w32", "regdir", "absent", "Bad"} {
		for fi, f := range runFlags {
			for pi, prog := range programs {
				if prefix == "game" && (fi+pi)%2 != 0 || prefix != "game" && (fi+pi)%9 != 0 {
					continue
				}
				cwd := []string{"{R}", "{R}/ro", "{R}/home/.local/share/limbo/wine/game/drive_c", "/usr/share", "{R}/link", "{R}/home"}[(fi+pi)%6]
				ff := f
				ff.Share, ff.ShareRW = rerootAll(f.Share, root), rerootAll(f.ShareRW, root)
				o, err := Merge(prefix, nil, ff, reroot(cwd, root), rhome)
				if err != nil {
					t.Fatal(err)
				}
				o.Prefix = prefix
				run := &Run{Options: o, Host: parityHost(rhome), Dirs: rdirs, Program: reroot(prog, root), Args: []string{"/x", "it's", ""}, Cwd: reroot(cwd, root)}
				var b strings.Builder
				err = run.DryRun(&b)
				add("dry_run", map[string]any{"prefix": prefix, "flags": flagsJSON(f), "program": prog, "cwd": cwd},
					unroot(map[string]any{"out": b.String(), "error": errs(err), "program_file": run.programFile()}, root))
			}
		}
	}

	// records
	t1 := time.Date(2026, 11, 11, 8, 0, 0, 123456789, time.UTC)
	t2 := time.Date(2026, 11, 11, 8, 0, 3, 0, time.UTC)
	code0, code3 := 0, 3
	recs := []*Record{
		{ID: "20261111T080000Z-0a1b2c3d", Prefix: "game", Via: "cli", Program: "notepad", Args: []string{}, Cwd: "/home/ada", Started: t1, Status: "running",
			Allowed: allowed(optSets[0], &Sandbox{})},
		{ID: "x", Prefix: "game", Via: "path", Parent: "winetricks", Profile: "/p.json", ProfileSHA256: "ab", Program: `C:\a<b>&.exe`,
			Args: []string{"-x", "é\u2028"}, ProgramPath: "/r/a.exe", ProgramSHA256: "cd", ProgramSize: 5, Cwd: "/c", Arch: "win64", Windows: "win10",
			Started: t1, Ended: &t2, Status: "exited", ExitCode: &code3, Stopped: "interrupt",
			Allowed: allowed(optSets[8], &Sandbox{GPU: true, Display: []string{"wayland", "x11"}, Audio: "pulse"}),
			Trace:   &Trace{File: "/t/trace.log", Channels: TraceChannels, Bytes: 12, Limit: TraceLimit, Truncated: true}},
		{Args: []string{}, Started: time.Time{}, Ended: &t1, ExitCode: &code0, Allowed: allowed(Options{}, &Sandbox{})},
	}
	for _, rec := range recs {
		b, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		add("record", recordJSON(rec), string(b)+"\n")
	}
	for _, pr := range []prefixRecord{{Arch: "win64", Windows: "win10", Updated: t1}, {}} {
		b, _ := json.MarshalIndent(pr, "", "  ")
		add("prefix_record", map[string]any{"arch": pr.Arch, "windows": pr.Windows, "updated": pr.Updated.Format(time.RFC3339Nano)}, string(b)+"\n")
	}
	for _, body := range []string{`{"arch":"win64","windows":"win10","updated":"2026-11-08T10:00:00Z"}`, `{}`, `{"windows":5}`, `{`, ``,
		`{"updated":"yesterday"}`, `{"arch":"win32","x":1}`, `null`, `[]`, `{"Windows":"win7","ARCH":"a"}`, strings.Repeat(" ", 4096) + "{}",
		strings.Repeat(" ", 4094) + "{}", `{"updated":"2026-11-08T10:00:00.5+01:00"}`, `{"windows":"a"} {}`} {
		p := filepath.Join(root, "runs", "rec.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		pr, ok := readPrefixRecord(p)
		add("read_prefix_record", body, map[string]any{"ok": ok, "arch": pr.Arch, "windows": pr.Windows, "updated": pr.Updated.Format(time.RFC3339Nano)})
	}
	for _, c := range []struct {
		pad  int
		body string
	}{{0, "#arch=win64\n"}, {0, "WINE REGISTRY Version 2\n;; x\n\n#arch=win32\n"}, {0, "  #arch=win64  \n"}, {0, "#arch=\n"},
		{0, "#ARCH=win64\n"}, {0, "1\n2\n3\n4\n5\n6\n7\n8\n9\n#arch=late\n"}, {0, "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n#arch=later\n"},
		{0, "#arch=a\n#arch=b\n"}, {0, ""}, {0, "#arch=x"}, {70000, "\n#arch=win64\n"}, {65535, "\n#arch=win64\n"}, {65536, "\n#arch=win64\n"},
		{0, "a\r\n#arch=win64\r\n"}, {0, "#arch=win64 # x\n"}} {
		dir := filepath.Join(root, "runs", "reg")
		_ = os.MkdirAll(dir, 0o700)
		if err := os.WriteFile(filepath.Join(dir, "system.reg"), []byte(strings.Repeat("y", c.pad)+c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		add("prefix_arch", map[string]any{"pad": c.pad, "body": c.body}, prefixArch(dir))
	}

	// text for the event log
	texts := []string{"", "plain", "tab\there", "nl\nx", "\x7f", "\u0085x", "\u200b\u200c\u200d\u200e\u200f", "\u202a\u202e\u202f",
		"\u2066\u2069\u206a", "é", "a\xffb", "\xff\xfe", "\xe2\x82", strings.Repeat("é", 120), strings.Repeat("a", 300) + "é",
		strings.Repeat("a", 199) + "é", "\U0001F600x", "%,a,b%2C", "x\u2028y", "\x00"}
	for _, s := range texts {
		add("clean", hex.EncodeToString([]byte(s)), map[string]any{"200": clean(s, 200), "64": clean(s, 64), "1": clean(s, 1), "0": clean(s, 0),
			"300": clean(s, 300), "512": clean(s, 512)})
	}
	for _, l := range [][]string{nil, {}, {"/a"}, {"/a,b", "/c%d", "/e%2C"}, {"x\ny", strings.Repeat("ü", 300)}, {""}, {"", ""}} {
		hx := []string{}
		for _, s := range l {
			hx = append(hx, hex.EncodeToString([]byte(s)))
		}
		add("path_list", hx, pathList(l))
	}
	for _, s := range []string{":0", ":0.0", "unix:1", ":12.3", ":1234", ":12345", "host:0", "", ":", ":a", "unix:", "localhost:10.0", ":0.", ":0.x",
		"UNIX:0", ":00", ":0001", " :0", ":0 ", "unix:0.12"} {
		n, ok := x11Display(s)
		add("x11_display", s, map[string]any{"n": n, "ok": ok})
	}
	for _, s := range []string{"nvidia0", "nvidia12", "nvidiactl", "nvidia-modeset", "nvidia-uvm", "nvidia-uvm-tools", "nvidia", "nvidia-caps",
		"nvidiax", "nvidia0x", "Nvidia0", "nvidia-uvm-toolsx", "xnvidia0"} {
		add("nvidia_node", s, nvidiaNode.MatchString(s))
	}
	for _, doc := range []string{`{"ICD":{"library_path":"/opt/amdgpu/lib/x.so"}}`, `{"layers":[{"library_path":"a.so"},{"library_path":"/opt/b/../c/l.so"}]}`,
		`{"library_path":5}`, `[{"x":{"library_path":"/p"}}]`, `"library_path"`, `{"library_path":"/a","LIBRARY_PATH":"/b","y":["/c",{"library_path":"/d"}]}`} {
		var v any
		_ = json.Unmarshal([]byte(doc), &v)
		paths := libraryPaths(v)
		sort.Strings(paths)
		add("library_paths", doc, paths)
	}

	// the lock's message when another run holds the prefix, by what the holder wrote
	ld := Dirs{Root: filepath.Join(root, "locks")}
	for i, body := range []string{"1234\n", "", "abc", " 42 ", "+7", "-3", "12345678901234567890", "0x10", "123\n456", "99999999999999999999\n"} {
		name := fmt.Sprintf("l%d", i)
		f, err := os.OpenFile(ld.lockFile(name), os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(body); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		_, err = lockPrefix(ld, name)
		f.Close()
		add("lock_busy", map[string]any{"name": name, "body": body}, unroot(errs(err), root))
	}
	for _, p := range []string{"{R}/ensure/new/deep", "{R}/ro", "{R}/link", "{R}/file.txt", "{R}/notdir/x", "{R}/dangling", "{R}/loop"} {
		add("ensure_dir", p, unroot(errs(ensureDir(reroot(p, root))), root))
	}
	for _, c := range []struct {
		names []string
		keep  int
	}{{[]string{"20261111T080000Z-aa", "20261110T080000Z-bb", "20261112T080000Z-cc"}, 2},
		{[]string{"20261111T080000Z-aa", "short", "20261111X080000Z-bb", "20261111T08000", "20261111T080000Z", "20261111T080000Z-"}, 0},
		{[]string{"b20261111T08000000", "a2026111T080000000", "20261111T080000Z-x"}, 1}} {
		dir := filepath.Join(root, "runs", fmt.Sprint(c.keep, len(c.names)))
		for _, n := range c.names {
			if err := os.MkdirAll(filepath.Join(dir, n), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		_ = os.WriteFile(filepath.Join(dir, "20261111T080000Z-file"), nil, 0o600)
		pruneRuns(dir, c.keep)
		ents, _ := os.ReadDir(dir)
		left := []string{}
		for _, e := range ents {
			left = append(left, e.Name())
		}
		add("prune_runs", map[string]any{"names": c.names, "keep": c.keep}, left)
	}
	parity.Fixture(t, "wine", cases)
}

func recordJSON(r *Record) map[string]any {
	m := map[string]any{"id": r.ID, "prefix": r.Prefix, "via": r.Via, "parent": r.Parent, "profile": r.Profile, "profile_sha256": r.ProfileSHA256,
		"program": r.Program, "args": r.Args, "program_path": r.ProgramPath, "program_sha256": r.ProgramSHA256, "program_size": r.ProgramSize,
		"cwd": r.Cwd, "arch": r.Arch, "windows": r.Windows, "started": r.Started.Format(time.RFC3339Nano), "status": r.Status, "stopped": r.Stopped,
		"allowed": map[string]any{"network": r.Allowed.Network, "gpu": r.Allowed.GPU, "display": r.Allowed.Display, "audio": r.Allowed.Audio,
			"shares": r.Allowed.Shares, "env": r.Allowed.Env}}
	if r.Ended != nil {
		m["ended"] = r.Ended.Format(time.RFC3339Nano)
	}
	if r.ExitCode != nil {
		m["exit_code"] = *r.ExitCode
	}
	if r.Trace != nil {
		m["trace"] = map[string]any{"file": r.Trace.File, "channels": r.Trace.Channels, "bytes": r.Trace.Bytes, "limit": r.Trace.Limit, "truncated": r.Trace.Truncated}
	}
	return m
}
