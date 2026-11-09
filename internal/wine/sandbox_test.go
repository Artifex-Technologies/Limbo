package wine

import (
	"strconv"
	"strings"
	"testing"
)

const home = "/home/ada"

// testHost is a described machine: a desktop session with Wayland, Xwayland, PipeWire's PulseAudio socket and an
// NVIDIA card, and a caller environment holding things that must never reach a sandbox.
func testHost() Host {
	etc := map[string]bool{}
	for _, n := range etcAll() {
		etc[n] = true
	}
	return Host{
		UID: 1000, GID: 1000, User: "ada", Group: "ada", Home: home,
		Env: map[string]string{
			"LANG": "en_US.UTF-8", "LC_TIME": "en_GB.UTF-8", "ENABLE_KAIROS": "1", "KAIROS_MULTIPLIER": "2", "DXVK_HUD": "fps",
			"WINEDEBUG": "-all", "MANGOHUD": "1",
			// never passed:
			"GITHUB_TOKEN": "ghp_secret", "AWS_SECRET_ACCESS_KEY": "secret", "SSH_AUTH_SOCK": "/run/user/1000/ssh-agent",
			"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", "LD_PRELOAD": "/home/ada/hook.so",
			"WINEPREFIX": "/home/ada/.wine", "WINEARCH": "win32", "WINESERVER": "/home/ada/bin/wineserver",
			"XDG_CONFIG_HOME": "/home/ada/.config", "PATH": "/home/ada/bin:/usr/local/bin:/usr/bin", "HOME": home,
		},
		RootLinks: map[string]string{"/bin": "usr/bin", "/lib": "usr/lib", "/lib64": "usr/lib", "/sbin": "usr/bin"},
		Etc:       etc, Localtime: "/usr/share/zoneinfo/Europe/London",
		NTSync: true, CPUInfo: true, FontCache: true,
		Wayland: "/run/user/1000/wayland-1", X11Display: 0, X11Socket: "/tmp/.X11-unix/X0", Xauth: []byte("cookie-entries"),
		Pulse: "/run/user/1000/pulse/native", PipeWire: "/run/user/1000/pipewire-0",
		GPUNodes: []string{"/dev/dri", "/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-modeset"},
		GPUSys:   []string{"/sys/devices/pci0000:00/0000:00:02.0/0000:03:00.0", "/sys/dev/char", "/sys/module/nvidia"},
	}
}

func testDirs() Dirs {
	return DefaultDirs(func(string) string { return "" }, home, home+"/.local/state/limbo")
}

func defaults(t *testing.T) Options {
	t.Helper()
	o, err := Merge("game", nil, Flags{}, home, home)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// mount is one filesystem option of bwrap's, as the sandbox will see it.
type mount struct{ op, src, dst string }

// parse reads bwrap's options back. It knows each option's arity and fails on any option it does not know, so a new
// kind of mount cannot slip into the builder unnoticed by these tests.
func parse(t *testing.T, args []string) (flags map[string]string, mounts []mount) {
	t.Helper()
	flags = map[string]string{}
	two := map[string]bool{"--bind": true, "--ro-bind": true, "--dev-bind": true, "--symlink": true, "--ro-bind-data": true}
	one := map[string]bool{"--tmpfs": true, "--dir": true, "--proc": true, "--dev": true, "--perms": true, "--hostname": true, "--chdir": true, "--cap-drop": true}
	none := map[string]bool{"--unshare-user": true, "--disable-userns": true, "--unshare-pid": true, "--unshare-ipc": true, "--unshare-uts": true,
		"--unshare-cgroup-try": true, "--unshare-net": true, "--die-with-parent": true, "--new-session": true}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case two[a]:
			mounts = append(mounts, mount{a, args[i+1], args[i+2]})
			i += 2
		case a == "--tmpfs" || a == "--dir" || a == "--proc" || a == "--dev":
			mounts = append(mounts, mount{a, "", args[i+1]})
			i++
		case one[a]:
			flags[a] = args[i+1]
			i++
		case none[a]:
			flags[a] = "yes"
		default:
			t.Fatalf("unknown bwrap option %q in %v", a, args)
		}
	}
	return flags, mounts
}

func envOf(s *Sandbox) map[string]string {
	m := map[string]string{}
	for _, kv := range s.Env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func build(t *testing.T, o Options, h Host) (*Sandbox, map[string]string, []mount) {
	t.Helper()
	s, err := Build(o, h, testDirs())
	if err != nil {
		t.Fatal(err)
	}
	f, m := parse(t, s.Args)
	return s, f, m
}

func TestDefaultsAreDenyFirst(t *testing.T) {
	d := testDirs()
	s, flags, mounts := build(t, defaults(t), testHost())
	for _, f := range []string{"--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
		"--unshare-net", "--die-with-parent", "--new-session"} {
		if flags[f] != "yes" {
			t.Errorf("missing %s", f)
		}
	}
	if flags["--cap-drop"] != "ALL" || flags["--hostname"] != "limbo" {
		t.Errorf("caps %q hostname %q", flags["--cap-drop"], flags["--hostname"])
	}
	homeTmpfs := false
	for _, m := range mounts {
		switch {
		case m.op == "--tmpfs" && m.dst == home:
			homeTmpfs = true
		case (m.op == "--bind" || m.op == "--ro-bind" || m.op == "--dev-bind") && within(m.src, home):
			// The only things of the person's home in the sandbox: the prefix and the prefix's cache.
			if m.src != d.Prefix("game") && m.src != d.PrefixCache("game") {
				t.Errorf("home path in the sandbox: %v", m)
			}
		}
		if m.op == "--bind" && m.src != d.Prefix("game") && m.src != d.PrefixCache("game") {
			t.Errorf("writable mount other than the prefix and its cache: %v", m)
		}
		for _, never := range []string{"/etc/passwd", "/etc/group", "/etc/hostname", "/etc/machine-id", "/etc/resolv.conf", "/etc/hosts",
			"/run/dbus", "/run/user/1000/bus", "/run/user/1000/ssh-agent", "/var/run", "/sys/class/net", "/home", "/"} {
			if (m.op == "--bind" || m.op == "--ro-bind") && m.src == never {
				t.Errorf("%s is in the sandbox: %v", never, m)
			}
		}
		if (m.op == "--bind" || m.op == "--ro-bind") && within(m.src, "/run/user/1000") &&
			m.src != "/run/user/1000/wayland-1" && m.src != "/run/user/1000/pulse/native" {
			t.Errorf("runtime folder entry beyond the display and sound sockets: %v", m)
		}
	}
	if !homeTmpfs {
		t.Error("the home is not a private tmpfs")
	}
	env := envOf(s)
	for _, k := range []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "LD_PRELOAD", "WINEARCH", "WINESERVER", "XDG_CONFIG_HOME"} {
		if v, ok := env[k]; ok {
			t.Errorf("%s=%s reached the sandbox", k, v)
		}
	}
	for k, want := range map[string]string{"WINEPREFIX": d.Prefix("game"), "HOME": home, "PATH": "/usr/bin", "LANG": "en_US.UTF-8",
		"LC_TIME": "en_GB.UTF-8", "ENABLE_KAIROS": "1", "KAIROS_MULTIPLIER": "2", "DXVK_HUD": "fps", "WINEDEBUG": "-all", "MANGOHUD": "1",
		"XDG_RUNTIME_DIR": "/run/user/1000", "XDG_CACHE_HOME": home + "/.cache"} {
		if env[k] != want {
			t.Errorf("%s=%q, want %q", k, env[k], want)
		}
	}
	if s.Chdir != home {
		t.Errorf("chdir %s", s.Chdir)
	}
}

// The person's account and nobody else's: no other users, no full name, the private home.
func TestPasswdHoldsOnlyThisUser(t *testing.T) {
	s, _, _ := build(t, defaults(t), testHost())
	var passwd, group string
	for _, d := range s.Data {
		switch d.Dest {
		case "/etc/passwd":
			passwd = string(d.Content)
		case "/etc/group":
			group = string(d.Content)
		}
	}
	lines := strings.Split(strings.TrimSpace(passwd), "\n")
	if len(lines) != 3 || lines[1] != "ada:x:1000:1000::/home/ada:/usr/bin/sh" || !strings.HasPrefix(lines[0], "root:") || !strings.HasPrefix(lines[2], "nobody:") {
		t.Fatalf("passwd:\n%s", passwd)
	}
	if !strings.Contains(group, "\nada:x:1000:\n") {
		t.Fatalf("group:\n%s", group)
	}
	// Each data file is on its own descriptor, from fdData up, in order.
	for i, d := range s.Data {
		found := false
		for j := 0; j+2 < len(s.Args); j++ {
			if s.Args[j] == "--ro-bind-data" && s.Args[j+2] == d.Dest && s.Args[j+1] == itoa(fdData+i) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not on descriptor %d: %v", d.Dest, fdData+i, s.Args)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestNoNetworkUnlessAsked(t *testing.T) {
	o := defaults(t)
	_, flags, mounts := build(t, o, testHost())
	if flags["--unshare-net"] != "yes" {
		t.Fatal("network shared by default")
	}
	for _, m := range mounts {
		if strings.HasPrefix(m.src, "/etc/") && (strings.HasSuffix(m.src, "resolv.conf") || strings.HasSuffix(m.src, "hosts")) {
			t.Errorf("name resolution files without network: %v", m)
		}
	}
	o, err := Merge("game", nil, Flags{Network: true}, home, home)
	if err != nil {
		t.Fatal(err)
	}
	_, flags, mounts = build(t, o, testHost())
	if flags["--unshare-net"] == "yes" {
		t.Fatal("--network still unshares the network")
	}
	resolv := false
	for _, m := range mounts {
		resolv = resolv || m.src == "/etc/resolv.conf"
	}
	if !resolv {
		t.Error("--network without /etc/resolv.conf: names would not resolve")
	}
}

func TestSharesExactlyAsGiven(t *testing.T) {
	o := defaults(t)
	o.Shares = []Share{
		{Path: home + "/Games/Foo", Source: "/mnt/data/Games/Foo", Writable: true},
		{Path: home + "/Games", Source: "/mnt/data/Games"},
		{Path: home + "/Downloads/setup.exe", Source: home + "/Downloads/setup.exe"},
	}
	d := testDirs()
	_, _, mounts := build(t, o, testHost())
	var got []mount
	for _, m := range mounts {
		if (m.op == "--bind" || m.op == "--ro-bind") && m.src != d.Prefix("game") && m.src != d.PrefixCache("game") &&
			(within(m.dst, home) || within(m.src, "/mnt")) {
			got = append(got, m)
		}
	}
	// Parents before children, so the writable Foo is not hidden under the read-only Games.
	want := []mount{
		{"--ro-bind", "/mnt/data/Games", home + "/Games"},
		{"--bind", "/mnt/data/Games/Foo", home + "/Games/Foo"},
		{"--ro-bind", home + "/Downloads/setup.exe", home + "/Downloads/setup.exe"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("share %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

func TestGPUNodesOnlyWithGPUOn(t *testing.T) {
	gpuMounts := func(mounts []mount) (nodes, sys, etc int) {
		for _, m := range mounts {
			switch {
			case m.op == "--dev-bind" && (m.src == "/dev/dri" || strings.HasPrefix(m.src, "/dev/nvidia")):
				nodes++
			case m.op == "--ro-bind" && (strings.HasPrefix(m.src, "/sys/devices/pci") || m.src == "/sys/dev/char" || strings.HasPrefix(m.src, "/sys/module")):
				sys++
			case m.op == "--ro-bind" && (m.src == "/etc/vulkan" || m.src == "/etc/glvnd" || m.src == "/etc/egl" || m.src == "/etc/nvidia"):
				etc++
			}
		}
		return
	}
	s, _, mounts := build(t, defaults(t), testHost())
	if n, sys, etc := gpuMounts(mounts); n != 4 || sys != 3 || etc != 4 || !s.GPU {
		t.Fatalf("GPU on: %d nodes, %d sysfs, %d /etc; %v", n, sys, etc, mounts)
	}
	o, _ := Merge("game", nil, Flags{NoGPU: true}, home, home)
	s, _, mounts = build(t, o, testHost())
	if n, sys, etc := gpuMounts(mounts); n+sys+etc != 0 || s.GPU {
		t.Fatalf("GPU off still has %d nodes, %d sysfs, %d /etc", n, sys, etc)
	}
	ntsync := false
	for _, m := range mounts {
		ntsync = ntsync || m.src == "/dev/ntsync"
	}
	if !ntsync {
		t.Error("/dev/ntsync is Wine's, not the graphics card's: it must stay without the GPU")
	}
}

func TestDisplayAndSound(t *testing.T) {
	has := func(mounts []mount, src string) bool {
		for _, m := range mounts {
			if m.src == src {
				return true
			}
		}
		return false
	}
	s, _, mounts := build(t, defaults(t), testHost())
	env := envOf(s)
	if !has(mounts, "/run/user/1000/wayland-1") || !has(mounts, "/tmp/.X11-unix/X0") || !has(mounts, "/run/user/1000/pulse/native") {
		t.Fatalf("display or sound missing: %v", mounts)
	}
	if env["WAYLAND_DISPLAY"] != "wayland-1" || env["DISPLAY"] != ":0" || env["XAUTHORITY"] != "/run/user/1000/Xauthority" ||
		env["PULSE_SERVER"] != "unix:/run/user/1000/pulse/native" || strings.Join(s.Display, ",") != "wayland,x11" || s.Audio != "pulse" {
		t.Fatalf("env %v display %v audio %q", env, s.Display, s.Audio)
	}
	if has(mounts, "/run/user/1000/pipewire-0") {
		t.Error("PipeWire's own socket shared although PulseAudio's is there (it reaches the whole media graph)")
	}

	o, _ := Merge("game", nil, Flags{NoX11: true}, home, home)
	s, _, mounts = build(t, o, testHost())
	if has(mounts, "/tmp/.X11-unix/X0") || envOf(s)["DISPLAY"] != "" || strings.Join(s.Display, ",") != "wayland" {
		t.Fatalf("--no-x11: %v", s.Display)
	}

	o, _ = Merge("tool", nil, Flags{Headless: true}, home, home)
	s, _, mounts = build(t, o, testHost())
	env = envOf(s)
	for _, src := range []string{"/run/user/1000/wayland-1", "/tmp/.X11-unix/X0", "/run/user/1000/pulse/native", "/run/user/1000/pipewire-0"} {
		if has(mounts, src) {
			t.Errorf("headless run has %s", src)
		}
	}
	for _, k := range []string{"WAYLAND_DISPLAY", "DISPLAY", "XAUTHORITY", "PULSE_SERVER"} {
		if env[k] != "" {
			t.Errorf("headless run has %s", k)
		}
	}
	for _, d := range s.Data {
		if strings.Contains(d.Dest, "Xauthority") || strings.Contains(d.Dest, "pulse") {
			t.Errorf("headless run has %s", d.Dest)
		}
	}

	h := testHost()
	h.Pulse = ""
	s, _, mounts = build(t, defaults(t), h)
	if !has(mounts, "/run/user/1000/pipewire-0") || s.Audio != "pipewire" {
		t.Error("without a PulseAudio socket, sound should go through PipeWire's (Wine's ALSA driver)")
	}
}

func TestEnvironmentLimboOwnsIsRefused(t *testing.T) {
	for _, k := range []string{"HOME", "PATH", "WINEPREFIX", "WINEARCH", "DISPLAY", "XDG_RUNTIME_DIR"} {
		if ValidEnvName(k) == nil {
			t.Errorf("--env %s accepted", k)
		}
		if _, err := Merge("game", nil, Flags{Env: []string{k + "=x"}}, home, home); err == nil {
			t.Errorf("Merge accepted --env %s", k)
		}
	}
	for _, bad := range []string{"", "1X", "A-B", "A B"} {
		if ValidEnvName(bad) == nil {
			t.Errorf("%q accepted as a name", bad)
		}
	}
	o, err := Merge("game", nil, Flags{Env: []string{"DXVK_ASYNC=1", "LD_PRELOAD=/usr/lib/libgamemodeauto.so.0"}}, home, home)
	if err != nil {
		t.Fatal(err)
	}
	s, _, _ := build(t, o, testHost())
	if env := envOf(s); env["DXVK_ASYNC"] != "1" || env["LD_PRELOAD"] != "/usr/lib/libgamemodeauto.so.0" {
		t.Fatalf("explicit --env lost: %v", env)
	}
}

func TestBuildRefusesWhatItCannotName(t *testing.T) {
	for _, name := range []string{"", ".hidden", "../up", "UPPER", "a/b", strings.Repeat("x", 49)} {
		o := defaults(t)
		o.Prefix = name
		if _, err := Build(o, testHost(), testDirs()); err == nil {
			t.Errorf("prefix %q accepted", name)
		}
	}
	o := defaults(t)
	o.Network = "internet-only"
	if _, err := Build(o, testHost(), testDirs()); err == nil {
		t.Error("an unbuilt network mode accepted")
	}
}

// The in-sandbox script is a fixed text: the program and its arguments go after it as positional parameters and are
// never part of what the shell parses.
func TestScriptNeverContainsTheProgram(t *testing.T) {
	s, _, _ := build(t, defaults(t), testHost())
	evil := `x"; rm -rf ~; echo "`
	argv := s.Command(script(bodyRun), []string{evil, "$(id)"})
	n := len(argv)
	if argv[n-2] != evil || argv[n-1] != "$(id)" || argv[n-3] != "limbo-wine" || argv[n-5] != "-c" || argv[n-6] != shPath || argv[n-7] != "--" {
		t.Fatalf("argv tail %q", argv[n-7:])
	}
	if strings.Contains(argv[n-4], evil) || !strings.Contains(argv[n-4], `"$@"`) {
		t.Fatalf("script %q", argv[n-4])
	}
	if argv[0] != BwrapPath {
		t.Fatalf("argv[0] %s", argv[0])
	}
}
