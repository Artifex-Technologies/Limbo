package wine

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Host is everything about this machine and session the sandbox is built from. Probe gathers it; tests write it by
// hand, so the builder never looks at the machine it runs on.
type Host struct {
	UID, GID    int
	User, Group string // login and primary group names
	Home        string
	Env         map[string]string // the caller's environment; only the names passEnv allows reach the sandbox

	RootLinks map[string]string // merged-/usr links at / ("/bin" -> "usr/bin")
	RootDirs  []string          // the same names when they are real directories (bound read-only)
	Etc       map[string]bool   // which of etcAll exist
	Localtime string            // /etc/localtime's link target, or "" (a plain file is bound as one)
	NTSync    bool              // /dev/ntsync: Wine 11's fast synchronization
	CPUInfo   bool              // /sys/devices/system/cpu: processor topology for Wine
	FontCache bool              // /var/cache/fontconfig

	Wayland     string // host path of the Wayland socket, or ""
	X11Display  int    // the X display number when X11Socket is set
	X11Socket   string // /tmp/.X11-unix/X<n>, or ""
	Xauth       []byte // the X authority entries for that display, rewritten (see FilterXauth), or nil
	Pulse       string // host path of the PulseAudio socket (PipeWire serves it), or ""
	PipeWire    string // host path of PipeWire's own socket, used only when there is no PulseAudio socket
	PulseCookie []byte // ~/.config/pulse/cookie, for a real PulseAudio server (PipeWire ignores it)

	GPUNodes   []string // /dev/dri and /dev/nvidia* nodes
	GPUSys     []string // sysfs the drivers read: /sys/dev/char, the cards' own device folders, /sys/module/nvidia*
	DriverDirs []string // folders outside /usr that the system's Vulkan/EGL driver files point into (under /opt)
}

// Sandbox is one run's bubblewrap invocation, without the command.
type Sandbox struct {
	Args []string   // bwrap's options, up to (not including) "--"
	Env  []string   // the whole environment bwrap and everything in the sandbox get
	Data []DataFile // files handed to bwrap on descriptors, in ExtraFiles order from fdData
	// What was shared, for the event log and the run record.
	Display []string // "wayland", "x11"
	Audio   string   // "pulse", "pipewire" or ""
	GPU     bool     // graphics nodes were given
	Chdir   string
}

// DataFile is content bwrap copies into the sandbox read-only (--ro-bind-data): files Limbo writes rather than takes
// from the host (a passwd with only this user, the X authority for one display, ...).
type DataFile struct {
	Dest    string
	Content []byte
}

// Descriptors the runner passes to bwrap: the stop pipe (the in-sandbox script reads it), the started pipe (the script
// writes one byte to it first thing, so limbo knows the sandbox was set up and the script ran), then the data files.
const (
	fdStop    = 3
	fdStarted = 4
	fdData    = 5
)

// runtimeDir is XDG_RUNTIME_DIR inside the sandbox: a private folder holding only the sockets Limbo puts there.
func runtimeDir(uid int) string { return "/run/user/" + strconv.Itoa(uid) }

// The /etc entries Limbo may bind, by what needs them. Everything else under /etc (the host's name, its users' details,
// its network setup, its machine ID, its keys) stays out.
var (
	etcBase  = []string{"ld.so.cache", "ld.so.conf", "ld.so.conf.d", "fonts", "nsswitch.conf", "ssl", "ca-certificates", "pki"}
	etcAudio = []string{"pulse", "alsa", "asound.conf"}
	etcGPU   = []string{"vulkan", "glvnd", "egl", "nvidia", "drirc", "drirc.d"}
	etcNet   = []string{"resolv.conf", "hosts", "host.conf", "gai.conf", "services", "protocols"}
)

// etcAll is every name Probe looks for.
func etcAll() []string {
	return append(append(append(append([]string(nil), etcBase...), etcAudio...), etcGPU...), etcNet...)
}

// Environment the caller may pass into the sandbox: locale and time zone, Wine's own debugging and tuning switches,
// and the graphics stack's (DXVK, VKD3D, Vulkan, NVIDIA, Mesa, Vulkan layers' on/off switches such as Kairos's
// ENABLE_KAIROS and MangoHud's MANGOHUD). Nothing else: tokens and keys people keep in their environment stay out.
var (
	passNames = map[string]bool{"LANG": true, "LANGUAGE": true, "TZ": true, "PULSE_LATENCY_MSEC": true,
		"WINEDEBUG": true, "WINEDLLOVERRIDES": true, "WINEESYNC": true, "WINEFSYNC": true, "WINENTSYNC": true, "WINEUSERNAME": true}
	passPrefixes = []string{"LC_", "WINE_", "DXVK_", "VKD3D_", "VK_", "__GL_", "__NV_", "MESA_", "ENABLE_", "DISABLE_",
		"KAIROS_", "LABYRINTH_FRAMEGEN_", "MANGOHUD"}
	// reservedEnv are Limbo's to set: the sandbox's layout depends on them, so neither the caller's environment nor
	// --env may change them.
	reservedEnv = map[string]bool{"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
		"WINEPREFIX": true, "WINEARCH": true, "WINESERVER": true, "WINELOADER": true, "WINEDLLPATH": true,
		"XDG_RUNTIME_DIR": true, "XDG_CACHE_HOME": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true,
		"WAYLAND_DISPLAY": true, "DISPLAY": true, "XAUTHORITY": true, "PULSE_SERVER": true, "PULSE_COOKIE": true}
)

func passEnv(name string) bool {
	if reservedEnv[name] {
		return false
	}
	if passNames[name] {
		return true
	}
	for _, p := range passPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ValidEnvName checks a name given with --env or in a profile.
func ValidEnvName(name string) error {
	if name == "" || strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != "" || (name[0] >= '0' && name[0] <= '9') {
		return fmt.Errorf("wine: %q is not an environment variable name", name)
	}
	if reservedEnv[name] {
		return fmt.Errorf("wine: %s is set by Limbo (the sandbox's layout depends on it)", name)
	}
	return nil
}

// Build turns a run's options into bwrap's options. Deny-first: what is not added here is not in the sandbox. The
// order matters to bwrap (later mounts go on top of earlier ones): system, devices, /tmp, /etc, the private home, the
// prefix's cache and the prefix, then the shares, parents before children.
func Build(o Options, h Host, d Dirs) (*Sandbox, error) {
	if err := ValidName(o.Prefix); err != nil {
		return nil, err
	}
	if o.Network != NetNone && o.Network != NetHost {
		return nil, fmt.Errorf("wine: network must be %q or %q", NetNone, NetHost)
	}
	if !filepath.IsAbs(h.Home) || h.Home == "/" || h.User == "" {
		return nil, fmt.Errorf("wine: no usable home folder or user name (home %q, user %q)", h.Home, h.User)
	}
	s := &Sandbox{}
	a := func(args ...string) { s.Args = append(s.Args, args...) }
	data := func(dest string, content []byte) {
		a("--ro-bind-data", strconv.Itoa(fdData+len(s.Data)), dest)
		s.Data = append(s.Data, DataFile{Dest: dest, Content: content})
	}
	etc := func(names []string) {
		for _, n := range names {
			if h.Etc[n] {
				a("--ro-bind", "/etc/"+n, "/etc/"+n)
			}
		}
	}

	// Isolation. Each namespace except the network's is always new; --disable-userns stops anything inside making
	// namespaces of its own; --new-session takes the terminal away (no TIOCSTI typing into the person's shell);
	// --die-with-parent ends everything inside when limbo ends. bwrap also sets no_new_privs and mounts nosuid, so
	// setuid programs in /usr gain nothing.
	a("--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try")
	if o.Network != NetHost {
		a("--unshare-net")
	}
	a("--die-with-parent", "--new-session", "--cap-drop", "ALL", "--hostname", "limbo")

	// The system, read-only.
	a("--ro-bind", "/usr", "/usr")
	for _, name := range sortedKeys(h.RootLinks) {
		a("--symlink", h.RootLinks[name], name)
	}
	for _, dir := range h.RootDirs {
		a("--ro-bind", dir, dir)
	}
	for _, dir := range h.DriverDirs {
		a("--ro-bind", dir, dir)
	}
	a("--proc", "/proc", "--dev", "/dev")
	if h.NTSync {
		a("--dev-bind", "/dev/ntsync", "/dev/ntsync")
	}
	if o.GPU {
		for _, n := range h.GPUNodes {
			a("--dev-bind", n, n)
		}
		for _, p := range h.GPUSys {
			a("--ro-bind", p, p)
		}
		s.GPU = len(h.GPUNodes) > 0
	}
	if h.CPUInfo {
		a("--ro-bind", "/sys/devices/system/cpu", "/sys/devices/system/cpu")
	}
	a("--tmpfs", "/tmp")

	etc(etcBase)
	if h.Localtime != "" {
		a("--symlink", h.Localtime, "/etc/localtime")
	} else if h.Etc["localtime"] {
		a("--ro-bind", "/etc/localtime", "/etc/localtime")
	}
	if o.GPU {
		etc(etcGPU)
	}
	if o.Audio {
		etc(etcAudio)
	}
	if o.Network == NetHost {
		etc(etcNet)
	}
	// Only this user (and root and nobody, which programs expect to exist): no other accounts, no full name.
	data("/etc/passwd", []byte(fmt.Sprintf("root:x:0:0::/root:/usr/bin/nologin\n%s:x:%d:%d::%s:/usr/bin/sh\nnobody:x:65534:65534::/:/usr/bin/nologin\n",
		h.User, h.UID, h.GID, h.Home)))
	data("/etc/group", []byte(fmt.Sprintf("root:x:0:\n%s:x:%d:\nnobody:x:65534:\n", h.Group, h.GID)))
	if h.FontCache {
		a("--ro-bind", "/var/cache/fontconfig", "/var/cache/fontconfig")
	}

	// A private home: an empty tmpfs at the real home's path, so paths look ordinary and shares appear where they are on
	// the host. Nothing of the real home is in it.
	run := runtimeDir(h.UID)
	a("--perms", "0700", "--tmpfs", h.Home, "--perms", "0700", "--dir", run)
	env := map[string]string{}
	for k, v := range h.Env {
		if passEnv(k) {
			env[k] = v
		}
	}

	if o.Display && h.Wayland != "" {
		name := filepath.Base(h.Wayland)
		a("--ro-bind", h.Wayland, run+"/"+name)
		env["WAYLAND_DISPLAY"] = name
		s.Display = append(s.Display, "wayland")
	}
	if o.Display && o.X11 && h.X11Socket != "" {
		// Xwayland's socket in the private /tmp. Its abstract twin is not reachable from a new network namespace.
		a("--ro-bind", h.X11Socket, h.X11Socket)
		env["DISPLAY"] = ":" + strconv.Itoa(h.X11Display)
		if len(h.Xauth) > 0 {
			data(run+"/Xauthority", h.Xauth)
			env["XAUTHORITY"] = run + "/Xauthority"
		}
		s.Display = append(s.Display, "x11")
	}
	if o.Audio {
		switch {
		case h.Pulse != "":
			a("--ro-bind", h.Pulse, run+"/pulse/native")
			env["PULSE_SERVER"] = "unix:" + run + "/pulse/native"
			if len(h.PulseCookie) > 0 {
				data(run+"/pulse/cookie", h.PulseCookie)
				env["PULSE_COOKIE"] = run + "/pulse/cookie"
			}
			s.Audio = "pulse"
		case h.PipeWire != "":
			// Wine has no PipeWire driver; its ALSA driver reaches PipeWire through PipeWire's ALSA plugin.
			a("--ro-bind", h.PipeWire, run+"/pipewire-0")
			s.Audio = "pipewire"
		}
	}

	// The prefix's own cache (shader caches, Wine's downloads) as the sandbox's ~/.cache, then the prefix at its real
	// path, so the same WINEPREFIX names it inside and outside (host tools such as winetricks agree with the sandbox).
	prefix := d.Prefix(o.Prefix)
	a("--bind", d.PrefixCache(o.Prefix), filepath.Join(h.Home, ".cache"))
	a("--bind", prefix, prefix)

	shares := append([]Share(nil), o.Shares...)
	sort.SliceStable(shares, func(i, j int) bool { return depth(shares[i].Path) < depth(shares[j].Path) })
	for _, sh := range shares {
		if sh.Writable {
			a("--bind", sh.Source, sh.Path)
		} else {
			a("--ro-bind", sh.Source, sh.Path)
		}
	}
	s.Chdir = h.Home
	a("--chdir", s.Chdir)

	for _, k := range sortedKeys(o.Env) { // sorted: with two bad names, the same one is named every time
		if err := ValidEnvName(k); err != nil {
			return nil, err
		}
		env[k] = o.Env[k]
	}
	env["PATH"] = "/usr/bin"
	env["HOME"] = h.Home
	env["USER"] = h.User
	env["LOGNAME"] = h.User
	env["XDG_RUNTIME_DIR"] = run
	env["XDG_CACHE_HOME"] = filepath.Join(h.Home, ".cache")
	env["WINEPREFIX"] = prefix
	for _, k := range sortedKeys(env) {
		s.Env = append(s.Env, k+"="+env[k])
	}
	return s, nil
}

// SetChdir starts the program in dir instead of the private home (the caller checks dir is inside the sandbox).
func (s *Sandbox) SetChdir(dir string) {
	for i := 0; i+1 < len(s.Args); i++ {
		if s.Args[i] == "--chdir" {
			s.Args[i+1] = dir
		}
	}
	s.Chdir = dir
}

// Command is the whole argument vector: bwrap, its options, and the in-sandbox script with its arguments.
func (s *Sandbox) Command(script string, args []string) []string {
	cmd := append([]string{BwrapPath}, s.Args...)
	cmd = append(cmd, "--", shPath, "-c", script, "limbo-wine")
	return append(cmd, args...)
}

// WithEnv returns the environment with name set to value (for one step, such as WINEARCH when a prefix is made).
func (s *Sandbox) WithEnv(name, value string) []string {
	out := make([]string, 0, len(s.Env)+1)
	for _, kv := range s.Env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	out = append(out, name+"="+value)
	sort.Strings(out)
	return out
}

func depth(p string) int { return strings.Count(filepath.Clean(p), "/") }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
