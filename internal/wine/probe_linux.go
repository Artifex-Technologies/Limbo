//go:build linux

package wine

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Probe gathers the Host facts from this machine and session. It only reads.
func Probe() (Host, error) {
	h := Host{UID: os.Getuid(), GID: os.Getgid(), Env: map[string]string{}, RootLinks: map[string]string{}, Etc: map[string]bool{}}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			h.Env[k] = v
		}
	}
	// The account from /etc/passwd; an account it does not list (systemd-homed, a directory service) falls back to the
	// session's USER and HOME.
	h.User, h.Home = h.Env["USER"], h.Env["HOME"]
	if u, err := user.Current(); err == nil {
		h.User = u.Username
		if !filepath.IsAbs(h.Home) {
			h.Home = u.HomeDir
		}
	}
	if h.User == "" || !filepath.IsAbs(h.Home) {
		return h, errors.New("wine: cannot tell this account's name and home folder (set USER and HOME)")
	}
	h.Group = h.User
	if g, err := user.LookupGroupId(strconv.Itoa(h.GID)); err == nil {
		h.Group = g.Name
	}
	h.Home = filepath.Clean(h.Home)

	for _, n := range []string{"/bin", "/sbin", "/lib", "/lib64", "/lib32"} {
		fi, err := os.Lstat(n)
		switch {
		case err != nil:
		case fi.Mode()&os.ModeSymlink != 0:
			if t, err := os.Readlink(n); err == nil {
				h.RootLinks[n] = t
			}
		case fi.IsDir():
			h.RootDirs = append(h.RootDirs, n)
		}
	}
	for _, n := range etcAll() {
		if _, err := os.Stat("/etc/" + n); err == nil {
			h.Etc[n] = true
		}
	}
	if fi, err := os.Lstat("/etc/localtime"); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			if t, err := os.Readlink("/etc/localtime"); err == nil {
				if !filepath.IsAbs(t) {
					t = filepath.Join("/etc", t)
				}
				if t = filepath.Clean(t); within(t, "/usr") {
					h.Localtime = t
				}
			}
		} else if fi.Mode().IsRegular() {
			h.Etc["localtime"] = true
		}
	}
	h.NTSync = isChar("/dev/ntsync")
	h.CPUInfo = isDir("/sys/devices/system/cpu")
	h.FontCache = isDir("/var/cache/fontconfig")

	run := h.Env["XDG_RUNTIME_DIR"]
	if !filepath.IsAbs(run) {
		run = ""
	}
	if w := h.Env["WAYLAND_DISPLAY"]; w != "" {
		if !filepath.IsAbs(w) && run != "" {
			w = filepath.Join(run, w)
		}
		if filepath.IsAbs(w) && isSocket(w) {
			h.Wayland = w
		}
	}
	if n, ok := x11Display(h.Env["DISPLAY"]); ok {
		sock := "/tmp/.X11-unix/X" + strconv.Itoa(n)
		if isSocket(sock) {
			h.X11Display, h.X11Socket = n, sock
			xa := h.Env["XAUTHORITY"]
			if !filepath.IsAbs(xa) {
				xa = filepath.Join(h.Home, ".Xauthority")
			}
			if b, err := readSmall(xa, 64<<10); err == nil {
				h.Xauth = FilterXauth(b, n)
			}
		}
	}
	pulse := strings.TrimPrefix(h.Env["PULSE_SERVER"], "unix:")
	if !filepath.IsAbs(pulse) && run != "" {
		pulse = filepath.Join(run, "pulse", "native")
	}
	if filepath.IsAbs(pulse) && isSocket(pulse) {
		h.Pulse = pulse
		cookie := h.Env["PULSE_COOKIE"]
		if !filepath.IsAbs(cookie) {
			cookie = filepath.Join(h.Home, ".config", "pulse", "cookie")
		}
		if b, err := readSmall(cookie, 4<<10); err == nil {
			h.PulseCookie = b
		}
	}
	if run != "" && isSocket(filepath.Join(run, "pipewire-0")) {
		h.PipeWire = filepath.Join(run, "pipewire-0")
	}

	h.GPUNodes, h.GPUSys = probeGPU()
	h.DriverDirs = driverDirs()
	return h, nil
}

var nvidiaNode = regexp.MustCompile(`^nvidia([0-9]+|ctl|-modeset|-uvm|-uvm-tools)$`)

// probeGPU finds the graphics nodes and the sysfs the drivers read: for each DRM node its card's own device folder
// (Mesa and NVIDIA's EGL find the card's PCI ID there, through /sys/dev/char), and NVIDIA's module folders (its Vulkan
// driver checks the kernel module's version there). Only those: the rest of /sys (other devices, network cards' addresses)
// stays out.
func probeGPU() (nodes, sys []string) {
	seen := map[string]bool{}
	addSys := func(p string) {
		if !seen[p] && isDir(p) {
			seen[p] = true
			sys = append(sys, p)
		}
	}
	if ents, err := os.ReadDir("/dev/dri"); err == nil {
		nodes = append(nodes, "/dev/dri")
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			dev, err := filepath.EvalSymlinks(filepath.Join("/sys/class/drm", e.Name()))
			if err != nil || filepath.Base(filepath.Dir(dev)) != "drm" {
				continue
			}
			if card := filepath.Dir(filepath.Dir(dev)); strings.HasPrefix(card, "/sys/devices/") {
				addSys(card)
			}
		}
		if len(sys) > 0 {
			addSys("/sys/dev/char")
		}
	}
	if ents, err := os.ReadDir("/dev"); err == nil {
		for _, e := range ents {
			if nvidiaNode.MatchString(e.Name()) && isChar("/dev/"+e.Name()) {
				nodes = append(nodes, "/dev/"+e.Name())
			}
		}
	}
	for _, m := range []string{"nvidia", "nvidia_drm", "nvidia_modeset", "nvidia_uvm"} {
		addSys("/sys/module/" + m)
	}
	return nodes, sys
}

// driverDirs lists the folders under /opt that the system's Vulkan, EGL and GLVND driver files name a library in.
// Drivers in /usr need nothing (it is bound whole); a driver installed under /opt would otherwise fail to load.
func driverDirs() []string {
	var out []string
	seen := map[string]bool{}
	for _, dir := range []string{
		"/etc/vulkan/icd.d", "/etc/vulkan/implicit_layer.d", "/etc/vulkan/explicit_layer.d",
		"/usr/share/vulkan/icd.d", "/usr/share/vulkan/implicit_layer.d", "/usr/share/vulkan/explicit_layer.d",
		"/etc/glvnd/egl_vendor.d", "/usr/share/glvnd/egl_vendor.d",
		"/etc/egl/egl_external_platform.d", "/usr/share/egl/egl_external_platform.d",
	} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, f := range files {
			b, err := readSmall(f, 64<<10)
			if err != nil {
				continue
			}
			var v any
			if json.Unmarshal(b, &v) != nil {
				continue
			}
			for _, lib := range libraryPaths(v) {
				if lib = filepath.Clean(lib); filepath.IsAbs(lib) && strings.HasPrefix(lib, "/opt/") {
					if d := filepath.Dir(lib); !seen[d] && isDir(d) {
						seen[d] = true
						out = append(out, d)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// libraryPaths finds every "library_path" string in a driver or layer manifest, wherever the format version puts it.
func libraryPaths(v any) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if s, ok := x.(string); ok && k == "library_path" {
				out = append(out, s)
			} else {
				out = append(out, libraryPaths(x)...)
			}
		}
	case []any:
		for _, x := range t {
			out = append(out, libraryPaths(x)...)
		}
	}
	return out
}

var x11Re = regexp.MustCompile(`^(?:unix)?:([0-9]{1,4})(?:\.[0-9]+)?$`)

// x11Display reads a local X display number from DISPLAY (":0", ":0.0", "unix:1"); a display over the network is not
// shared.
func x11Display(d string) (int, bool) {
	m := x11Re.FindStringSubmatch(d)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func isDir(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
func isChar(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
func isSocket(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// readSmall reads a regular file of at most max bytes.
func readSmall(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, os.ErrInvalid
	}
	return io.ReadAll(io.LimitReader(f, max))
}
