// Package wine is Limbo's Wine backend: Windows programs run with Wine directly on the host desktop, each prefix inside
// its own bubblewrap sandbox (docs/ARCHITECTURE.md section 13).
//
// Wine is not a security boundary: it runs Windows code as the host user, with everything that user can reach. So
// Limbo never runs it bare. The sandbox gets the system read-only, a private /tmp and a private home holding only the
// prefix (and the prefix's own cache), the display, sound and graphics card, and nothing else of the person's files
// unless a share names it. No network unless asked. The defaults are the restrictive ones; every widening is a flag or
// a profile setting the person wrote.
//
// The package builds bwrap's argument vector (never a shell string: nothing from a profile, a share or the program's
// arguments is ever interpreted by a shell on the host) and runs it. The argument builder is pure, so the deny-first
// defaults are pinned by unit tests against a described host rather than the machine the tests run on.
package wine

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Fixed paths. Absolute on purpose: Limbo's own `wine` shim sits earlier in PATH, so looking Wine up in PATH would find
// the shim and recurse.
const (
	BwrapPath      = "/usr/bin/bwrap"
	WinePath       = "/usr/bin/wine"
	WineserverPath = "/usr/bin/wineserver"
	shPath         = "/usr/bin/sh"
)

// DefaultPrefix is the prefix used when none is named, and the one Limbo's `wine` shim uses when the caller sets no
// WINEPREFIX.
const DefaultPrefix = "default"

// nameRe keeps a prefix name usable as a directory and file name, and in the event log. No dots: names never start
// with "." (Limbo's own lock and record files beside the prefixes do) and never contain "..".
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)

// ValidName checks a prefix name.
func ValidName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("wine: prefix name %q must match %s (lowercase letters, digits, - and _)", name, nameRe)
	}
	return nil
}

// Guest is the name a prefix's events carry in the log's guest field. "wine:" keeps it apart from virtual machines,
// whose names cannot contain a colon.
func Guest(prefix string) string { return "wine:" + prefix }

// Architectures a new prefix can be made with. Win64 runs 32-bit programs too, through Wine's own WoW64, as 64-bit
// Windows does; win32 is only for the rare program that refuses to run on 64-bit Windows, and a WoW64-only Wine build
// (Arch's Wine 11) cannot make one at all.
const (
	ArchWin64 = "win64"
	ArchWin32 = "win32"
)

// DefaultWindows is the Windows version a new prefix reports (winecfg -v): a modern one, so programs do not take the
// old-Windows code paths that look and behave dated.
const DefaultWindows = "win10"

// windowsVersions are the versions Limbo hands to `winecfg -v` (Wine's own names). Anything else is refused before it
// reaches Wine.
var windowsVersions = []string{"win11", "win10", "win81", "win8", "win7", "vista", "winxp64", "winxp", "win2k", "win98"}

// ValidWindows checks a Windows version name.
func ValidWindows(v string) error {
	for _, w := range windowsVersions {
		if v == w {
			return nil
		}
	}
	return fmt.Errorf("wine: Windows version %q is not one of %s", v, strings.Join(windowsVersions, ", "))
}

// ValidArch checks an architecture name.
func ValidArch(a string) error {
	if a != ArchWin64 && a != ArchWin32 {
		return fmt.Errorf("wine: arch must be %q or %q, got %q", ArchWin64, ArchWin32, a)
	}
	return nil
}

// Network modes. None is the default; host shares the host's whole network namespace. Finer modes (internet only, an
// allowlist) need a network of the sandbox's own and are not built yet.
const (
	NetNone = "none"
	NetHost = "host"
)

// Dirs are where Limbo keeps each prefix and what must never be shared into a sandbox.
type Dirs struct {
	Root   string // the prefixes: Root/NAME is a prefix (default ~/.local/share/limbo/wine)
	Cache  string // each prefix's cache: Cache/NAME is the sandbox's ~/.cache (default ~/.cache/limbo/wine)
	Config string // profiles: Config/NAME.json (default ~/.config/limbo/wine)
	State  string // Limbo's state folder, with the event log (default ~/.local/state/limbo)
}

// DefaultDirs follows the XDG base directories (a relative value is ignored, as the specification says).
func DefaultDirs(getenv func(string) string, home, state string) Dirs {
	xdg := func(name, fallback string) string {
		if v := getenv(name); filepath.IsAbs(v) {
			return filepath.Clean(v)
		}
		return filepath.Join(home, fallback)
	}
	return Dirs{
		Root:   filepath.Join(xdg("XDG_DATA_HOME", ".local/share"), "limbo", "wine"),
		Cache:  filepath.Join(xdg("XDG_CACHE_HOME", ".cache"), "limbo", "wine"),
		Config: filepath.Join(xdg("XDG_CONFIG_HOME", ".config"), "limbo", "wine"),
		State:  filepath.Clean(state),
	}
}

// Prefix is the prefix directory for name.
func (d Dirs) Prefix(name string) string { return filepath.Join(d.Root, name) }

// PrefixCache is the prefix's cache directory.
func (d Dirs) PrefixCache(name string) string { return filepath.Join(d.Cache, name) }

// Profile is the prefix's profile file.
func (d Dirs) Profile(name string) string { return filepath.Join(d.Config, name+".json") }

// The lock, Limbo's record of what it set, and the marker of a prefix being made sit beside the prefixes, outside every
// sandbox (only Root/NAME is mounted).
func (d Dirs) lockFile(name string) string     { return filepath.Join(d.Root, "."+name+".lock") }
func (d Dirs) recordFile(name string) string   { return filepath.Join(d.Root, "."+name+".json") }
func (d Dirs) creatingFile(name string) string { return filepath.Join(d.Root, "."+name+".creating") }

// Share is a host folder (or file) mounted into the sandbox at the path the person gave.
type Share struct {
	Path     string // absolute and clean, as given: where it appears inside the sandbox
	Source   string // Path with every symlink resolved: what is really mounted
	Writable bool
}

// Options are what one run asks for: a profile's settings merged with the command line's.
type Options struct {
	Prefix  string
	Network string // NetNone or NetHost
	GPU     bool
	Audio   bool
	Display bool // Wayland and X11 (Wine's two display drivers)
	X11     bool // with Display: X11 as well as Wayland
	Shares  []Share
	Env     map[string]string // set explicitly (--env, a profile's "env")
	// Arch and Windows apply when the prefix is made (Windows also when it differs from what Limbo last set); empty
	// means the defaults, ArchWin64 and DefaultWindows.
	Arch    string
	Windows string
	// Trace records Wine's behaviour trace (TraceChannels) in the run's folder.
	Trace bool
}
