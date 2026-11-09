package wine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxShares bounds how many folders one run may be given.
const maxShares = 32

// ResolveShare makes a share from what the person typed: relative paths are taken from cwd, and the source is the path
// with every symlink resolved, so what is checked is what is mounted. It must exist and be a folder or a regular file.
func ResolveShare(given, cwd string, writable bool) (Share, error) {
	if given == "" {
		return Share{}, fmt.Errorf("wine: an empty share")
	}
	p := given
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)
	src, err := filepath.EvalSymlinks(p)
	if err != nil {
		return Share{}, fmt.Errorf("wine: share %s: %w", given, err)
	}
	fi, err := os.Stat(src)
	if err != nil {
		return Share{}, fmt.Errorf("wine: share %s: %w", given, err)
	}
	if !fi.IsDir() && !fi.Mode().IsRegular() {
		return Share{}, fmt.Errorf("wine: share %s is not a folder or a regular file", given)
	}
	return Share{Path: p, Source: src, Writable: writable}, nil
}

// CheckShare refuses the shares that would hand the sandbox far more than a folder of the person's files, or a way
// out of it. Both the path as given and the resolved source are checked. A share is for files: not the whole home or
// anything holding it, not the system's live folders, not Limbo's own folders (other prefixes, the profiles that set
// what a sandbox may do, the event log), not a hidden folder of the home as a whole (settings, secrets and startup
// files live there; and nothing inside ~/.ssh or ~/.gnupg), and nothing writable inside a hidden folder (a program
// could leave something there the host later runs).
func CheckShare(sh Share, home string, d Dirs) error {
	for _, p := range []string{sh.Path, sh.Source} {
		if err := checkSharePath(p, sh.Writable, home, d); err != nil {
			return fmt.Errorf("wine: share %s refused: %w", sh.Path, err)
		}
	}
	return nil
}

func checkSharePath(p string, writable bool, home string, d Dirs) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("not an absolute, clean path")
	}
	if within(home, p) {
		return fmt.Errorf("it is your home folder or holds it")
	}
	for _, sys := range []string{"/proc", "/sys", "/dev", "/run"} {
		if within(p, sys) {
			return fmt.Errorf("it is a live system folder (%s)", sys)
		}
	}
	if p == "/tmp" || p == "/var/tmp" {
		return fmt.Errorf("it is the whole shared temporary folder (other programs' files and sockets); share a folder inside it")
	}
	hidden := ""
	if rel, err := filepath.Rel(home, p); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		if first := strings.Split(rel, string(filepath.Separator))[0]; strings.HasPrefix(first, ".") {
			hidden = first
			switch {
			case rel == first:
				return fmt.Errorf("it is a whole hidden folder of your home (%s holds settings, secrets or startup files)", first)
			case first == ".ssh" || first == ".gnupg":
				return fmt.Errorf("it is inside %s (keys)", first)
			}
		}
	}
	for _, own := range []string{d.Root, d.Cache, d.Config, d.State} {
		if own != "" && (within(p, own) || within(own, p)) {
			return fmt.Errorf("it overlaps Limbo's own folder %s (prefixes, profiles or the event log)", own)
		}
	}
	if hidden != "" && writable {
		return fmt.Errorf("a writable share inside a hidden folder of your home (%s) could leave behind something the host runs", hidden)
	}
	return nil
}

// within reports whether p is dir or inside it.
func within(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}

// visible reports whether a host path is inside the sandbox at the same path: in the prefix, in a share, or in /usr.
func visible(p string, o Options, d Dirs) bool {
	if within(p, d.Prefix(o.Prefix)) || within(p, "/usr") {
		return true
	}
	for _, sh := range o.Shares {
		if within(p, sh.Path) {
			return true
		}
	}
	return false
}
