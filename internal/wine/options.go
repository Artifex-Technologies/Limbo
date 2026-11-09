package wine

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Flags are the command line's settings, which go on top of a profile's.
type Flags struct {
	Network                                    bool // share the host's network
	NoGPU, NoAudio, NoX11, NoDisplay, Headless bool
	Share, ShareRW                             []string
	Env                                        []string // NAME=VALUE
	Windows, Arch                              string
	Trace                                      bool
}

// Merge makes a run's options: the defaults (no network, no shares; display, sound and graphics card on), then the
// profile, then the command line. The command line may add shares, environment and the host's network, switch the
// display, sound or graphics card off, and choose the Windows version and architecture; it cannot switch back on what
// the profile switched off (edit the profile for that). Shares are resolved here (relative to cwd; "~/" in a profile
// is the home folder) and checked when the run starts.
func Merge(prefix string, p *Profile, f Flags, cwd, home string) (Options, error) {
	o := Options{Prefix: prefix, Network: NetNone, GPU: true, Audio: true, Display: true, X11: true, Env: map[string]string{}}
	var ro, rw []string
	if p != nil {
		if p.Network != "" {
			o.Network = p.Network
		}
		o.GPU, o.Audio, o.Display, o.X11 = on(p.GPU), on(p.Audio), on(p.Display), on(p.X11)
		for k, v := range p.Env {
			o.Env[k] = v
		}
		o.Windows, o.Arch, o.Trace = p.Windows, p.Arch, p.Trace
		for _, list := range []struct {
			in  []string
			out *[]string
		}{{p.Share, &ro}, {p.ShareRW, &rw}} {
			for _, s := range list.in {
				if strings.HasPrefix(s, "~/") {
					s = filepath.Join(home, s[2:])
				}
				if !filepath.IsAbs(s) {
					return Options{}, fmt.Errorf("wine profile: share %q must be an absolute path (or start with ~/)", s)
				}
				*list.out = append(*list.out, s)
			}
		}
	}
	if f.Network {
		o.Network = NetHost
	}
	if f.NoGPU {
		o.GPU = false
	}
	if f.NoAudio || f.Headless {
		o.Audio = false
	}
	if f.NoDisplay || f.Headless {
		o.Display = false
	}
	if f.NoX11 {
		o.X11 = false
	}
	if f.Windows != "" {
		o.Windows = f.Windows
	}
	if f.Arch != "" {
		o.Arch = f.Arch
	}
	o.Trace = o.Trace || f.Trace
	for _, kv := range f.Env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return Options{}, fmt.Errorf("wine: --env %q is not NAME=VALUE", kv)
		}
		if err := ValidEnvName(k); err != nil {
			return Options{}, err
		}
		o.Env[k] = v
	}
	ro, rw = append(ro, f.Share...), append(rw, f.ShareRW...)
	if len(ro)+len(rw) > maxShares {
		return Options{}, fmt.Errorf("wine: more than %d shares", maxShares)
	}
	byPath := map[string]int{}
	for _, list := range []struct {
		paths    []string
		writable bool
	}{{ro, false}, {rw, true}} {
		for _, given := range list.paths {
			sh, err := ResolveShare(given, cwd, list.writable)
			if err != nil {
				return Options{}, err
			}
			if i, dup := byPath[sh.Path]; dup {
				if o.Shares[i].Writable != sh.Writable {
					return Options{}, fmt.Errorf("wine: %s is shared both read-only and writable", sh.Path)
				}
				continue
			}
			byPath[sh.Path] = len(o.Shares)
			o.Shares = append(o.Shares, sh)
		}
	}
	return o, nil
}

// ShimPrefix is the prefix for a run through Limbo's `wine` on PATH, from the caller's WINEPREFIX: unset is the
// default prefix, a folder directly in Limbo's prefix folder is that prefix, and anything else is refused (Wine runs
// only in Limbo's own prefixes; a WINEPREFIX elsewhere would have to be mounted into the sandbox whole, which is a
// decision for a person, not for whatever program set the variable).
func ShimPrefix(wineprefix string, d Dirs) (string, error) {
	if wineprefix == "" {
		return DefaultPrefix, nil
	}
	p := filepath.Clean(wineprefix)
	if filepath.IsAbs(p) && filepath.Dir(p) == d.Root && ValidName(filepath.Base(p)) == nil {
		return filepath.Base(p), nil
	}
	return "", fmt.Errorf("wine: WINEPREFIX=%s is not one of Limbo's prefixes, and Wine runs only through Limbo, in its own: "+
		"set WINEPREFIX=%s/NAME (made on first use), or run limbo wine --prefix NAME", wineprefix, d.Root)
}
