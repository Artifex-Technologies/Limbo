//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/wine"
)

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// wineCmd: limbo wine [options] [--] PROGRAM [ARGS]: a Windows program with Wine, on the desktop, inside its prefix's
// bubblewrap sandbox (package wine; docs/ARCHITECTURE.md section 13). Limbo's `wine` on PATH runs `limbo wine --shim`.
func wineCmd(args []string) error {
	fs := flag.NewFlagSet("wine", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: limbo wine [options] [--] PROGRAM [ARGS]   (Windows programs with Wine, inside a sandbox)")
		fs.PrintDefaults()
	}
	prefix := fs.String("prefix", "", "the prefix ~/.local/share/limbo/wine/NAME, with its profile ~/.config/limbo/wine/NAME.json (default \"default\")")
	var f wine.Flags
	fs.BoolVar(&f.Network, "network", false, "share the host's network (default: no network at all)")
	fs.Var((*listFlag)(&f.Share), "share", "a folder (or file) the program may read, at the same path inside (repeatable)")
	fs.Var((*listFlag)(&f.ShareRW), "share-rw", "a folder (or file) the program may read and write (repeatable)")
	fs.Var((*listFlag)(&f.Env), "env", "NAME=VALUE in the program's environment (repeatable)")
	fs.BoolVar(&f.NoGPU, "no-gpu", false, "no graphics card (software rendering)")
	fs.BoolVar(&f.NoAudio, "no-audio", false, "no sound")
	fs.BoolVar(&f.NoX11, "no-x11", false, "Wayland only (an X11 program can read other X11 programs' windows and keys)")
	fs.BoolVar(&f.NoDisplay, "no-display", false, "no display (console programs)")
	fs.BoolVar(&f.Headless, "headless", false, "no display and no sound: console programs in the background")
	fs.StringVar(&f.Windows, "windows", "", "the Windows version the prefix reports: win11, win10 (a new prefix's default), win81, win8, win7, vista, winxp64, winxp, win2k, win98")
	fs.StringVar(&f.Arch, "arch", "", "a new prefix's architecture: win64 (the default; it runs 32-bit programs too) or win32")
	fs.BoolVar(&f.Trace, "trace", false, "record Wine's behaviour trace (processes, DLLs, network use, services) in the run's folder")
	dry := fs.Bool("dry-run", false, "print the sandbox and the steps; change nothing")
	state := fs.String("state-dir", defaultStateDir(), "Limbo's state folder: the event log and the run folders")
	shim := fs.Bool("shim", false, "for Limbo's wine command on PATH: the prefix comes from WINEPREFIX")
	if err := fs.Parse(args); err != nil {
		return err
	}
	h, err := wine.Probe()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	dirs := wine.DefaultDirs(os.Getenv, h.Home, *state)
	via, parent := "cli", ""
	if *shim {
		via, parent = "path", parentName()
	}

	// Refusals before a run exists go to the log too (a program asking for Wine outside Limbo is worth knowing about).
	var log *events.Logger
	openLog := func() error {
		if log != nil || *dry {
			return nil
		}
		l, err := events.Open(filepath.Join(*state, "events.jsonl"))
		if err != nil {
			return fmt.Errorf("wine: the event log could not be opened, so nothing was run: %w", err)
		}
		log = l
		return nil
	}
	defer func() {
		if log != nil {
			log.Close()
		}
	}()
	refuse := func(guest string, err error) error {
		if lerr := openLog(); lerr == nil && log != nil {
			d := map[string]string{"reason": err.Error(), "via": via}
			if parent != "" {
				d["parent"] = parent
			}
			_ = log.Emit(events.WineRefused, guest, d)
		}
		return err
	}

	name := *prefix
	switch {
	case *shim && name != "":
		return errors.New("wine: --shim takes the prefix from WINEPREFIX; leave out --prefix")
	case *shim:
		if name, err = wine.ShimPrefix(os.Getenv("WINEPREFIX"), dirs); err != nil {
			return refuse("wine", err)
		}
	case name == "":
		name = wine.DefaultPrefix
	}
	if err := wine.ValidName(name); err != nil {
		return err
	}
	for _, v := range []struct{ val, what string }{{f.Windows, "windows"}, {f.Arch, "arch"}} {
		if v.val == "" {
			continue
		}
		check := wine.ValidWindows
		if v.what == "arch" {
			check = wine.ValidArch
		}
		if err := check(v.val); err != nil {
			return err
		}
	}
	profilePath := dirs.Profile(name)
	p, profileSHA, err := wine.LoadProfile(profilePath)
	if err != nil {
		return refuse(wine.Guest(name), err)
	}
	if p == nil {
		profilePath = ""
	}
	o, err := wine.Merge(name, p, f, cwd, h.Home)
	if err != nil {
		return refuse(wine.Guest(name), err)
	}
	program, progArgs := "", fs.Args()
	if len(progArgs) > 0 {
		program, progArgs = progArgs[0], progArgs[1:]
	} else if p != nil && p.Program != "" {
		program, progArgs = p.Program, p.Args
	} else if *shim {
		return errors.New("usage: wine PROGRAM [ARGS]   (Limbo's wine: it runs in Limbo's sandbox; see limbo wine --help)")
	}

	r := &wine.Run{Options: o, Host: h, Dirs: dirs, Program: program, Args: progArgs, Cwd: cwd, Via: via, Parent: parent,
		Profile: profilePath, ProfileSHA: profileSHA, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	if *dry {
		return r.DryRun(os.Stdout)
	}
	if err := openLog(); err != nil {
		return err
	}
	r.Log = log
	code, err := r.Do()
	if err != nil {
		return err
	}
	if code != 0 {
		return exitStatus(code)
	}
	return nil
}

// parentName is the name of the program that ran Limbo's wine command (the shim execs limbo, so it is limbo's parent),
// for the event log: "winetricks", "lutris", a shell.
func parentName() string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(os.Getppid()) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
