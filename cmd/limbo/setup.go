package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/Artifex-Technologies/Limbo/internal/deps"
	"github.com/Artifex-Technologies/Limbo/internal/runs"
)

// libvirtSockets are the socket-activated daemons the engine talks to. Enabling
// the sockets (not the services) is how libvirt is meant to run: each daemon
// starts on first use and exits when idle.
var libvirtSockets = []string{
	"virtlogd.socket", "virtqemud.socket", "virtnetworkd.socket", "virtstoraged.socket", "virtnodedevd.socket",
}

// setupEnv is everything doctor and setup touch outside themselves, so the
// logic can be tested without installing anything.
type setupEnv struct {
	out      io.Writer
	look     deps.LookPath
	run      func(ctx context.Context, name string, args ...string) error // output visible to the user
	exists   func(path string) bool
	isRoot   bool
	confirm  func(prompt string) bool
	groupsOK func() bool
	// skippedProfiles lists validation profiles that exist but are not usable (nil: not checked).
	skippedProfiles func() []runs.SkippedProfile
}

func realSetupEnv() setupEnv {
	return setupEnv{
		out:  os.Stdout,
		look: exec.LookPath,
		run: func(ctx context.Context, name string, args ...string) error {
			c := exec.CommandContext(ctx, name, args...)
			c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
			return c.Run()
		},
		exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
		isRoot: os.Geteuid() == 0,
		confirm: func(prompt string) bool {
			fmt.Print(prompt + " [y/N] ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
		},
		groupsOK: func() bool {
			return exec.Command("getent", "group", "limbo-heimdall").Run() == nil &&
				exec.Command("getent", "group", "limbo-agent").Run() == nil
		},
		skippedProfiles: func() []runs.SkippedProfile {
			return (&runs.Manager{ProfileDir: "/etc/limbo/validation"}).SkippedAll()
		},
	}
}

// doctor reports what is and is not ready, and returns whether Limbo can run
// guests here. It changes nothing.
func doctor(env setupEnv) bool {
	ok := true
	fmt.Fprintln(env.out, "Runtime dependencies:")
	missing := deps.Missing(env.look)
	have := map[string]bool{}
	for _, d := range missing {
		have[d.Command] = true
	}
	for _, d := range deps.Required {
		if have[d.Command] {
			fmt.Fprintf(env.out, "  MISSING  %-20s %s (package %s)\n", d.Command, d.Purpose, d.Package)
			ok = false
		} else {
			fmt.Fprintf(env.out, "  ok       %-20s %s\n", d.Command, d.Purpose)
		}
	}
	fmt.Fprintln(env.out, "\nSystem:")
	check := func(good bool, okMsg, badMsg string) {
		if good {
			fmt.Fprintln(env.out, "  ok       "+okMsg)
		} else {
			fmt.Fprintln(env.out, "  MISSING  "+badMsg)
			ok = false
		}
	}
	check(env.exists("/dev/kvm"), "/dev/kvm (hardware virtualization is available)",
		"/dev/kvm: no hardware virtualization here (enable VT-x/AMD-V, or nested virtualization in a VM)")
	check(env.groupsOK(), "groups limbo-heimdall and limbo-agent exist",
		"groups limbo-heimdall / limbo-agent: run `sudo limbo setup` (or install the package so sysusers creates them)")
	if env.skippedProfiles != nil {
		if sk := env.skippedProfiles(); len(sk) > 0 {
			fmt.Fprintln(env.out, "\nValidation profiles that exist but are not offered:")
			for _, s := range sk {
				name := s.Name
				if name == "" {
					name = "(unnamed file)"
				}
				fmt.Fprintf(env.out, "  SKIPPED  %-20s %s: %s. %s\n", name, s.Code, s.Reason, s.Remedy)
			}
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(env.out, "\nFix: sudo limbo setup   (installs: %s)\n", strings.Join(deps.Packages(missing), " "))
	}
	return ok
}

type setupOpts struct {
	yes           bool
	upgrade       bool // run a full system upgrade first (pacman -Syu)
	enableService bool
}

// setup installs what is missing, enables libvirt, creates the groups, and
// optionally enables limbo.service. It asks before changing anything unless
// --yes is given, and never runs a partial upgrade.
func setup(ctx context.Context, env setupEnv, o setupOpts) error {
	if !env.isRoot {
		return errors.New("setup: must run as root (it installs packages and enables services): sudo limbo setup")
	}
	missing := deps.Missing(env.look)
	pkgs := deps.Packages(missing)

	fmt.Fprintln(env.out, "Limbo setup will:")
	if len(pkgs) > 0 {
		verb := "pacman -S --needed"
		if o.upgrade {
			verb = "pacman -Syu --needed  (a FULL system upgrade, then these)"
		}
		fmt.Fprintf(env.out, "  - install: %s   [%s]\n", strings.Join(pkgs, " "), verb)
	} else {
		fmt.Fprintln(env.out, "  - install nothing: every runtime dependency is already present")
	}
	fmt.Fprintf(env.out, "  - enable libvirt's socket-activated daemons (%s)\n", strings.Join(libvirtSockets, ", "))
	fmt.Fprintln(env.out, "  - create the limbo-heimdall and limbo-agent groups, if the package's sysusers file is present")
	if o.enableService {
		fmt.Fprintln(env.out, "  - enable and start limbo.service (the control API)")
	}
	fmt.Fprintln(env.out)
	if !o.yes && !env.confirm("Proceed?") {
		return errors.New("setup: cancelled; nothing was changed")
	}

	if len(pkgs) > 0 {
		if _, err := env.look("pacman"); err != nil {
			return fmt.Errorf("setup: this system has no pacman; install these with your package manager and run `limbo doctor`: %s", strings.Join(pkgs, " "))
		}
		args := []string{"-S", "--needed", "--noconfirm"}
		if o.upgrade {
			args = []string{"-Syu", "--needed", "--noconfirm"}
		}
		if err := env.run(ctx, "pacman", append(args, pkgs...)...); err != nil {
			// A stale package database is the usual cause on a freshly installed
			// or live-medium system. The fix is a normal system upgrade, which we
			// do not do silently: `pacman -Sy` followed by an install is the
			// unsupported partial upgrade that can break an Arch system.
			return fmt.Errorf("setup: pacman failed: %w\n\nIf it says a package was not found or a dependency conflicts, the package database is probably out of date.\nUpdate the system first (sudo pacman -Syu) and run `sudo limbo setup` again,\nor run `sudo limbo setup --upgrade` to do both now.", err)
		}
	}

	if env.exists("/usr/lib/sysusers.d/limbo.conf") {
		if err := env.run(ctx, "systemd-sysusers", "/usr/lib/sysusers.d/limbo.conf"); err != nil {
			return fmt.Errorf("setup: creating groups: %w", err)
		}
	}
	if err := env.run(ctx, "systemctl", append([]string{"enable", "--now"}, libvirtSockets...)...); err != nil {
		return fmt.Errorf("setup: enabling libvirt: %w", err)
	}
	if o.enableService {
		if err := env.run(ctx, "systemctl", "enable", "--now", "limbo.service"); err != nil {
			return fmt.Errorf("setup: enabling limbo.service: %w", err)
		}
	}

	fmt.Fprintln(env.out, "\nSetup finished. Checking:")
	if !doctor(env) {
		return errors.New("setup: finished, but `limbo doctor` still reports problems (above)")
	}
	return nil
}

func doctorCmd(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if !doctor(realSetupEnv()) {
		return errors.New("doctor: Limbo cannot run guests on this system yet")
	}
	return nil
}

func setupCmd(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	upgrade := fs.Bool("upgrade", false, "run a full system upgrade (pacman -Syu) before installing; needed when the package database is stale")
	svc := fs.Bool("enable-service", false, "also enable and start limbo.service (the control API)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	return setup(context.Background(), realSetupEnv(), setupOpts{yes: *yes, upgrade: *upgrade, enableService: *svc})
}

// preflight is called before commands that need the runtime. On a system where
// Limbo shipped without its dependencies it turns "exec: virsh not found" into
// instructions.
func preflight() error { return deps.Preflight(exec.LookPath) }
