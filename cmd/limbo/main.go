// Command limbo runs guest applications as sandboxed host windows.
//
//	limbo validate <manifest>     check a manifest
//	limbo plan     <manifest>     print everything `up` would apply; changes nothing
//	limbo seed     <manifest> <dir>   write cloud-init user-data/meta-data (Linux guests)
//	limbo up       <manifest>     verify, configure firewall, start the guest (Linux host, root)
//	limbo launch   <manifest>     show the guest's application as a host window
//	limbo down     <manifest>     stop the guest and remove its network and firewall table
//
//	limbo serve                   run the control API: admin, control and agent sockets (Linux, root)
//	limbo quarantine ...          list / show / restrict / verdict / close (admin socket; needs sudo)
//	limbo report [--guest G] [--since 7d] [--out F]   Markdown evidence report
//	limbo doctor                  what is installed and what is missing
//	limbo setup [--yes] [--upgrade] [--enable-service]   install the runtime (libvirt, QEMU, ...) and enable it
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Artifex-Technologies/Limbo/internal/engine"
	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/hostfw"
	"github.com/Artifex-Technologies/Limbo/internal/hostpolicy"
	"github.com/Artifex-Technologies/Limbo/internal/launch"
	"github.com/Artifex-Technologies/Limbo/internal/license"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/policy"
	"github.com/Artifex-Technologies/Limbo/internal/provision"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/runner"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

const version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "limbo:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: limbo <validate|plan|seed|up|launch|down|version> <manifest> [args] | limbo serve | limbo quarantine ... | limbo report | limbo doctor | limbo setup | limbo passthrough ... | limbo analyze FILE")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Println(version)
		return nil
	case "serve":
		return serve(rest)
	case "quarantine":
		return quarantineCmd(rest)
	case "report":
		return reportCmd(rest)
	case "doctor":
		return doctorCmd(rest)
	case "setup":
		return setupCmd(rest)
	case "passthrough":
		return passthroughCmd(rest)
	case "analyze":
		return analyzeCmd(rest)
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	state := fs.String("state-dir", defaultStateDir(), "directory for event log and generated definitions")
	iso := fs.String("iso", "", "seed: also build a cloud-init ISO at this path (needs xorriso)")
	iKnow := fs.Bool("i-know", false, "as root, allow a state folder other than the daemon's")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("%s: manifest path required", cmd)
	}
	m, err := manifest.Load(fs.Arg(0))
	if err != nil {
		return err
	}

	switch cmd {
	case "validate":
		fmt.Printf("%s: ok (%s guest, network %s)\n", m.Name, m.OS, m.Network.Mode)
		return nil
	case "plan":
		return plan(m, *state)
	case "seed":
		if fs.NArg() != 2 {
			return errors.New("seed: output directory required")
		}
		return seed(m, fs.Arg(1), *iso)
	case "up", "down", "launch":
		if err := checkRootStateDir(*state, *iKnow); err != nil {
			return err
		}
		return act(cmd, m, *state)
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// daemonStateDir is limbo.service's state folder: its quarantine holds, its audit log (which Heimdall reads) and the
// passthrough approval live there.
const daemonStateDir = "/var/lib/limbo/state"

var geteuid = os.Geteuid

func defaultStateDir() string {
	if d := os.Getenv("LIMBO_STATE_DIR"); d != "" {
		return d
	}
	if geteuid() == 0 {
		return daemonStateDir
	}
	if d, err := os.UserHomeDir(); err == nil {
		return filepath.Join(d, ".local", "state", "limbo")
	}
	return "limbo-state"
}

// checkRootStateDir refuses, for root, a state folder other than the daemon's: a guest started against another folder
// would skip the quarantine holds and be invisible to Heimdall. --i-know is for a person who means it.
func checkRootStateDir(state string, iKnow bool) error {
	if geteuid() != 0 || iKnow || filepath.Clean(state) == daemonStateDir {
		return nil
	}
	return fmt.Errorf("as root the state folder is the daemon's (%s), where the quarantine holds and Heimdall's view are; "+
		"add --i-know to use %s anyway", daemonStateDir, state)
}

// plan prints the generated artifacts. It performs the license check but no
// side effects, so it is safe on any OS and is how the generators are reviewed.
// planRootDisk mirrors the engine's choice of boot disk, so the plan shows the
// path the guest would really use.
func planRootDisk(m *manifest.Manifest, state string) string {
	if m.Disposable {
		return filepath.Join(state, virt.OverlayName(m))
	}
	return m.Image.Path
}

func plan(m *manifest.Manifest, state string) error {
	if err := license.Check(m); err != nil {
		fmt.Println("# GATE:", err)
	}
	netXML, err := virt.NetworkXML(m)
	if err != nil {
		return err
	}
	domXML, err := virt.DomainXML(m, planRootDisk(m, state))
	if err != nil {
		return err
	}
	rules, err := policy.NFT(m)
	if err != nil {
		return err
	}
	launchLine := "refused: "
	if c, err := launch.Build(m); err != nil {
		launchLine += err.Error()
	} else {
		launchLine = strings.Join(c.Args, " ")
	}
	fmt.Printf("# libvirt network\n%s\n# libvirt domain\n%s\n# nftables\n%s\n# launch\n%s\n", netXML, domXML, rules, launchLine)
	return nil
}

func seed(m *manifest.Manifest, dir, isoPath string) error {
	s, err := provision.Build(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, body := range map[string]string{"user-data": s.UserData, "meta-data": s.MetaData} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	if isoPath == "" {
		fmt.Printf("wrote %s/{user-data,meta-data}; add --iso PATH to build the seed disk\n", dir)
		return nil
	}
	// The volume label must be "cidata" for cloud-init's NoCloud datasource.
	out, err := exec.Command("xorriso", "-as", "mkisofs", "-o", isoPath, "-V", "cidata", "-J", "-r", dir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("xorriso: %w: %s", err, out)
	}
	fmt.Printf("wrote seed disk %s\n", isoPath)
	return nil
}

func act(cmd string, m *manifest.Manifest, state string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%s: requires a Linux host (use `plan` elsewhere)", cmd)
	}
	if cmd == "up" || cmd == "down" {
		// Limbo can ship without its heavy runtime and fetch it on first setup.
		if err := preflight(); err != nil {
			return err
		}
	}
	log, err := events.Open(filepath.Join(state, "events.jsonl"))
	if err != nil {
		return err
	}
	defer log.Close()
	ctx := context.Background()
	// A quarantined or condemned guest must not be startable from the CLI either.
	store, err := quarantine.Open(filepath.Join(state, "quarantine"))
	if err != nil {
		return err
	}
	e := &engine.Engine{Runner: runner.Exec{}, Events: log, StateDir: state, Holds: store, Hardware: &hostpolicy.Policy{StateDir: state}, UFWActive: hostfw.UFWActive}

	switch cmd {
	case "up":
		return e.Up(ctx, m)
	case "down":
		return e.Down(ctx, m)
	}

	// launch: gate first, then record, then hand the terminal to the client. A held guest's app is not opened either.
	if rec, held := store.Holding(m.Name); held {
		reason := "guest is quarantined (" + rec.ID + ", " + string(rec.Status) + ")"
		_ = log.Emit(events.GateBlocked, m.Name, map[string]string{"reason": reason})
		return fmt.Errorf("%w: %s", engine.ErrQuarantined, reason)
	}
	if err := license.Check(m); err != nil {
		_ = log.Emit(events.GateBlocked, m.Name, map[string]string{"reason": err.Error()})
		return err
	}
	c, err := launch.Build(m)
	if err != nil {
		return err
	}
	if err := log.Emit(events.AppLaunch, m.Name, map[string]string{"app": m.App.Name}); err != nil {
		return err
	}
	p := exec.CommandContext(ctx, c.Args[0], c.Args[1:]...)
	p.Stdin, p.Stdout, p.Stderr = os.Stdin, os.Stdout, os.Stderr
	return p.Run()
}
