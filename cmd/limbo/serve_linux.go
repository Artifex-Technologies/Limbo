//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/Artifex-Technologies/Limbo/internal/api"
	"github.com/Artifex-Technologies/Limbo/internal/engine"
	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/hostpolicy"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/runner"
	"github.com/Artifex-Technologies/Limbo/internal/runs"
)

// serve runs the control API: three unix sockets, one per principal. See
// docs/QUARANTINE.md for why they are separate sockets rather than one socket
// with permission checks.
func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	state := fs.String("state-dir", defaultStateDir(), "directory for the event log, quarantine records and generated definitions")
	runDir := fs.String("run-dir", "/run/limbo", "directory for the sockets")
	heimdallGroup := fs.String("heimdall-group", "limbo-heimdall", "group that may use control.sock (Heimdall)")
	agentGroup := fs.String("agent-group", "limbo-agent", "group that may use agent.sock (Sarina)")
	profiles := fs.String("profile-dir", "/etc/limbo/validation", "directory of validation profiles (must be root-writable only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("serve: must run as root (it manages libvirt and nftables)")
	}
	if err := preflight(); err != nil {
		return err
	}
	if err := checkProfileDir(*profiles); err != nil {
		return err
	}

	log, err := events.Open(filepath.Join(*state, "events.jsonl"))
	if err != nil {
		return err
	}
	defer log.Close()
	if err := shareEventLog(*state, filepath.Join(*state, "events.jsonl"), *heimdallGroup); err != nil {
		return err
	}
	store, err := quarantine.Open(filepath.Join(*state, "quarantine"))
	if err != nil {
		return err
	}
	if err := checkHostPolicy(hostpolicy.DefaultConfig); err != nil {
		return err
	}
	e := &engine.Engine{Runner: runner.Exec{}, Events: log, StateDir: *state, Holds: store, Hardware: &hostpolicy.Policy{StateDir: *state, RunDir: *runDir}}
	mgr := runs.NewManager(*profiles, *state, e, runs.SSH{}, log)
	// A previous Limbo that died mid-run left guests behind; destroy them now.
	if n := mgr.ReapOrphans(context.Background()); n > 0 {
		fmt.Fprintf(os.Stderr, "limbo serve: destroyed %d guest(s) left by an interrupted run\n", n)
	}
	srv := &api.Server{
		Store:   store,
		Actions: api.EngineActions{E: e},
		Events:  log,
		Runs:    mgr,
	}

	if err := os.MkdirAll(*runDir, 0o755); err != nil {
		return err
	}
	type sock struct {
		name  string
		who   api.Principal
		mode  os.FileMode
		group string
	}
	socks := []sock{
		{"admin.sock", api.Admin, 0o600, ""},
		{"control.sock", api.Control, 0o660, *heimdallGroup},
		{"agent.sock", api.Agent, 0o660, *agentGroup},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, len(socks))
	for _, s := range socks {
		path := filepath.Join(*runDir, s.name)
		l, err := api.Listen(path, s.mode, s.group)
		if err != nil {
			stop()
			return err
		}
		defer os.Remove(path)
		fmt.Fprintf(os.Stderr, "limbo: %s listening on %s (mode %o, group %q)\n", s.who, path, s.mode, s.group)
		go func(l net.Listener, h api.Principal) {
			errc <- api.Serve(ctx, l, srv.Handler(h))
		}(l, s.who)
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// shareEventLog lets Heimdall read the audit log (and only that). The log is the
// contract Heimdall watches, so it is group-readable by the Heimdall group; the state
// directory becomes traversable (x, not listable) so the file can be opened by
// its exact path, while everything else under it (quarantine records, manifests,
// evidence) stays 0600 root. Heimdall cannot write the log.
func shareEventLog(stateDir, logPath, group string) error {
	if err := os.Chmod(stateDir, 0o711); err != nil {
		return err
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		fmt.Fprintf(os.Stderr, "limbo: group %q not found; the event log stays root-only and Heimdall cannot read it\n", group)
		return nil
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(logPath, -1, gid); err != nil {
		return err
	}
	return os.Chmod(logPath, 0o640)
}

// checkHostPolicy refuses to start if the passthrough device list could have been
// written by a non-root user: it decides which host hardware a guest may take.
// A missing file is fine (passthrough is then simply denied).
func checkHostPolicy(file string) error {
	fi, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("serve: %s is group- or world-writable; refusing to start", file)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("serve: %s is not owned by root; refusing to start", file)
	}
	return nil
}

// checkProfileDir refuses to serve profiles from a directory a non-root user
// could modify: a profile defines what a validation run may do, so whoever can
// write it controls the sandbox.
func checkProfileDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no profiles yet: the agent socket simply offers none
		}
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("serve: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("serve: %s is group- or world-writable; refusing to load validation profiles from it", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("serve: %s is not owned by root; refusing to load validation profiles from it", dir)
	}
	return nil
}
