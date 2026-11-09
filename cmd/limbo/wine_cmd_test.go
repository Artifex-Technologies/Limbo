//go:build linux

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/events"
)

// wineEnv points every folder limbo wine uses at a temporary place and takes the display and sound away, so a test
// run touches neither the person's home nor their screen.
func wineEnv(t *testing.T) (data, state string) {
	t.Helper()
	root := t.TempDir()
	for _, k := range []string{"XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"} {
		t.Setenv(k, filepath.Join(root, strings.ToLower(k)))
	}
	for _, k := range []string{"WAYLAND_DISPLAY", "DISPLAY", "PULSE_SERVER", "XAUTHORITY", "WINEPREFIX"} {
		t.Setenv(k, "")
	}
	t.Setenv("WINEDLLOVERRIDES", "mscoree=;mshtml=")
	return filepath.Join(root, "xdg_data_home"), filepath.Join(root, "state")
}

func wineEvents(t *testing.T, state string) []events.Event {
	t.Helper()
	evs, _, err := events.Read(filepath.Join(state, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// A program that sets WINEPREFIX somewhere else does not get Wine at all: Wine runs only in Limbo's own prefixes.
func TestWineShimRefusesAPrefixOutsideLimbo(t *testing.T) {
	_, state := wineEnv(t)
	t.Setenv("WINEPREFIX", filepath.Join(t.TempDir(), ".wine"))
	err := wineCmd([]string{"--shim", "--state-dir", state, "--", "notepad"})
	if err == nil || !strings.Contains(err.Error(), "not one of Limbo's prefixes") {
		t.Fatalf("err=%v", err)
	}
	evs := wineEvents(t, state)
	if len(evs) != 1 || evs[0].Kind != events.WineRefused || evs[0].Detail["via"] != "path" {
		t.Fatalf("events %+v", evs)
	}
	if err := wineCmd([]string{"--shim", "--prefix", "x", "--state-dir", state, "--", "notepad"}); err == nil {
		t.Fatal("--shim with --prefix accepted")
	}
}

// captureStdout runs f with the process's standard output going to a pipe, and returns what was written.
func captureStdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	ferr := f()
	os.Stdout = old
	w.Close()
	out := <-done
	r.Close()
	return out, ferr
}

// The command as a person and as Limbo's wine on PATH run it, for real: bubblewrap, Wine and Wine's own cmd.
func TestWineCommandRealRun(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: a real Wine run makes a prefix")
	}
	if os.Geteuid() == 0 {
		t.Skip("limbo wine refuses root")
	}
	for _, p := range []string{"/usr/bin/bwrap", "/usr/bin/wine", "/usr/bin/wineserver"} {
		if _, err := os.Stat(p); err != nil {
			t.Skip(p + " is not installed")
		}
	}
	if out, err := exec.Command("/usr/bin/bwrap", "--unshare-user", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib64", "--", "/usr/bin/true").CombinedOutput(); err != nil {
		t.Skipf("bwrap cannot make a sandbox here: %v %s", err, out)
	}
	data, state := wineEnv(t)

	out, err := captureStdout(t, func() error {
		return wineCmd([]string{"--headless", "--state-dir", state, "--", "cmd", "/c", "echo", "hello"})
	})
	t.Logf("limbo wine --headless -- cmd /c echo hello: %q %v", out, err)
	if err != nil || strings.TrimSpace(out) != "hello" {
		t.Fatalf("%q %v", out, err)
	}
	evs := wineEvents(t, state)
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Kind)
	}
	if strings.Join(kinds, " ") != "wine.setup wine.start wine.stop" || evs[1].Guest != "wine:default" || evs[2].Detail["exit_code"] != "0" ||
		evs[1].Detail["network"] != "none" || evs[1].Detail["via"] != "cli" {
		t.Fatalf("events %+v", evs)
	}
	if _, err := os.Stat(evs[2].Detail["record"]); err != nil {
		t.Fatalf("run record: %v", err)
	}

	// Through Limbo's wine on PATH: the prefix from WINEPREFIX, the program's exit status passed on.
	t.Setenv("WINEPREFIX", filepath.Join(data, "limbo", "wine", "default"))
	out, err = captureStdout(t, func() error {
		return wineCmd([]string{"--shim", "--state-dir", state, "--", "cmd", "/c", "echo", "via-PATH"})
	})
	if err != nil || strings.TrimSpace(out) != "via-PATH" {
		t.Fatalf("shim: %q %v", out, err)
	}
	if last := wineEvents(t, state); last[len(last)-1].Detail["via"] != "path" {
		t.Fatalf("shim run not marked: %+v", last[len(last)-1])
	}
	_, err = captureStdout(t, func() error { return wineCmd([]string{"--shim", "--state-dir", state, "--", "cmd", "/c", "exit", "3"}) })
	var status exitStatus
	if !errors.As(err, &status) || status != 3 {
		t.Fatalf("exit status: %v", err)
	}
}
