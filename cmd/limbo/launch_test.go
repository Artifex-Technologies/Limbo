//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/engine"
	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
)

func launchManifest(t *testing.T, extra string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse([]byte(`{"name":"lab","os":"linux","clipboard":"text",
 "image":{"path":"/x.qcow2","sha256":"` + strings.Repeat("0", 64) + `"},
 "access":{"user":"analyst"},` + extra + `"app":{"name":"Shell","exec":"foot"}}`))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const testPin = `"provision":{"host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},`

func launchDeps(t *testing.T) (*quarantine.Store, *events.Logger) {
	t.Helper()
	d := t.TempDir()
	st, err := quarantine.Open(filepath.Join(d, "q"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(filepath.Join(d, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	return st, log
}

// A person's launch asks the daemon (user.sock) whether the guest is held and where it is; it does not trust its own
// state folder, which never holds the daemon's holds.
func TestPersonsLaunchAsksTheDaemonAndPinsTheKey(t *testing.T) {
	if geteuid() == 0 {
		t.Skip("runs the non-root path")
	}
	st, log := launchDeps(t)
	old := askLimbo
	defer func() { askLimbo = old }()

	askLimbo = func(string) (launchView, error) { return launchView{}, errors.New("connection refused") }
	if _, _, err := prepareLaunch(launchManifest(t, testPin), t.TempDir(), st, log); err == nil || !strings.Contains(err.Error(), "limbo-users") {
		t.Fatalf("no answer must mean no launch: %v", err)
	}
	askLimbo = func(string) (launchView, error) {
		v := launchView{Running: true, Address: "10.213.9.2"}
		v.Hold = &struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}{"q-1", "open"}
		return v, nil
	}
	if _, _, err := prepareLaunch(launchManifest(t, testPin), t.TempDir(), st, log); !errors.Is(err, engine.ErrQuarantined) {
		t.Fatalf("held: %v", err)
	}
	askLimbo = func(string) (launchView, error) { return launchView{Running: false}, nil }
	if _, _, err := prepareLaunch(launchManifest(t, testPin), t.TempDir(), st, log); err == nil {
		t.Fatal("launched a stopped guest")
	}
	askLimbo = func(string) (launchView, error) { return launchView{Running: true, Address: "10.213.9.2"}, nil }
	if _, _, err := prepareLaunch(launchManifest(t, ""), t.TempDir(), st, log); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("unpinned: %v", err)
	}
	c, cleanup, err := prepareLaunch(launchManifest(t, testPin), t.TempDir(), st, log)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(c.Args, " ")
	if !strings.Contains(joined, "analyst@10.213.9.2") || !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Fatal(joined)
	}
	var kh string
	for _, a := range c.Args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") {
			kh = strings.TrimPrefix(a, "UserKnownHostsFile=")
		}
	}
	b, err := os.ReadFile(kh)
	if err != nil || !strings.HasPrefix(string(b), "limbo-lab ssh-ed25519 AAAAC3") {
		t.Fatalf("%q %v", b, err)
	}
	if fi, _ := os.Stat(kh); fi.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts mode %v", fi.Mode())
	}
	cleanup()
	if _, err := os.Stat(kh); !os.IsNotExist(err) {
		t.Fatal("known_hosts left behind")
	}
}

// seed makes the guest's host key once, puts it in the guest's user-data, and holds the manifest to its pin.
func TestSeedMakesAndPinsTheGuestsHostKey(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	dir := t.TempDir()
	m := launchManifest(t, `"provision":{"ssh_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample analyst@host"},`)
	if err := seed(m, dir, ""); err != nil {
		t.Fatal(err)
	}
	ud, _ := os.ReadFile(filepath.Join(dir, "user-data"))
	pub, _ := os.ReadFile(filepath.Join(dir, hostKeyFile+".pub"))
	f := strings.Fields(string(pub))
	if !strings.Contains(string(ud), "ssh_genkeytypes: []") || !strings.Contains(string(ud), f[1]) || !strings.Contains(string(ud), "ed25519_private") {
		t.Fatalf("user-data:\n%s", ud)
	}
	if fi, _ := os.Stat(filepath.Join(dir, hostKeyFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", fi.Mode())
	}
	// Run again: the same key, not a new one.
	m.Provision.HostKey = f[0] + " " + f[1]
	if err := seed(m, dir, ""); err != nil {
		t.Fatal(err)
	}
	pub2, _ := os.ReadFile(filepath.Join(dir, hostKeyFile+".pub"))
	if string(pub2) != string(pub) {
		t.Fatal("key changed between seeds")
	}
	m.Provision.HostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	if err := seed(m, dir, ""); err == nil || !strings.Contains(err.Error(), "different host key") {
		t.Fatalf("mismatch: %v", err)
	}
}
