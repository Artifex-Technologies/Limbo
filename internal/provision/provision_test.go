package provision

import (
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

func mf(t *testing.T, os, prov string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse([]byte(`{"name":"lab","os":"` + os + `",
 "image":{"path":"/x.qcow2","sha256":"` + strings.Repeat("0", 64) + `"},
 "access":{"user":"analyst"},"provision":` + prov + `,
 "app":{"name":"A","exec":"a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const key = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample analyst@host`

func TestBuild(t *testing.T) {
	s, err := Build(mf(t, "linux", `{"ssh_public_key":"`+key+`","packages":["wireshark","nmap"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#cloud-config", `name: "analyst"`, "lock_passwd: true", "ssh_pwauth: false", `"wireshark"`, "disable_root: true"} {
		if !strings.Contains(s.UserData, want) {
			t.Errorf("user-data missing %q:\n%s", want, s.UserData)
		}
	}
	if !strings.Contains(s.MetaData, `instance-id: "limbo-lab"`) {
		t.Errorf("meta-data: %s", s.MetaData)
	}
}

func TestBuildRejects(t *testing.T) {
	tests := []struct{ name, os, prov string }{
		{"windows", "windows", `{"ssh_public_key":"` + key + `"}`},
		{"no key", "linux", `{}`},
		{"multiline key", "linux", `{"ssh_public_key":"ssh-ed25519 AAAA\nruncmd: [x]"}`},
		{"package injection", "linux", `{"ssh_public_key":"` + key + `","packages":["nmap\"]\nruncmd: [evil]"]}`},
		{"package flag", "linux", `{"ssh_public_key":"` + key + `","packages":["-oAPT::Foo"]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Build(mf(t, tc.os, tc.prov)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Without packages the seed must switch updates off explicitly so first boot
// never depends on the network.
func TestNoPackagesDisablesUpdates(t *testing.T) {
	s, err := Build(mf(t, "linux", `{"ssh_public_key":"`+key+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"package_update: false", "package_upgrade: false"} {
		if !strings.Contains(s.UserData, want) {
			t.Errorf("missing %q:\n%s", want, s.UserData)
		}
	}
	s, _ = Build(mf(t, "linux", `{"ssh_public_key":"`+key+`","packages":["nmap"]}`))
	if strings.Contains(s.UserData, "package_update: false") {
		t.Error("updates must stay on when packages are requested")
	}
}

// Regression for a real-guest finding: sshd waited on NTP via
// systemd-time-wait-sync, so guests without internet never became reachable.
func TestSeedDisablesNTPWait(t *testing.T) {
	s, err := Build(mf(t, "linux", `{"ssh_public_key":"`+key+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.UserData, "systemd-time-wait-sync.service") || !strings.Contains(s.UserData, "mask") {
		t.Errorf("seed does not mask the NTP wait: %s", s.UserData)
	}
}

// Sudo is opt-in: a default guest's user must NOT get root, but a validation
// profile can ask for it (vetting an update means running pacman).
func TestSudoIsOffByDefaultAndOptIn(t *testing.T) {
	plain, err := Build(mf(t, "linux", `{"ssh_public_key":"`+key+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.UserData, "NOPASSWD") {
		t.Fatalf("a default guest must not grant sudo:\n%s", plain.UserData)
	}

	m := mf(t, "linux", `{"ssh_public_key":"`+key+`"}`)
	m.Access.Sudo = true
	withSudo, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withSudo.UserData, `sudo: "ALL=(ALL) NOPASSWD:ALL"`) {
		t.Fatalf("access.sudo must grant it:\n%s", withSudo.UserData)
	}
	// The grant sits inside the user's entry, not at the top level.
	userBlock := withSudo.UserData[strings.Index(withSudo.UserData, "users:"):strings.Index(withSudo.UserData, "disable_root")]
	if !strings.Contains(userBlock, "NOPASSWD") {
		t.Fatalf("sudo must be part of the user entry:\n%s", userBlock)
	}
}
