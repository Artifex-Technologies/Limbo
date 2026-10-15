package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/deps"
)

// fakeEnv is a machine on which only the named commands exist.
type fakeEnv struct {
	env      setupEnv
	out      *bytes.Buffer
	ran      []string
	prompted int
}

func newFake(installed []string, root bool) *fakeEnv {
	f := &fakeEnv{out: &bytes.Buffer{}}
	have := map[string]bool{"pacman": true} // an Arch system, with none of Limbo's runtime
	for _, c := range installed {
		have[c] = true
	}
	f.env = setupEnv{
		out: f.out,
		look: func(file string) (string, error) {
			if have[file] {
				return "/usr/bin/" + file, nil
			}
			return "", errors.New("not found")
		},
		run: func(_ context.Context, name string, args ...string) error {
			f.ran = append(f.ran, name+" "+strings.Join(args, " "))
			if name == "pacman" {
				// installing makes the commands appear, as it would for real
				for _, d := range deps.Required {
					have[d.Command] = true
				}
			}
			return nil
		},
		exists:   func(p string) bool { return p == "/dev/kvm" || p == "/usr/lib/sysusers.d/limbo.conf" },
		isRoot:   root,
		confirm:  func(string) bool { f.prompted++; return true },
		groupsOK: func() bool { return true },
	}
	return f
}

func allDeps() []string {
	var out []string
	for _, d := range deps.Required {
		out = append(out, d.Command)
	}
	return out
}

func TestSetupRefusesWithoutRoot(t *testing.T) {
	f := newFake(nil, false)
	err := setup(context.Background(), f.env, setupOpts{yes: true})
	if err == nil || !strings.Contains(err.Error(), "must run as root") || len(f.ran) != 0 {
		t.Fatalf("err=%v ran=%v", err, f.ran)
	}
}

func TestSetupInstallsOnlyWhatIsMissingWithTheExactCommand(t *testing.T) {
	f := newFake([]string{"virsh", "nft", "ssh", "xorriso", "dnsmasq"}, true) // qemu absent
	if err := setup(context.Background(), f.env, setupOpts{yes: true}); err != nil {
		t.Fatalf("%v\n%s", err, f.out)
	}
	if f.ran[0] != "pacman -S --needed --noconfirm qemu-base" {
		t.Fatalf("unexpected install command: %q", f.ran[0])
	}
	if strings.Contains(strings.Join(f.ran, "\n"), "-Sy") {
		t.Fatalf("a partial upgrade (-Sy without -u) must never be run: %v", f.ran)
	}
}

func TestSetupEnablesLibvirtAndCreatesGroups(t *testing.T) {
	f := newFake(nil, true)
	if err := setup(context.Background(), f.env, setupOpts{yes: true}); err != nil {
		t.Fatalf("%v\n%s", err, f.out)
	}
	all := strings.Join(f.ran, "\n")
	for _, want := range []string{
		"pacman -S --needed --noconfirm dnsmasq libisoburn libvirt nftables openssh qemu-base",
		"systemd-sysusers /usr/lib/sysusers.d/limbo.conf",
		"systemctl enable --now virtlogd.socket virtqemud.socket virtnetworkd.socket virtstoraged.socket virtnodedevd.socket",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "limbo.service") {
		t.Error("the control service must not be enabled unless asked for")
	}
}

func TestSetupMakesTheGroupsItselfWhenThePackageIsNotInstalled(t *testing.T) {
	f := newFake(allDeps(), true)
	have := map[string]bool{"limbo-agent": true} // one exists already: only the other is made
	f.env.exists = func(p string) bool { return p == "/dev/kvm" }
	f.env.hasGroup = func(n string) bool { return have[n] }
	if err := setup(context.Background(), f.env, setupOpts{yes: true}); err != nil {
		t.Fatalf("%v\n%s", err, f.out)
	}
	all := strings.Join(f.ran, "\n")
	if !strings.Contains(all, "groupadd --system limbo-heimdall") || strings.Contains(all, "groupadd --system limbo-agent") || strings.Contains(all, "systemd-sysusers") {
		t.Fatalf("unexpected commands:\n%s", all)
	}
}

func TestUpgradeFlagDoesAFullUpgradeNotAPartialOne(t *testing.T) {
	f := newFake(nil, true)
	if err := setup(context.Background(), f.env, setupOpts{yes: true, upgrade: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f.ran[0], "pacman -Syu --needed --noconfirm ") {
		t.Fatalf("got %q", f.ran[0])
	}
}

func TestEnableServiceIsOptIn(t *testing.T) {
	f := newFake(allDeps(), true)
	if err := setup(context.Background(), f.env, setupOpts{yes: true, enableService: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.ran, "\n"), "systemctl enable --now limbo.service") {
		t.Fatalf("%v", f.ran)
	}
}

func TestNothingToInstallSkipsThePackageManager(t *testing.T) {
	f := newFake(allDeps(), true)
	if err := setup(context.Background(), f.env, setupOpts{yes: true}); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.ran {
		if strings.HasPrefix(c, "pacman") {
			t.Fatalf("pacman was run although nothing was missing: %v", f.ran)
		}
	}
	if !strings.Contains(f.out.String(), "install nothing") {
		t.Errorf("the plan should say nothing will be installed:\n%s", f.out)
	}
}

func TestDecliningChangesNothing(t *testing.T) {
	f := newFake(nil, true)
	f.env.confirm = func(string) bool { f.prompted++; return false }
	err := setup(context.Background(), f.env, setupOpts{})
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") || len(f.ran) != 0 || f.prompted != 1 {
		t.Fatalf("err=%v ran=%v prompted=%d", err, f.ran, f.prompted)
	}
}

func TestYesSkipsTheQuestionButStillShowsThePlan(t *testing.T) {
	f := newFake(nil, true)
	if err := setup(context.Background(), f.env, setupOpts{yes: true}); err != nil {
		t.Fatal(err)
	}
	if f.prompted != 0 {
		t.Error("--yes must not prompt")
	}
	if !strings.Contains(f.out.String(), "install: dnsmasq libisoburn libvirt nftables openssh qemu-base") {
		t.Errorf("the plan must be shown even with --yes:\n%s", f.out)
	}
}

func TestAPackageManagerFailureExplainsTheStaleDatabaseAndDoesNotContinue(t *testing.T) {
	f := newFake(nil, true)
	f.env.run = func(_ context.Context, name string, args ...string) error {
		f.ran = append(f.ran, name)
		if name == "pacman" {
			return errors.New("exit status 1")
		}
		return nil
	}
	err := setup(context.Background(), f.env, setupOpts{yes: true})
	if err == nil || !strings.Contains(err.Error(), "pacman -Syu") || !strings.Contains(err.Error(), "--upgrade") {
		t.Fatalf("the error must say how to recover: %v", err)
	}
	if len(f.ran) != 1 {
		t.Fatalf("nothing may run after a failed install (no half-configured system): %v", f.ran)
	}
}

func TestWithoutPacmanTheMissingPackagesAreListed(t *testing.T) {
	f := newFake(nil, true)
	f.env.look = func(file string) (string, error) { return "", errors.New("not found") } // not even pacman
	err := setup(context.Background(), f.env, setupOpts{yes: true})
	if err == nil || !strings.Contains(err.Error(), "no pacman") || !strings.Contains(err.Error(), "qemu-base") || len(f.ran) != 0 {
		t.Fatalf("err=%v ran=%v", err, f.ran)
	}
}

func TestDoctorReportsAndChangesNothing(t *testing.T) {
	f := newFake([]string{"virsh", "ssh"}, false)
	if doctor(f.env) {
		t.Fatal("doctor must report not-ready when dependencies are missing")
	}
	out := f.out.String()
	for _, want := range []string{"ok       virsh", "MISSING  qemu-img", "Fix: sudo limbo setup", "qemu-base"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if len(f.ran) != 0 {
		t.Fatalf("doctor must not run anything: %v", f.ran)
	}
}

func TestDoctorFlagsMissingKVMAndGroups(t *testing.T) {
	f := newFake(allDeps(), false)
	f.env.exists = func(string) bool { return false }
	f.env.groupsOK = func() bool { return false }
	if doctor(f.env) {
		t.Fatal("no /dev/kvm and no groups must not be ready")
	}
	if !strings.Contains(f.out.String(), "/dev/kvm: no hardware virtualization") || !strings.Contains(f.out.String(), "limbo-heimdall") {
		t.Errorf("\n%s", f.out)
	}
}

func TestDoctorOKWhenEverythingIsThere(t *testing.T) {
	f := newFake(allDeps(), false)
	if !doctor(f.env) {
		t.Fatalf("\n%s", f.out)
	}
}
