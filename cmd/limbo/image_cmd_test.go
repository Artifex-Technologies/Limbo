package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/image"
)

type recordedEvents struct{ got []events.Event }

func (r *recordedEvents) Emit(kind, guest string, d map[string]string) error {
	r.got = append(r.got, events.Event{Kind: kind, Guest: guest, Detail: d})
	return nil
}

// proven sets up an image proven by a full hash, with the test's own uid as the trusted owner.
func proven(t *testing.T) (*image.Proofs, string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "images")
	if err := os.Mkdir(dir, 0o755); err != nil || os.Chmod(dir, 0o755) != nil {
		t.Fatal(err)
	}
	img := filepath.Join(dir, "base.qcow2")
	if err := os.WriteFile(img, []byte("abc"), 0o644); err != nil || os.Chmod(img, 0o644) != nil {
		t.Fatal(err)
	}
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	p := &image.Proofs{Path: filepath.Join(root, image.ProofsFile), Owner: uint32(os.Getuid())}
	if how, err := p.Check(img, abc); err != nil || how != image.ByHash {
		t.Fatal(how, err)
	}
	if how, err := p.Check(img, abc); err != nil || how != image.ByRecord {
		t.Fatal(how, err)
	}
	return p, img, abc
}

func TestImageVerifyPassesAnUnchangedImage(t *testing.T) {
	p, img, _ := proven(t)
	ev := &recordedEvents{}
	var out bytes.Buffer
	if err := imageVerify(p, ev, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "ok       "+img) || len(ev.got) != 0 {
		t.Fatalf("%q %v", out.String(), ev.got)
	}
	out.Reset()
	if err := imageList(p, &out); err != nil || !strings.Contains(out.String(), "a start skips the hash") {
		t.Fatalf("%v %q", err, out.String())
	}
}

// A changed image: the weekly check fails, refuses it and writes image.rejected once (Heimdall turns it into a
// finding); the next start hashes it in full and refuses it.
func TestImageVerifyRefusesAChangedImageAndLogsIt(t *testing.T) {
	p, img, abc := proven(t)
	if err := os.WriteFile(img, []byte("abd"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := &recordedEvents{}
	var out bytes.Buffer
	err := imageVerify(p, ev, &out)
	if err == nil || !strings.Contains(err.Error(), "1 of 1 images changed") {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(out.String(), "CHANGED  "+img) {
		t.Fatalf("%q", out.String())
	}
	if len(ev.got) != 1 {
		t.Fatalf("events %v", ev.got)
	}
	e := ev.got[0]
	if e.Kind != events.ImageRejected || e.Guest != "" || e.Detail["during"] != "weekly check" || e.Detail["path"] != img ||
		e.Detail["sha256"] != abc || e.Detail["found"] == "" || e.Detail["stat"] != "changed" || !strings.Contains(e.Detail["reason"], img) {
		t.Fatalf("event %+v", e)
	}
	if how, err := p.Check(img, abc); how != image.ByHash || !errors.Is(err, image.ErrMismatch) {
		t.Fatalf("after the refusal a start got %q %v", how, err)
	}
	// Next week: still refused, still failing, but no second event for the same finding.
	if err := imageVerify(p, ev, &out); err == nil || len(ev.got) != 1 {
		t.Fatalf("second week: %v, %d events", err, len(ev.got))
	}
	out.Reset()
	if err := imageList(p, &out); err != nil || !strings.Contains(out.String(), "refused by the weekly check") {
		t.Fatalf("%v %q", err, out.String())
	}
}

func TestImageVerifyFailsOnAnUntrustedRecordFile(t *testing.T) {
	p, _, _ := proven(t)
	if err := os.WriteFile(p.Path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := imageVerify(p, &recordedEvents{}, &bytes.Buffer{}); !errors.Is(err, image.ErrRecordsIgnored) {
		t.Fatalf("%v", err)
	}
}

func readPackaging(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "arch", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The package installs the weekly check, enables its timer, keeps it in the background, and gives game time its say.
func TestImageVerifyUnitsArePackaged(t *testing.T) {
	pkg := readPackaging(t, "PKGBUILD")
	for _, want := range []string{
		`packaging/arch/limbo-image-verify.service "$pkgdir/usr/lib/systemd/system/limbo-image-verify.service"`,
		`packaging/arch/limbo-image-verify.timer "$pkgdir/usr/lib/systemd/system/limbo-image-verify.timer"`,
		`"$pkgdir/usr/lib/systemd/system/limbo-image-verify.service.d/gametime.conf"`,
		`ln -s ../limbo-image-verify.timer "$pkgdir/usr/lib/systemd/system/timers.target.wants/limbo-image-verify.timer"`,
	} {
		if !strings.Contains(pkg, want) {
			t.Errorf("the PKGBUILD lacks %s", want)
		}
	}
	svc := readPackaging(t, "limbo-image-verify.service")
	for _, want := range []string{"Nice=19", "IOSchedulingClass=idle", "CPUWeight=idle", "Type=oneshot",
		"ExecStart=/usr/bin/limbo image verify --state-dir /var/lib/limbo/state",
		"ConditionPathExists=/var/lib/limbo/state/" + image.ProofsFile, "ReadWritePaths=/var/lib/limbo/state"} {
		if !strings.Contains(svc, want+"\n") {
			t.Errorf("the service lacks %s", want)
		}
	}
	if tm := readPackaging(t, "limbo-image-verify.timer"); !strings.Contains(tm, "OnCalendar=weekly\n") || !strings.Contains(tm, "Persistent=true\n") {
		t.Errorf("the timer is not weekly and persistent:\n%s", tm)
	}
	if !strings.Contains(readPackaging(t, "limbo.install"), "start limbo-image-verify.timer") {
		t.Error("the install script does not start the timer")
	}
}

// The game-time drop-in, run as systemd would run it (its "$$" is a "$", %n the unit's name): without
// yggdrasil-gametime the chore runs (a missing ExecCondition program would make systemd skip it every week); with
// it, game time's answer decides.
func TestGameTimeDropInRunsTheChoreWithoutGameTime(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	conf := readPackaging(t, "limbo-image-verify-gametime.conf")
	m := regexp.MustCompile(`(?m)^ExecCondition=\+(.*)$`).FindStringSubmatch(conf)
	if m == nil {
		t.Fatalf("no ExecCondition=+ line:\n%s", conf)
	}
	const real = "/usr/bin/yggdrasil-gametime"
	if strings.Count(m[1], real) != 2 {
		t.Fatalf("the line must test for and run %s: %s", real, m[1])
	}
	dir := t.TempDir()
	run := func(gametime string) (int, string) {
		line := strings.ReplaceAll(strings.ReplaceAll(m[1], "%n", "limbo-image-verify.service"), "$$", "$")
		line = strings.ReplaceAll(line, real, gametime)
		argv := splitQuoted(t, line)
		cmd := exec.Command(argv[0], argv[1:]...)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	if code, out := run(filepath.Join(dir, "absent")); code != 0 {
		t.Fatalf("without game time the condition must pass: %d %s", code, out)
	}
	for _, game := range []struct {
		code int
		name string
	}{{100, "a game runs"}, {0, "no game"}} {
		stand := filepath.Join(dir, "gametime-"+strings.ReplaceAll(game.name, " ", "-"))
		script := "#!/bin/sh\necho \"$@\"\nexit " + map[bool]string{true: "100", false: "0"}[game.code == 100] + "\n"
		if err := os.WriteFile(stand, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		code, out := run(stand)
		if code != game.code || strings.TrimSpace(out) != "no-game limbo-image-verify.service" {
			t.Fatalf("%s: exit %d, game time was asked %q", game.name, code, out)
		}
	}
}

// splitQuoted splits a command line the way systemd does for these lines: words, with single quotes grouping.
func splitQuoted(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	var cur strings.Builder
	in, word := false, false
	for _, r := range s {
		switch {
		case r == '\'':
			in, word = !in, true
		case r == ' ' && !in:
			if word {
				out = append(out, cur.String())
				cur.Reset()
				word = false
			}
		default:
			cur.WriteRune(r)
			word = true
		}
	}
	if in {
		t.Fatalf("unbalanced quotes: %s", s)
	}
	if word {
		out = append(out, cur.String())
	}
	return out
}
