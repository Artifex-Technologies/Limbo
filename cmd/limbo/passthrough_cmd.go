package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/hostpolicy"
)

// passthroughCmd is the only way to approve a GPU test window. It runs as root at
// a terminal and writes a root-only file: there is deliberately no socket route
// for it, so Sarina and Heimdall cannot approve anything, only a person can.
func passthroughCmd(args []string) error {
	fs := flag.NewFlagSet("passthrough", flag.ContinueOnError)
	state := fs.String("state-dir", defaultStateDir(), "directory for the event log and the approval")
	runDir := fs.String("run-dir", "/run/limbo", "directory for the reboot-needed marker")
	minutes := fs.Int("minutes", 30, "approve: how long the approval lasts (max 120)")
	iKnow := fs.Bool("i-know", false, "allow a state folder other than the daemon's")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("passthrough: must run as root (it changes what guests may take from the host)")
	}
	if err := checkRootStateDir(*state, *iKnow); err != nil {
		return err
	}
	tty := false
	if fi, err := os.Stdin.Stat(); err == nil {
		tty = fi.Mode()&os.ModeCharDevice != 0
	}
	log, err := events.Open(filepath.Join(*state, "events.jsonl"))
	if err != nil {
		return err
	}
	defer log.Close()
	p := &hostpolicy.Policy{StateDir: *state, RunDir: *runDir}
	return passthrough(pos, time.Duration(*minutes)*time.Minute, p, log, os.Stdin, os.Stdout, tty, whoAmI())
}

// passthrough implements the subcommands. Split from passthroughCmd so tests can
// drive it without root or a terminal.
func passthrough(pos []string, d time.Duration, p *hostpolicy.Policy, log interface {
	Emit(kind, guest string, detail map[string]string) error
}, in io.Reader, out io.Writer, tty bool, who string) error {
	const usage = "usage: limbo passthrough status | approve [--minutes N] ADDR... | revoke | clear"
	if len(pos) == 0 {
		return errors.New(usage)
	}
	switch pos[0] {
	case "status":
		fmt.Fprintf(out, "host OS: %q\n", p.HostID())
		if a := p.Approval(); a != nil {
			fmt.Fprintf(out, "approved: %s until %s (by %s)\n", strings.Join(a.Devices, ", "), a.Expires.Local().Format(time.RFC3339), a.By)
		} else {
			fmt.Fprintln(out, "approved: nothing (guests asking for a device are refused)")
		}
		if p.Blocked() {
			fmt.Fprintln(out, "BLOCKED: an earlier run left a device unusable; reboot the host (or 'limbo passthrough clear' once you have recovered it)")
		}
		return nil
	case "revoke":
		if err := p.Revoke(); err != nil {
			return err
		}
		_ = log.Emit(events.PassthroughRevoke, "", map[string]string{"by": who})
		fmt.Fprintln(out, "approval removed")
		return nil
	case "clear":
		if err := p.Clear(); err != nil {
			return err
		}
		fmt.Fprintln(out, "reboot-needed marker removed")
		return nil
	case "approve":
		return approvePassthrough(pos[1:], d, p, log, in, out, tty, who)
	}
	return errors.New(usage)
}

func approvePassthrough(devs []string, d time.Duration, p *hostpolicy.Policy, log interface {
	Emit(kind, guest string, detail map[string]string) error
}, in io.Reader, out io.Writer, tty bool, who string) error {
	if len(devs) == 0 {
		return errors.New("approve: name the device(s), e.g. 0000:03:00.0 0000:03:00.1")
	}
	if !tty {
		return errors.New("approve: run this from a terminal; it asks you to confirm")
	}
	if p.Blocked() {
		return errors.New("approve: an earlier run left a device unusable; reboot the host first")
	}
	// The same checks Approve applies, run first so the warning is shown only for a
	// request that could succeed, and the person sees what is in the way. Nothing is
	// written until they confirm: an approval must not be live while the prompt waits.
	if err := p.CanApprove(devs); err != nil {
		var busy *hostpolicy.Busy
		if errors.As(err, &busy) {
			fmt.Fprintln(out, "These are using the device right now:")
			for _, w := range busy.Who {
				fmt.Fprintln(out, "  "+w)
			}
			fmt.Fprintln(out, "Save your work and close them, then run this again.")
			fmt.Fprintln(out, "(If it is your desktop session, the display must run on the other GPU first.)")
		}
		return err
	}
	fmt.Fprintf(out, `GPU test approval for: %s
For the next %s, validation runs (Sarina's) may take this device away from the host.

  - While a run holds it, the host cannot use it. Anything using it fails or is killed.
  - After a run the card may not reset cleanly. If it does not, Limbo refuses further
    passthrough runs until you reboot the host, and unsaved work on a display driven by
    this card could be lost.
  - Nothing appears to be using the device right now. Keep it that way: save your work
    and close anything that draws on this GPU (games, video, compositors, AI models).

Type "yes" to approve: `, strings.Join(devs, ", "), d)
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		fmt.Fprintln(out, "not approved")
		return nil
	}
	a, err := p.Approve(devs, d, who)
	if err != nil {
		return err
	}
	if err := log.Emit(events.PassthroughApprove, "", map[string]string{
		"devices": strings.Join(a.Devices, ","), "expires": a.Expires.Format(time.RFC3339), "by": who,
	}); err != nil {
		_ = p.Revoke() // an approval that cannot be audited does not stand
		return err
	}
	fmt.Fprintf(out, "approved until %s\n", a.Expires.Local().Format(time.RFC3339))
	return nil
}
