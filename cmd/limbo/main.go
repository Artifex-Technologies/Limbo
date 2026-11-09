// Command limbo runs guest applications as sandboxed host windows.
//
//	limbo validate <manifest>     check a manifest
//	limbo plan     <manifest>     print everything `up` would apply; changes nothing
//	limbo seed     <manifest> <dir> [--iso F]   Linux: cloud-init user-data/meta-data; Windows: the unattended answer
//	                              file and first-logon script (a CD for the guest with --iso)
//	limbo up       <manifest>     verify, configure firewall, start the guest (Linux host, root)
//	limbo launch   <manifest>     show the guest's application as a host window (--check: every check, no window)
//	limbo down     <manifest>     stop the guest and remove its network and firewall table
//	limbo address  <manifest>     print the guest's address (given at up)
//	limbo export   <manifest> <out.qcow2>   a stopped guest's disk as one standalone base image, with its SHA-256 (root)
//	limbo screenshot <manifest> <out.ppm>   what the guest's screen shows (Windows guests; root)
//	limbo capture [--seconds N] <manifest> <out.pcap>   the guest's USB devices' traffic, for Wireshark (root)
//
//	limbo serve                   run the control API: admin, control and agent sockets (Linux, root)
//	limbo quarantine ...          list / show / restrict / verdict / close (admin socket; needs sudo)
//	limbo report [--guest G] [--since 7d] [--out F]   Markdown evidence report
//	limbo doctor                  what is installed and what is missing
//	limbo image list | verify     base images proven by a full hash (a start skips the hash while the file is
//	                              provably unchanged); verify hashes each again (weekly, limbo-image-verify.timer)
//	limbo setup [--yes] [--upgrade] [--enable-service]   install the runtime (libvirt, QEMU, ...) and enable it
//
//	The Settings page (docs/SETTINGS_PAGE.md); --json prints the socket's answer:
//	limbo settings show | password on|off
//	limbo instance list | show | start | stop | set | free-space | add | remove
//	limbo license list | add --name N (key on stdin) | remove | reveal | assign | unassign
//	limbo exchange list GUEST | take GUEST PATH DEST   (ClamAV scans before anything leaves a guest)
//	limbo net watch [--seconds N]   guests' flows and refusals as they happen (root; limbo serve logs them itself)
//
//	limbo wine [options] [--] PROGRAM [ARGS]   a Windows program with Wine on the desktop, inside its prefix's
//	                              bubblewrap sandbox (no network, no home, shares only as given; section 13)
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/api"
	"github.com/Artifex-Technologies/Limbo/internal/engine"
	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/hostfw"
	"github.com/Artifex-Technologies/Limbo/internal/hostpolicy"
	"github.com/Artifex-Technologies/Limbo/internal/image"
	"github.com/Artifex-Technologies/Limbo/internal/instances"
	"github.com/Artifex-Technologies/Limbo/internal/launch"
	"github.com/Artifex-Technologies/Limbo/internal/license"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/policy"
	"github.com/Artifex-Technologies/Limbo/internal/provision"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/runner"
	"github.com/Artifex-Technologies/Limbo/internal/usbcap"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

const version = "0.1.0-dev"

func main() {
	api.Version = version
	if err := run(os.Args[1:]); err != nil {
		var status exitStatus
		if errors.As(err, &status) {
			os.Exit(int(status))
		}
		if err != errSilent {
			fmt.Fprintln(os.Stderr, "limbo:", err)
		}
		os.Exit(1)
	}
}

// exitStatus is a program's own exit status, which limbo exits with unchanged (limbo wine: callers such as
// winetricks read the Windows program's status).
type exitStatus int

func (e exitStatus) Error() string { return "exit status " + strconv.Itoa(int(e)) }

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: limbo <validate|plan|seed|up|launch|down|address|export|screenshot|capture|version> <manifest> [args] | limbo serve | limbo quarantine ... | limbo report | limbo doctor | limbo setup | limbo passthrough ... | limbo analyze FILE | limbo settings|instance|license|exchange ... | limbo image list|verify | limbo wine [options] -- PROGRAM [ARGS]")
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
	case "settings":
		return settingsCmd(rest)
	case "instance":
		return instanceCmd(rest)
	case "license":
		return licenseCmd(rest)
	case "exchange":
		return exchangeCmd(rest)
	case "net":
		return netCmd(rest)
	case "wine":
		return wineCmd(rest)
	case "image":
		return imageCmd(rest)
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	state := fs.String("state-dir", defaultStateDir(), "directory for event log and generated definitions")
	iso := fs.String("iso", "", "seed: also build the seed CD at this path: cloud-init for Linux, the answer file for Windows (needs xorriso)")
	iKnow := fs.Bool("i-know", false, "as root, allow a state folder other than the daemon's")
	seconds := fs.Int("seconds", 120, "capture: how long to record (at most 3600)")
	check := fs.Bool("check", false, "launch: run every check (hold, address, pinned key, ssh, the app and waypipe in the guest, waypipe and a display here) without opening a window")
	identity := fs.String("identity", "", "launch: the ssh private key to use (default: your ssh defaults)")
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
	case "address":
		return address(m, *state)
	case "capture":
		if fs.NArg() != 2 {
			return errors.New("capture: manifest and output path required")
		}
		if geteuid() != 0 {
			return errors.New("capture: must run as root (usbmon is root's)")
		}
		return capture(m, fs.Arg(1), *seconds)
	case "export", "screenshot":
		if fs.NArg() != 2 {
			return fmt.Errorf("%s: manifest and output path required", cmd)
		}
		if err := checkRootStateDir(*state, *iKnow); err != nil {
			return err
		}
		if geteuid() != 0 {
			return fmt.Errorf("%s: must run as root (the guest's disk and libvirt are root's)", cmd)
		}
		if cmd == "export" {
			return export(context.Background(), m, *state, fs.Arg(1))
		}
		return screenshot(context.Background(), m, fs.Arg(1))
	case "up", "down", "launch":
		if err := checkRootStateDir(*state, *iKnow); err != nil {
			return err
		}
		return act(cmd, m, *state, launchOpts{check: *check, identity: *identity})
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
	return filepath.Join(state, virt.DiskName(m))
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
	if c, err := launch.Build(m, "<known_hosts holding the pinned key>"); err != nil {
		launchLine += err.Error()
	} else {
		launchLine = strings.Join(c.Args, " ")
	}
	fmt.Printf("# addresses are placeholders: each guest's subnet is given and recorded at up (limbo address MANIFEST)\n")
	fmt.Printf("# libvirt network\n%s\n# libvirt domain\n%s\n# nftables\n%s\n# launch\n%s\n", netXML, domXML, rules, launchLine)
	return nil
}

// hostKeyFile is where `limbo seed` keeps the guest's host key pair, beside the seed it goes into.
const hostKeyFile = "ssh_host_ed25519_key"

// keygen makes an ed25519 key pair; replaced in tests.
var keygen = func(path, comment string) error {
	out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh-keygen: %w: %s", err, out)
	}
	return nil
}

// guestHostKey makes the guest's host key pair in dir the first time (and reuses it after), so the host knows the key
// before the guest boots. A manifest that pins a different key is refused; one that pins none is told what to add.
func guestHostKey(m *manifest.Manifest, dir string) (*provision.HostKey, error) {
	if m.OS != manifest.OSLinux && m.OS != manifest.OSWindows {
		return nil, nil
	}
	priv := filepath.Join(dir, hostKeyFile)
	if _, err := os.Lstat(priv); os.IsNotExist(err) {
		if err := keygen(priv, "limbo-"+m.Name); err != nil {
			return nil, err
		}
	}
	pb, err1 := os.ReadFile(priv)
	ub, err2 := os.ReadFile(priv + ".pub")
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("seed: reading the guest's host key in %s: %v %v", dir, err1, err2)
	}
	hk := &provision.HostKey{Private: string(pb), Public: strings.TrimSpace(string(ub))}
	f := strings.Fields(hk.Public)
	if len(f) < 2 {
		return nil, fmt.Errorf("seed: %s.pub is not a public key", priv)
	}
	pin := f[0] + " " + f[1]
	switch pinned := strings.Fields(m.Provision.HostKey); {
	case len(pinned) == 0:
		fmt.Fprintf(os.Stderr, "pin: add this to %s's manifest under \"provision\" (limbo launch refuses a guest without it):\n  \"host_key\": %q\n", m.Name, pin)
	case len(pinned) < 2 || pinned[0]+" "+pinned[1] != pin:
		return nil, fmt.Errorf("seed: the manifest pins a different host key than %s.pub; fix provision.host_key, or delete the key pair in %s to make a new one (then update the pin)", priv, dir)
	}
	return hk, nil
}

// address prints the guest's IPv4 address, given at `up` (as root the daemon's record; otherwise the daemon's record
// if readable, then the caller's own state folder).
func address(m *manifest.Manifest, state string) error {
	ip, err := guestAddress(m, state)
	if err != nil {
		return err
	}
	fmt.Println(ip)
	return nil
}

func guestAddress(m *manifest.Manifest, state string) (string, error) {
	for _, dir := range []string{state, daemonStateDir} {
		if x, ok := (virt.Subnets{Path: filepath.Join(dir, "subnets.json")}).Lookup(m.Name); ok {
			cp := *m
			cp.Subnet = x
			return virt.Addr(&cp).Guest.String(), nil
		}
	}
	return "", fmt.Errorf("guest %q is not up (no subnet is recorded for it)", m.Name)
}

func seed(m *manifest.Manifest, dir, isoPath string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	hk, err := guestHostKey(m, dir)
	if err != nil {
		return err
	}
	if m.OS == manifest.OSWindows {
		return seedWindows(m, dir, isoPath, hk)
	}
	s, err := provision.BuildWithHostKey(m, hk)
	if err != nil {
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

// windowsPasswordFile holds a Windows guest's local password, beside its seed (0600): made once, kept for limbo launch.
const windowsPasswordFile = "windows-password"

// seedWindows writes a Windows guest's answer file and first-logon script (package provision) into DIR/cd, and with
// --iso puts them on a CD for the guest. The password is made once and kept in DIR/windows-password. A product key is
// used only when this runs as root and Limbo's license store has a license assigned to the guest (it goes into the
// answer file and nowhere else); without one the guest installs an edition that takes no key, such as an evaluation.
func seedWindows(m *manifest.Manifest, dir, isoPath string, hk *provision.HostKey) error {
	pwPath := filepath.Join(dir, windowsPasswordFile)
	pw, err := os.ReadFile(pwPath)
	if os.IsNotExist(err) {
		pw = []byte(newPassword())
		err = os.WriteFile(pwPath, append(pw, '\n'), 0o600)
	}
	if err != nil {
		return err
	}
	key := ""
	if geteuid() == 0 {
		if st, err := license.OpenStore(license.DefaultDir); err == nil {
			if k, err := st.KeyForInstall(m.Name); err == nil {
				key = k
			}
		}
	}
	files, err := provision.BuildWindows(m, provision.WindowsOptions{Password: strings.TrimSpace(string(pw)), ProductKey: key, HostKey: hk})
	if err != nil {
		return err
	}
	cd := filepath.Join(dir, "cd")
	if err := os.MkdirAll(cd, 0o700); err != nil {
		return err
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(cd, name), body, 0o600); err != nil {
			return err
		}
	}
	if key != "" {
		fmt.Println("the license assigned to this guest goes into its answer file")
	} else {
		fmt.Println("no license is assigned to this guest: its Windows installs without a product key (an evaluation edition)")
	}
	fmt.Printf("the local account %q's password is in %s (limbo launch asks for it)\n", m.Access.User, pwPath)
	if isoPath == "" {
		fmt.Printf("wrote %s; add --iso PATH to build the seed CD\n", cd)
		return nil
	}
	out, err := exec.Command("xorriso", "-as", "mkisofs", "-o", isoPath, "-V", "LIMBOSEED", "-J", "-r", cd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("xorriso: %w: %s", err, out)
	}
	_ = os.Chmod(isoPath, 0o600) // it holds the password and the guest's host key
	fmt.Printf("wrote seed CD %s (Windows Setup finds autounattend.xml on it)\n", isoPath)
	return nil
}

// newPassword is 20 characters from an alphabet without look-alikes (no 0/O, 1/l/I), with at least one of each kind
// Windows asks for.
func newPassword() string {
	const lower, upper, digits = "abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789"
	all := lower + upper + digits
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	out := make([]byte, len(b))
	for i, x := range b {
		out[i] = all[int(x)%len(all)]
	}
	out[0], out[1], out[2] = lower[int(b[0])%len(lower)], upper[int(b[1])%len(upper)], digits[int(b[2])%len(digits)]
	return string(out)
}

// export turns a stopped guest's disk (its overlay and the base image under it) into one standalone image at out, and
// prints its SHA-256 for a manifest: how a Windows guest installed by its answer file becomes a base image. The file is
// given to the person who ran sudo.
func export(ctx context.Context, m *manifest.Manifest, state, out string) error {
	if out == "" || !filepath.IsAbs(out) {
		return errors.New("export: the output image needs an absolute path")
	}
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("export: %s exists; pick a new name", out)
	}
	if st, err := exec.CommandContext(ctx, "virsh", "-c", "qemu:///system", "domstate", virt.DomainName(m)).Output(); err == nil &&
		!strings.Contains(string(st), "shut off") {
		return fmt.Errorf("export: %s is %s; it must be shut off (limbo down after it finishes)", m.Name, strings.TrimSpace(string(st)))
	}
	disk := filepath.Join(state, virt.DiskName(m))
	if _, err := os.Stat(disk); err != nil {
		return fmt.Errorf("export: %s has no disk in %s (a disposable guest's disk is gone after down)", m.Name, state)
	}
	if b, err := exec.CommandContext(ctx, "qemu-img", "convert", "-O", "qcow2", disk, out).CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img convert: %w: %s", err, b)
	}
	giveToSudoUser(out)
	sum, err := image.SHA256(out)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\n  \"image\": {\"path\": %q, \"sha256\": %q}\n", out, out, sum)
	return nil
}

// screenshot saves what a guest's screen shows (Windows guests have a display adapter, with no display attached, for
// this): the way to follow an unattended installation.
func screenshot(ctx context.Context, m *manifest.Manifest, out string) error {
	if out == "" || !filepath.IsAbs(out) {
		return errors.New("screenshot: the output file needs an absolute path")
	}
	if b, err := exec.CommandContext(ctx, "virsh", "-c", "qemu:///system", "screenshot", virt.DomainName(m), out).CombinedOutput(); err != nil {
		return fmt.Errorf("virsh screenshot: %w: %s", err, b)
	}
	giveToSudoUser(out)
	fmt.Printf("wrote %s\n", out)
	return nil
}

// capture records the guest's passed-through USB devices' traffic (package usbcap) into a pcap file Wireshark opens, for
// the given seconds or until Ctrl+C: how a maker's program talking to its device in a guest is learned. Only those
// devices' events are written; anything else on their bus is not.
func capture(m *manifest.Manifest, out string, seconds int) error {
	if len(m.Devices.USB) == 0 {
		return fmt.Errorf("capture: %s's manifest names no USB device", m.Name)
	}
	if out == "" || !filepath.IsAbs(out) {
		return errors.New("capture: the output file needs an absolute path")
	}
	if seconds < 1 || seconds > 3600 {
		return errors.New("capture: --seconds must be 1 to 3600")
	}
	devs, err := usbcap.Find(nil, m.Devices.USB)
	if err != nil {
		return err
	}
	if _, err := os.Stat(fmt.Sprintf("/dev/usbmon%d", devs[0].Bus)); err != nil {
		_ = exec.Command("modprobe", "usbmon").Run()
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	giveToSudoUser(out)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	for _, d := range devs {
		fmt.Fprintf(os.Stderr, "recording %s (bus %d, device %d) for %d s (Ctrl+C stops)...\n", d.ID, d.Bus, d.Dev, seconds)
	}
	w := bufio.NewWriter(f)
	n, err := usbcap.Capture(ctx, devs, w)
	if ferr := w.Flush(); err == nil {
		err = ferr
	}
	fmt.Printf("%d events written to %s\n", n, out)
	return err
}

// giveToSudoUser hands a file root made to the person who ran sudo, so they can open it.
func giveToSudoUser(path string) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if geteuid() == 0 && err1 == nil && err2 == nil {
		_ = os.Chown(path, uid, gid)
	}
}

// launchOpts are launch's flags.
type launchOpts struct {
	check    bool
	identity string
}

func act(cmd string, m *manifest.Manifest, state string, lo launchOpts) error {
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
	e := &engine.Engine{Runner: runner.Exec{}, Events: log, StateDir: state, Holds: store, Hardware: &hostpolicy.Policy{StateDir: state}, UFWActive: hostfw.UFWActive,
		ExchangeRoot: instances.DefaultExchangeRoot, Subnets: &virt.Subnets{Path: filepath.Join(state, "subnets.json")},
		Images: &image.Proofs{Path: filepath.Join(state, image.ProofsFile)}}

	switch cmd {
	case "up":
		return e.Up(ctx, m)
	case "down":
		return e.Down(ctx, m)
	}

	// launch: gate first, then record, then hand the terminal to the client. A held guest's app is not opened either.
	c, cleanup, err := prepareLaunch(m, state, store, log)
	if err != nil {
		return err
	}
	defer cleanup()
	c = launch.WithIdentity(c, lo.identity)
	if lo.check {
		return launchCheck(ctx, m, c)
	}
	if err := log.Emit(events.AppLaunch, m.Name, map[string]string{"app": m.App.Name}); err != nil {
		return err
	}
	p := exec.CommandContext(ctx, c.Args[0], c.Args[1:]...)
	p.Stdin, p.Stdout, p.Stderr = os.Stdin, os.Stdout, os.Stderr
	return p.Run()
}

// launchCheck proves everything a launch needs except the window: the gates already passed (prepareLaunch), then
// ssh with the pinned key, the app and waypipe inside the guest, and waypipe and a Wayland display here. It prints one
// line per check and fails if any does.
func launchCheck(ctx context.Context, m *manifest.Manifest, c launch.Command) error {
	fmt.Printf("ok    %s is running, not held, and its host key is pinned\n", m.Name)
	failed := 0
	report := func(ok bool, good, bad string) {
		if ok {
			fmt.Println("ok    " + good)
		} else {
			fmt.Println("FAIL  " + bad)
			failed++
		}
	}
	app := strings.Fields(m.App.Exec)
	remote := "true"
	if len(app) > 0 {
		remote = "command -v -- " + shellQuote(app[0]) + " >/dev/null && command -v waypipe >/dev/null"
	}
	for i, r := range []string{"true", remote} {
		args, err := launch.CheckArgs(c, r)
		if err != nil {
			return err
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		out, err := exec.CommandContext(cctx, args[0], args[1:]...).CombinedOutput()
		cancel()
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if i == 0 {
			report(err == nil, "ssh reaches the guest and it shows the pinned host key", "ssh with the pinned key failed: "+msg)
			if err != nil {
				break
			}
		} else {
			report(err == nil, fmt.Sprintf("the guest has %q and waypipe", app[0]), fmt.Sprintf("the guest lacks %q or waypipe (install them in its image)", app[0]))
		}
	}
	_, werr := exec.LookPath("waypipe")
	report(werr == nil, "waypipe is installed here", "waypipe is not installed here (sudo pacman -S waypipe)")
	report(os.Getenv("WAYLAND_DISPLAY") != "", "a Wayland display is here", "no Wayland display here (WAYLAND_DISPLAY is not set): run launch from the desktop")
	if failed > 0 {
		return fmt.Errorf("launch check: %d of the checks failed", failed)
	}
	return nil
}

// shellQuote quotes one word for the guest's shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// launchView is what a person's `limbo launch` asks Limbo about the guest (GET /v1/instances/{name} on user.sock).
type launchView struct {
	State   string `json:"state"`
	Running bool   `json:"running"`
	Address string `json:"address"`
	Hold    *struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"hold"`
}

// askLimbo is replaced in tests.
var askLimbo = func(name string) (launchView, error) {
	var v launchView
	err := doJSON(unixClient(userSock), "GET", "/v1/instances/"+name, nil, &v)
	return v, err
}

// prepareLaunch runs every check `launch` needs and returns the client's command, with a cleanup for the known_hosts
// file it writes. Guests are started by root, so their holds and addresses are the daemon's: root reads them from the
// daemon's state folder; anyone else asks the daemon through user.sock, and without an answer nothing is launched.
func prepareLaunch(m *manifest.Manifest, state string, store *quarantine.Store, log *events.Logger) (launch.Command, func(), error) {
	none := func() {}
	refuse := func(reason string) (launch.Command, func(), error) {
		_ = log.Emit(events.GateBlocked, m.Name, map[string]string{"reason": reason})
		return launch.Command{}, none, fmt.Errorf("%w: %s", engine.ErrQuarantined, reason)
	}
	var addr string
	if geteuid() == 0 {
		if rec, held := store.Holding(m.Name); held {
			return refuse("guest is quarantined (" + rec.ID + ", " + string(rec.Status) + ")")
		}
		a, err := guestAddress(m, state)
		if err != nil {
			return launch.Command{}, none, err
		}
		addr = a
	} else {
		v, err := askLimbo(m.Name)
		if err != nil {
			return launch.Command{}, none, fmt.Errorf("launch: Limbo could not be asked whether %s is held (%v); a person's launch "+
				"goes through user.sock: join the limbo-users group (sudo gpasswd -a $USER limbo-users, then log in again)", m.Name, err)
		}
		if v.Hold != nil {
			return refuse("guest is quarantined (" + v.Hold.ID + ", " + v.Hold.Status + ")")
		}
		if !v.Running || v.Address == "" {
			return launch.Command{}, none, fmt.Errorf("launch: %s is not running", m.Name)
		}
		addr = v.Address
	}
	if err := license.Check(m); err != nil {
		_ = log.Emit(events.GateBlocked, m.Name, map[string]string{"reason": err.Error()})
		return launch.Command{}, none, err
	}
	var a, b, x, host int
	if n, _ := fmt.Sscanf(addr, "%d.%d.%d.%d", &a, &b, &x, &host); n != 4 || a != 10 || b != 213 || x < 1 || x > 254 || host != 2 {
		return launch.Command{}, none, fmt.Errorf("launch: %q is not a Limbo guest address", addr)
	}
	cp := *m
	cp.Subnet = x
	line, err := launch.KnownHostsLine(&cp)
	if err != nil {
		return launch.Command{}, none, err
	}
	f, err := os.CreateTemp("", "limbo-known-hosts-*")
	if err != nil {
		return launch.Command{}, none, err
	}
	cleanup := func() { os.Remove(f.Name()) }
	_, werr := f.WriteString(line)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		cleanup()
		return launch.Command{}, none, werr
	}
	c, err := launch.Build(&cp, f.Name())
	if err != nil {
		cleanup()
		return launch.Command{}, none, err
	}
	return c, cleanup, nil
}
