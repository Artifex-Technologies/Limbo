// Package engine brings a guest up and down. It owns the one ordering rule that
// matters for safety: the guest's firewall table is loaded before the guest
// starts, so there is never a window in which a running guest is unfiltered.
// Anything that fails after partial setup tears that setup back down.
//
// All side effects go through Runner, so tests assert the exact command
// sequence without libvirt or root.
package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/hostfw"
	"github.com/Artifex-Technologies/Limbo/internal/image"
	"github.com/Artifex-Technologies/Limbo/internal/license"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/policy"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

// Runner executes a host command, optionally feeding it stdin.
type Runner interface {
	Run(ctx context.Context, stdin string, name string, args ...string) error
}

// Emitter records an audit event. *events.Logger satisfies it.
type Emitter interface {
	Emit(kind, guest string, detail map[string]string) error
}

// Engine holds the dependencies for Up and Down.
type Engine struct {
	Runner   Runner
	Events   Emitter
	StateDir string // where generated XML is written (mode 0700)
	// Holds, if set, is consulted by Up: a held guest is not started.
	Holds Holder
	// Hardware decides whether a guest may be given host devices. Nil means no
	// guest may: a manifest that asks for a device is refused.
	Hardware Hardware
	// UFWActive, if set and true, makes Up open the guest's bridge in the host's UFW (and Down close it): see
	// package hostfw for why a default-drop host firewall otherwise starves the guest of DHCP.
	UFWActive func() bool

	before sync.Map // guest name -> driver bindings recorded at Up, checked at teardown
}

// Hardware is the host's policy on device passthrough. *hostpolicy.Policy satisfies it.
type Hardware interface {
	// Check says whether the host may ever give these devices (static).
	Check(m *manifest.Manifest) error
	// Ready says whether it is safe right now: approved, unused, no earlier damage.
	Ready(m *manifest.Manifest) error
	// Before records the devices' host drivers; After verifies them once the guest is gone.
	Before(m *manifest.Manifest) map[string]string
	After(m *manifest.Manifest, before map[string]string) error
}

// ErrHardwareDenied is returned when a guest asks for a device the host will not give.
var ErrHardwareDenied = errors.New("engine: hardware passthrough denied")

// CheckHardware applies the host policy to a guest's device request. A guest that
// asks for nothing always passes; one that asks while no policy is set never does.
func (e *Engine) CheckHardware(m *manifest.Manifest) error {
	if len(m.Devices.PCI) == 0 {
		return nil
	}
	if e == nil || e.Hardware == nil { // nil Engine: `limbo doctor` scans profiles without one
		return fmt.Errorf("%w: no host policy is configured", ErrHardwareDenied)
	}
	if err := e.Hardware.Check(m); err != nil {
		return fmt.Errorf("%w: %w", ErrHardwareDenied, err)
	}
	return nil
}

// ReadyHardware asks whether handing the guest its devices right now is safe. The
// error wraps the policy's own type (approval needed, device busy, reboot needed).
func (e *Engine) ReadyHardware(m *manifest.Manifest) error {
	if len(m.Devices.PCI) == 0 {
		return nil
	}
	if e == nil || e.Hardware == nil {
		return fmt.Errorf("%w: no host policy is configured", ErrHardwareDenied)
	}
	if err := e.Hardware.Ready(m); err != nil {
		return fmt.Errorf("%w: %w", ErrHardwareDenied, err)
	}
	return nil
}

const connect = "qemu:///system"

func (e *Engine) virsh(ctx context.Context, args ...string) error {
	return e.Runner.Run(ctx, "", "virsh", append([]string{"-c", connect}, args...)...)
}

// Up verifies, configures and starts the guest.
//
// An audit failure is fatal: an action that cannot be logged does not happen,
// because the log is the evidence trail and Heimdall's input.
func (e *Engine) Up(ctx context.Context, m *manifest.Manifest) (err error) {
	g := m.Name
	if e.Holds != nil {
		if rec, held := e.Holds.Holding(g); held {
			reason := "guest is quarantined (" + rec.ID + ", " + string(rec.Status) + ")"
			_ = e.Events.Emit(events.GateBlocked, g, map[string]string{"reason": reason})
			return fmt.Errorf("%w: %s", ErrQuarantined, reason)
		}
	}
	for _, check := range []func(*manifest.Manifest) error{e.CheckHardware, e.ReadyHardware} {
		if err := check(m); err != nil {
			_ = e.Events.Emit(events.GateBlocked, g, map[string]string{"reason": err.Error(), "pci": strings.Join(m.Devices.PCI, ",")})
			return err
		}
	}
	if len(m.Devices.PCI) > 0 {
		e.before.Store(g, e.Hardware.Before(m))
	}
	if err := exchangeSafe(m); err != nil {
		_ = e.Events.Emit(events.GateBlocked, g, map[string]string{"reason": err.Error()})
		return err
	}
	if err := license.Check(m); err != nil {
		_ = e.Events.Emit(events.GateBlocked, g, map[string]string{"reason": err.Error()})
		return err
	}
	if err := image.Verify(m.Image.Path, m.Image.SHA256); err != nil {
		_ = e.Events.Emit(events.ImageRejected, g, map[string]string{"reason": err.Error()})
		return err
	}
	if err := e.Events.Emit(events.ImageVerified, g, map[string]string{"sha256": m.Image.SHA256}); err != nil {
		return err
	}

	rootDisk := m.Image.Path
	overlay := filepath.Join(e.StateDir, virt.OverlayName(m))
	if m.Disposable {
		rootDisk = overlay
	}
	netXML, err := virt.NetworkXML(m)
	if err != nil {
		return err
	}
	domXML, err := virt.DomainXML(m, rootDisk)
	if err != nil {
		return err
	}
	rules, err := policy.NFT(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(e.StateDir, 0o700); err != nil {
		return err
	}
	netPath := filepath.Join(e.StateDir, g+".network.xml")
	domPath := filepath.Join(e.StateDir, g+".domain.xml")
	if err := os.WriteFile(netPath, netXML, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(domPath, domXML, 0o600); err != nil {
		return err
	}
	if err := saveManifest(e.StateDir, m); err != nil {
		return err
	}

	define := map[string]string{"os": m.OS, "network": m.Network.Mode}
	if len(m.Devices.PCI) > 0 {
		define["pci"] = strings.Join(m.Devices.PCI, ",") // additive: hardware handed to this guest
	}
	if err := e.Events.Emit(events.GuestDefine, g, define); err != nil {
		return err
	}
	// From here on, undo whatever was set up if anything fails.
	defer func() {
		if err != nil {
			_ = e.teardown(context.WithoutCancel(ctx), m)
		}
	}()

	if m.Disposable {
		// A fresh copy-on-write overlay per guest: the shared base image is only
		// ever opened read-only (so several guests can use it at once, which
		// libvirt's own <transient/> disks cannot), and the guest's writes die
		// with the overlay at Down.
		_ = os.Remove(overlay)
		if err = e.Runner.Run(ctx, "", "qemu-img", "create", "-f", "qcow2", "-b", m.Image.Path, "-F", "qcow2", overlay); err != nil {
			return fmt.Errorf("engine: creating disposable overlay: %w", err)
		}
	}
	if err = e.virsh(ctx, "net-define", netPath); err != nil {
		return err
	}
	if err = e.virsh(ctx, "net-start", virt.NetworkName(m)); err != nil {
		return err
	}
	// Rules before the guest exists, so they are in force from its first packet.
	if err = e.Events.Emit(events.PolicyApply, g, map[string]string{"table": policy.TableName(m)}); err != nil {
		return err
	}
	if err = e.Runner.Run(ctx, rules, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("engine: loading firewall rules: %w", err)
	}
	if err = e.openHostFirewall(ctx, m); err != nil {
		return err
	}
	if err = e.virsh(ctx, "define", domPath); err != nil {
		return err
	}
	if err = e.Events.Emit(events.GuestStart, g, nil); err != nil {
		return err
	}
	return e.virsh(ctx, "start", virt.DomainName(m))
}

// Down stops the guest and removes everything Up created. Each step runs even
// if an earlier one fails, since a half-removed guest is the worst outcome;
// failures are joined and returned.
func (e *Engine) Down(ctx context.Context, m *manifest.Manifest) error {
	if err := e.Events.Emit(events.GuestStop, m.Name, nil); err != nil {
		return err
	}
	return e.teardown(ctx, m)
}

// settleHardware checks that a passthrough device came back to the host. A device
// that did not is not an error of the teardown (the guest is gone); it is recorded
// so the next passthrough run is refused until the host is rebooted.
func (e *Engine) settleHardware(m *manifest.Manifest) {
	if len(m.Devices.PCI) == 0 || e.Hardware == nil {
		return
	}
	var before map[string]string // nil for a guest left by a crash: After then checks vfio-pci only
	if v, ok := e.before.LoadAndDelete(m.Name); ok {
		before = v.(map[string]string)
	}
	if err := e.Hardware.After(m, before); err != nil {
		_ = e.Events.Emit(events.HardwareStuck, m.Name, map[string]string{"reason": err.Error(), "pci": strings.Join(m.Devices.PCI, ",")})
	}
}

func (e *Engine) teardown(ctx context.Context, m *manifest.Manifest) error {
	steps := [][]string{
		{"destroy", virt.DomainName(m)},
		{"undefine", virt.DomainName(m)},
		{"net-destroy", virt.NetworkName(m)},
		{"net-undefine", virt.NetworkName(m)},
	}
	var errs []error
	for _, s := range steps {
		if err := e.virsh(ctx, s...); err != nil {
			errs = append(errs, err)
		}
	}
	if m.Disposable {
		// Discard everything the guest wrote (or keep it as evidence if the
		// guest was condemned). Only after the guest is destroyed.
		if err := e.discardOverlay(m); err != nil {
			errs = append(errs, err)
		}
	}
	if err := e.closeHostFirewall(ctx, m); err != nil {
		errs = append(errs, err)
	}
	// Firewall table goes last: it must outlive the guest.
	if err := e.Runner.Run(ctx, "", "nft", "delete", "table", "inet", policy.TableName(m)); err != nil {
		errs = append(errs, err)
	}
	e.settleHardware(m)
	if err := e.Events.Emit(events.PolicyRemove, m.Name, nil); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// openHostFirewall lets the guest's bridge through UFW, when UFW is on. It runs after Limbo's own table is
// loaded, so the guest is still never unfiltered; those rules are what restrict it.
func (e *Engine) openHostFirewall(ctx context.Context, m *manifest.Manifest) error {
	if e.UFWActive == nil || !e.UFWActive() {
		return nil
	}
	for _, args := range hostfw.UFWOpen(virt.BridgeName(m)) {
		if err := e.Runner.Run(ctx, "", "ufw", args...); err != nil {
			return fmt.Errorf("engine: opening the bridge in the host firewall (ufw %s): %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

// closeHostFirewall takes those rules out again; each runs even if another fails, and a rule that is already gone is not an error worth stopping for.
func (e *Engine) closeHostFirewall(ctx context.Context, m *manifest.Manifest) error {
	if e.UFWActive == nil || !e.UFWActive() {
		return nil
	}
	var errs []error
	for _, args := range hostfw.UFWClose(virt.BridgeName(m)) {
		if err := e.Runner.Run(ctx, "", "ufw", args...); err != nil {
			errs = append(errs, fmt.Errorf("ufw %s: %w", strings.Join(args, " "), err))
		}
	}
	return errors.Join(errs...)
}

// exchangeSafe refuses a writable shared folder whose host mount allows setuid programs or device nodes: the guest's root writes
// into it as the host's root. A read-only share (the default) needs nothing.
func exchangeSafe(m *manifest.Manifest) error {
	if m.ExchangeDir == "" || !m.ExchangeWritable {
		return nil
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(m.ExchangeDir, &st); err != nil {
		return fmt.Errorf("exchange_dir %s: %w", m.ExchangeDir, err)
	}
	if !mountSafe(st.Flags) {
		return fmt.Errorf("exchange_dir %s is writable for the guest but its mount allows setuid programs and device nodes: put it on a mount with nosuid,nodev (for example a bind mount of the folder onto itself with those options), or make the share read-only", m.ExchangeDir)
	}
	return nil
}

// mountSafe: the mount has both ST_NOSUID and ST_NODEV.
func mountSafe(flags int64) bool {
	const stNosuid, stNodev = 0x2, 0x4
	return flags&stNosuid != 0 && flags&stNodev != 0
}
