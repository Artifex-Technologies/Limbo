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

	"github.com/Artifex-Technologies/Limbo/internal/events"
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

	if err := e.Events.Emit(events.GuestDefine, g, map[string]string{"os": m.OS, "network": m.Network.Mode}); err != nil {
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
	// Firewall table goes last: it must outlive the guest.
	if err := e.Runner.Run(ctx, "", "nft", "delete", "table", "inet", policy.TableName(m)); err != nil {
		errs = append(errs, err)
	}
	if err := e.Events.Emit(events.PolicyRemove, m.Name, nil); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
