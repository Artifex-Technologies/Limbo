package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/policy"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

// ErrQuarantined is returned by Up for a guest that is held.
var ErrQuarantined = errors.New("engine: guest is quarantined")

// Holder answers whether a guest is currently held. *quarantine.Store satisfies
// it; Engine.Up consults it so a quarantined or condemned guest cannot simply be
// started again.
type Holder interface {
	Holding(guest string) (quarantine.Record, bool)
}

// ManifestPath is where Up leaves a copy of the manifest it started a guest
// from. The quarantine server reads it back, so a hold can be applied to (or
// lifted from) a guest knowing only its name, with no way for the caller to
// supply a different manifest.
func ManifestPath(stateDir, guest string) string {
	return filepath.Join(stateDir, guest+".manifest.json")
}

// LoadGuest reads back the manifest Up recorded for a running guest.
func LoadGuest(stateDir, guest string) (*manifest.Manifest, error) {
	probe := &manifest.Manifest{Name: guest}
	if err := probe.ValidateName(); err != nil {
		return nil, err
	}
	m, err := manifest.Load(ManifestPath(stateDir, guest))
	if err != nil {
		return nil, fmt.Errorf("engine: no record of a running guest %q: %w", guest, err)
	}
	if m.Name != guest {
		return nil, fmt.Errorf("engine: manifest record for %q names a different guest", guest)
	}
	return m, nil
}

func saveManifest(stateDir string, m *manifest.Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ManifestPath(stateDir, m.Name), b, 0o600)
}

// Restrict replaces the guest's firewall table with the deny-all ruleset,
// atomically. The guest keeps running and the host can still reach it.
//
// Restricting only ever makes things safer, so it is attempted even if the audit
// event cannot be written (the failure is returned afterwards): refusing to
// quarantine because the log is full would be the wrong trade.
func (e *Engine) Restrict(ctx context.Context, m *manifest.Manifest) error {
	rules, err := policy.NFTRestrict(m)
	if err != nil {
		return err
	}
	logErr := e.Events.Emit(events.PolicyRestrict, m.Name, map[string]string{"table": policy.TableName(m)})
	if err := e.Runner.Run(ctx, rules, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("engine: restricting %s: %w", m.Name, err)
	}
	return logErr
}

// Isolate restricts and then takes the guest's virtual link down, so the cut
// holds even if the firewall were tampered with. The host loses the guest too.
func (e *Engine) Isolate(ctx context.Context, m *manifest.Manifest) error {
	if err := e.Restrict(ctx, m); err != nil {
		return err
	}
	logErr := e.Events.Emit(events.LinkDown, m.Name, map[string]string{"interface": virt.TapName(m)})
	if err := e.virsh(ctx, "domif-setlink", virt.DomainName(m), virt.TapName(m), "down"); err != nil {
		return fmt.Errorf("engine: taking link down for %s: %w", m.Name, err)
	}
	return logErr
}

// Hold applies a quarantine level.
func (e *Engine) Hold(ctx context.Context, m *manifest.Manifest, level quarantine.Level) error {
	switch level {
	case quarantine.LevelRestrict:
		return e.Restrict(ctx, m)
	case quarantine.LevelIsolate:
		return e.Isolate(ctx, m)
	}
	return quarantine.ErrBadLevel
}

// Release restores the firewall the manifest asked for and brings the link back
// up. This loosens, so unlike Restrict it fails closed: if the audit event
// cannot be written, nothing is released.
func (e *Engine) Release(ctx context.Context, m *manifest.Manifest) error {
	rules, err := policy.NFTRelease(m)
	if err != nil {
		return err
	}
	if err := e.Events.Emit(events.PolicyRelease, m.Name, map[string]string{"table": policy.TableName(m)}); err != nil {
		return err
	}
	if err := e.Runner.Run(ctx, rules, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("engine: releasing %s: %w", m.Name, err)
	}
	if err := e.Events.Emit(events.LinkUp, m.Name, map[string]string{"interface": virt.TapName(m)}); err != nil {
		return err
	}
	return e.virsh(ctx, "domif-setlink", virt.DomainName(m), virt.TapName(m), "up")
}

// discardOverlay removes a disposable guest's overlay at teardown. A guest the
// human condemned is the exception: its overlay is the evidence, so it is moved
// aside instead of deleted.
func (e *Engine) discardOverlay(m *manifest.Manifest) error {
	ov := filepath.Join(e.StateDir, virt.OverlayName(m))
	if _, err := os.Stat(ov); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if e.Holds != nil {
		if rec, held := e.Holds.Holding(m.Name); held && rec.Status == quarantine.StatusDangerous {
			dir := filepath.Join(e.StateDir, "evidence")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			return os.Rename(ov, filepath.Join(dir, rec.ID+".overlay.qcow2"))
		}
	}
	return os.Remove(ov)
}

// Defined reports whether the guest exists in libvirt. Up defines it and Down
// undefines it, so this is "is it up" for Limbo's purposes.
func (e *Engine) Defined(ctx context.Context, m *manifest.Manifest) bool {
	return e.virsh(ctx, "dominfo", virt.DomainName(m)) == nil
}

// CleanState removes the generated definitions and manifest copy for a guest
// that has been torn down, unless it is held (a held guest's record may still
// be needed to apply or lift a hold).
func (e *Engine) CleanState(m *manifest.Manifest) {
	if e.Holds != nil {
		if _, held := e.Holds.Holding(m.Name); held {
			return
		}
	}
	for _, f := range []string{m.Name + ".network.xml", m.Name + ".domain.xml", m.Name + ".manifest.json"} {
		_ = os.Remove(filepath.Join(e.StateDir, f))
	}
}
