package api

import (
	"context"

	"github.com/Artifex-Technologies/Limbo/internal/engine"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
)

// EngineActions backs Actions with the real engine.
type EngineActions struct{ E *engine.Engine }

// Guest loads the manifest Up recorded. Callers can name a guest but can never
// supply a manifest, so a hold cannot be pointed at something Limbo did not start.
func (a EngineActions) Guest(name string) (*manifest.Manifest, error) {
	return engine.LoadGuest(a.E.StateDir, name)
}

func (a EngineActions) Defined(ctx context.Context, m *manifest.Manifest) bool {
	return a.E.Defined(ctx, m)
}

func (a EngineActions) Hold(ctx context.Context, m *manifest.Manifest, l quarantine.Level) error {
	return a.E.Hold(ctx, m, l)
}

func (a EngineActions) Release(ctx context.Context, m *manifest.Manifest) error {
	return a.E.Release(ctx, m)
}

func (a EngineActions) Down(ctx context.Context, m *manifest.Manifest) error {
	return a.E.Down(ctx, m)
}
