// Package runner executes host commands for the engine.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Exec runs real processes. Arguments are passed as a vector, never through a
// shell.
type Exec struct{}

// Run executes name with args, feeding stdin when non-empty. On failure the
// error carries the command's stderr, which is where virsh and nft explain
// what they objected to.
func (Exec) Run(ctx context.Context, stdin string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
