package runs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// SSH is the real Executor.
//
// Host key checking is off on purpose: each run boots a disposable guest whose
// host keys are generated fresh at first boot, reached over a private bridge
// that exists only for that guest. There is nothing stable to pin, and the
// guest's IP is fixed by Limbo, not discovered.
type SSH struct{}

func sshArgs(ip, user, identity string) []string {
	return []string{
		"-i", identity,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		"-o", "LogLevel=ERROR",
		user + "@" + ip,
	}
}

// WaitReady polls until a trivial command succeeds.
func (SSH) WaitReady(ctx context.Context, ip, user, identity string) error {
	for {
		cmd := exec.CommandContext(ctx, "ssh", append(sshArgs(ip, user, identity), "true")...)
		if err := cmd.Run(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// Run executes command in the guest. ssh exits 255 for its own failures, which
// is reported as an error; any other status is the command's own.
func (SSH) Run(ctx context.Context, ip, user, identity, command string, limit int) (string, string, int, bool, error) {
	cmd := exec.CommandContext(ctx, "ssh", append(sshArgs(ip, user, identity), command)...)
	out, errOut := &capWriter{limit: limit}, &capWriter{limit: limit}
	cmd.Stdout, cmd.Stderr = out, errOut
	err := cmd.Run()
	trunc := out.truncated || errOut.truncated
	if err == nil {
		return out.String(), errOut.String(), 0, trunc, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode() == 255 {
			return out.String(), errOut.String(), 0, trunc, fmt.Errorf("%w: %s", errConnection, errOut.String())
		}
		return out.String(), errOut.String(), ee.ExitCode(), trunc, nil
	}
	return out.String(), errOut.String(), 0, trunc, err
}

// capWriter keeps the first limit bytes and drops the rest, remembering that it
// did. A runaway command must not be able to exhaust the daemon's memory.
type capWriter struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if room <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *capWriter) String() string { return c.buf.String() }
