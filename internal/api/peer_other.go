//go:build !linux

package api

import (
	"context"
	"net"
)

// ConnContext is a no-op off Linux, where SO_PEERCRED is unavailable.
func ConnContext(ctx context.Context, c net.Conn) context.Context { return ctx }

func peerOf(context.Context) string { return "unknown" }
