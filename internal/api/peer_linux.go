//go:build linux

package api

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

type connKey struct{}

// ConnContext stores the accepted connection so handlers can ask who is on the
// other end of the unix socket.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

// peerOf returns "uid=N pid=N" for the unix-socket peer (SO_PEERCRED), or
// "unknown". Recorded in the audit log as evidence of who connected.
func peerOf(ctx context.Context) string {
	c, ok := ctx.Value(connKey{}).(*net.UnixConn)
	if !ok {
		return "unknown"
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return "unknown"
	}
	out := "unknown"
	_ = raw.Control(func(fd uintptr) {
		if u, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
			out = fmt.Sprintf("uid=%d pid=%d", u.Uid, u.Pid)
		}
	})
	return out
}

// realPeerUID returns the unix-socket peer's uid (SO_PEERCRED). Used on user.sock to know whose guest is asked about;
// the socket's group is still the access control.
func realPeerUID(ctx context.Context) (int, bool) {
	c, ok := ctx.Value(connKey{}).(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, false
	}
	uid, found := 0, false
	_ = raw.Control(func(fd uintptr) {
		if u, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
			uid, found = int(u.Uid), true
		}
	})
	return uid, found
}
