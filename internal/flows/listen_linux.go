//go:build linux

package flows

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

type errnoError syscall.Errno

func (e errnoError) Error() string { return fmt.Sprintf("flows: netlink: %v", syscall.Errno(e)) }

// Listen binds the NFLOG group and hands every Limbo packet to h until ctx ends. Between packets it waits in Go's
// network poller (epoll), so an idle Limbo does nothing. Binding needs CAP_NET_ADMIN (limbo serve is root); a group
// another program already holds is an error.
func Listen(ctx context.Context, group uint16, h func(Packet)) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("flows: netlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("flows: netlink bind: %w", err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	buf := make([]byte, 1<<16)
	for _, req := range bindRequests(group) {
		if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
			syscall.Close(fd)
			return fmt.Errorf("flows: binding NFLOG group %d: %w", group, err)
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			syscall.Close(fd)
			return fmt.Errorf("flows: binding NFLOG group %d: %w", group, err)
		}
		if err := ackError(buf[:n]); err != nil {
			syscall.Close(fd)
			return fmt.Errorf("flows: binding NFLOG group %d (is another program using it?): %w", group, err)
		}
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return err
	}
	f := os.NewFile(uintptr(fd), "nflog") // non-blocking, so reads go through the poller and Close wakes them
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()
	for {
		var n int
		var rerr error
		err := rc.Read(func(s uintptr) bool {
			n, _, rerr = syscall.Recvfrom(int(s), buf, 0)
			return rerr != syscall.EAGAIN
		})
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("flows: reading NFLOG: %w", err)
		}
		if rerr != nil {
			if rerr == syscall.EINTR || rerr == syscall.ENOBUFS { // ENOBUFS: the kernel dropped copies we were too slow for
				continue
			}
			return fmt.Errorf("flows: reading NFLOG: %w", rerr)
		}
		for _, l := range parseMessages(buf[:n]) {
			if p, ok := decode(l); ok {
				h(p)
			}
		}
	}
}
