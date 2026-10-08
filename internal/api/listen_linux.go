//go:build linux

package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// Listen creates a unix socket at path with the given mode, owned by group when
// one is named. This is the access control for the whole API, so the socket is
// never visible with looser permissions than intended: the umask is tightened
// before it is created, and the final mode and group are applied before the
// listener is handed back.
func Listen(path string, mode os.FileMode, group string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("api: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Listener, error) {
		l.Close()
		os.Remove(path)
		return nil, err
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fail(fmt.Errorf("api: group %q for %s does not exist (create it first, e.g. via sysusers): %w", group, path, err))
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			return fail(err)
		}
		if err := os.Chown(path, -1, gid); err != nil {
			return fail(err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		return fail(err)
	}
	return l, nil
}

// Serve runs h on l until ctx ends, recording each connection so handlers can
// read the peer's credentials.
func Serve(ctx context.Context, l net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ConnContext: ConnContext, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
