//go:build !linux

package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
)

// Listen is Linux-only: the access control is unix-socket ownership and mode.
func Listen(string, os.FileMode, string) (net.Listener, error) {
	return nil, errors.New("api: the control sockets require a Linux host")
}

// Serve is Linux-only; see Listen.
func Serve(context.Context, net.Listener, http.Handler) error {
	return errors.New("api: the control sockets require a Linux host")
}
