//go:build linux

package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Over a real unix socket: the caller's account comes from the kernel (SO_PEERCRED), not from anything it sends.
func TestUserSocketNamesTheCallerFromTheKernel(t *testing.T) {
	s, fi, ms, _ := settingsServer(t)
	peerUID = realPeerUID // the real thing for this test
	ms.s.AskPassword = false
	sock := filepath.Join(t.TempDir(), "user.sock")
	l, err := Listen(sock, 0o600, "")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", fi.Mode(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, l, s.Handler(User))
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	resp, err := c.Post("http://limbo/v1/instances/lab/start", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	me, _ := user.Current()
	if len(fi.calls) != 1 || fi.calls[0] != "start:lab:"+me.Username {
		t.Fatalf("the caller must be the kernel's account (%s): %v", me.Username, fi.calls)
	}
	ms.s.AskPassword = true
	resp, err = c.Post("http://limbo/v1/instances/lab/stop", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || !strings.Contains(string(b), `"code":"password_required"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}
