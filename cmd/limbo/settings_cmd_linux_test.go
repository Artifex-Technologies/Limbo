//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubSocket(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// The Settings page can run the CLI and read the socket's own JSON, errors included.
func TestCLIJSONPassesTheSocketsAnswersThrough(t *testing.T) {
	var got []string
	sock := stubSocket(t, func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/instances/lab/start":
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"password_required: x. Remedy: y","code":"password_required","message":"x","remedy":"y"}`))
		case "/v1/status":
			w.Write([]byte(`{"version":"t","running":true,"kvm":true,"ask_password":true,"space":{"total_bytes":1}}`))
		case "/v1/instances":
			w.Write([]byte(`{"instances":[{"name":"lab"}]}`))
		case "/v1/licenses":
			w.Write([]byte(`{"licenses":[]}`))
		case "/v1/instances/lab/settings":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["cpus"] != float64(4) || body["shared_folder"] != "off" || len(body) != 2 {
				w.WriteHeader(400)
			}
			w.Write([]byte(`{"name":"lab"}`))
		}
	})
	var out bytes.Buffer
	cliOut = &out
	defer func() { cliOut = os.Stdout }()

	err := instanceCmd([]string{"start", "lab", "--socket", sock, "--json"})
	if err != errSilent || !strings.Contains(out.String(), `"code":"password_required"`) {
		t.Fatalf("%v %q", err, out.String())
	}
	out.Reset()
	if err := settingsCmd([]string{"show", "--json", "--socket", sock}); err != nil {
		t.Fatal(err)
	}
	var page map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &page); err != nil || page["status"] == nil || string(page["licenses"]) != "[]" || !strings.Contains(string(page["instances"]), `"lab"`) {
		t.Fatalf("%v %s", err, out.String())
	}
	out.Reset()
	if err := instanceCmd([]string{"set", "lab", "--cpus", "4", "--shared-folder", "off", "--socket", sock, "--json"}); err != nil {
		t.Fatalf("%v %s", err, out.String())
	}
}
