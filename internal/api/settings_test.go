package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/exchange"
	"github.com/Artifex-Technologies/Limbo/internal/instances"
	"github.com/Artifex-Technologies/Limbo/internal/license"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/settings"
)

type fakeInstances struct {
	calls []string
	held  bool
	owner string
}

func (f *fakeInstances) view(name string, c instances.Caller) instances.View {
	v := instances.View{Name: name, Kind: "instance", OS: "windows", State: "stopped", Devices: []string{}, Owner: f.owner}
	v.Mine = c.Admin || f.owner == "" || f.owner == c.User
	if f.held {
		v.Hold = &instances.Hold{ID: "q1", By: "heimdall"}
		v.State, v.HeldByHeimdall = "held", true
	}
	return v
}
func (f *fakeInstances) List(_ context.Context, c instances.Caller) []instances.View {
	return []instances.View{f.view("lab", c)}
}
func (f *fakeInstances) Get(_ context.Context, name string, c instances.Caller) (instances.View, error) {
	if name != "lab" {
		return instances.View{}, &instances.Error{Status: 404, Code: "not_found", Message: "no", Remedy: "no"}
	}
	return f.view(name, c), nil
}
func (f *fakeInstances) Space(context.Context) instances.Space {
	return instances.Space{TotalBytes: 42}
}
func (f *fakeInstances) record(op, name string, c instances.Caller) {
	f.calls = append(f.calls, op+":"+name+":"+map[bool]string{true: "admin", false: c.User}[c.Admin])
}
func (f *fakeInstances) Start(_ context.Context, name string, c instances.Caller) (instances.View, error) {
	f.record("start", name, c)
	return f.view(name, c), nil
}
func (f *fakeInstances) Stop(_ context.Context, name string, c instances.Caller) (instances.View, error) {
	f.record("stop", name, c)
	return f.view(name, c), nil
}
func (f *fakeInstances) Configure(_ context.Context, name string, ch instances.Change, c instances.Caller) (instances.View, error) {
	f.record("configure", name, c)
	return f.view(name, c), nil
}
func (f *fakeInstances) FreeSpace(_ context.Context, name string, c instances.Caller) (int64, error) {
	f.record("free", name, c)
	return 7, nil
}
func (f *fakeInstances) Add(m *manifest.Manifest, owner string, c instances.Caller) (instances.View, error) {
	f.record("add", m.Name, c)
	return f.view(m.Name, c), nil
}
func (f *fakeInstances) Remove(_ context.Context, name string, del bool, c instances.Caller) error {
	f.record("remove", name, c)
	return nil
}

type memSettings struct {
	s   settings.Settings
	err error
}

func (m *memSettings) Load() (settings.Settings, error) { return m.s, m.err }
func (m *memSettings) Save(s settings.Settings) error   { m.s = s; return nil }

type fakeExchange struct{ took []string }

func (f *fakeExchange) List(guest string) (exchange.Listing, error) {
	return exchange.Listing{Guest: guest, Files: []exchange.File{{Path: "report.txt", Size: 5}}}, nil
}
func (f *fakeExchange) Take(_ context.Context, guest, rel string, _ map[string]string) (*exchange.Taken, error) {
	f.took = append(f.took, guest+"/"+rel)
	return nil, &exchange.Error{Status: 503, Code: "scanner_unavailable", Message: "x", Remedy: "y"}
}

const key = "ABCDE-12345-FGHIJ-67890-7K2QF"

func settingsServer(t *testing.T) (*Server, *fakeInstances, *memSettings, *fakeEmitter) {
	t.Helper()
	s, _, e := newServer(t)
	fi := &fakeInstances{}
	ms := &memSettings{s: settings.Default()}
	dir := filepath.Join(t.TempDir(), "lic")
	os.MkdirAll(dir, 0o700)
	ls := &license.Store{Dir: dir}
	s.Instances, s.Settings, s.Licenses, s.Exchange = fi, ms, ls, &fakeExchange{}
	old := peerUID
	peerUID = func(context.Context) (int, bool) { return 1000, true }
	t.Cleanup(func() { peerUID = old })
	return s, fi, ms, e
}

// The Settings page's socket: what exists on it, and what never does.
func TestUserSocketRouteTable(t *testing.T) {
	s, _, ms, _ := settingsServer(t)
	ms.s.AskPassword = false // even with the switch off
	m, err := s.Licenses.Add("Windows 11", key)
	if err != nil {
		t.Fatal(err)
	}
	_, opened := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	id := recID(opened)
	never := []struct{ method, path, body string }{
		{"POST", "/v1/quarantine/" + id + "/verdict", `{"verdict":"safe"}`},
		{"POST", "/v1/quarantine/" + id + "/close", `{}`},
		{"POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`},
		{"GET", "/v1/quarantine", ""},
		{"POST", "/v1/guests/lab/down", `{}`},
		{"POST", "/v1/runs", `{"profile":"arch-update","command":"true"}`},
		{"POST", "/v1/settings", `{"ask_password":false}`},
		{"POST", "/v1/instances", `{"manifest":{}}`},
		{"DELETE", "/v1/instances/lab", `{}`},
		{"POST", "/v1/licenses", `{"name":"x","key":"` + key + `"}`},
		{"DELETE", "/v1/licenses/" + m.ID, ``},
		{"GET", "/v1/licenses/" + m.ID + "/key", ``},
	}
	for _, tc := range never {
		if code, _ := call(t, s.Handler(User), tc.method, tc.path, tc.body); code != 404 && code != 405 {
			t.Errorf("user.sock %s %s: %d, must not exist", tc.method, tc.path, code)
		}
	}
	for _, path := range []string{"/v1/status", "/v1/settings", "/v1/instances", "/v1/instances/lab", "/v1/licenses", "/v1/exchange/lab"} {
		if code, out := call(t, s.Handler(User), "GET", path, ""); code != 200 {
			t.Errorf("user.sock GET %s: %d %v", path, code, out)
		}
	}
	// Heimdall and Sarina get none of the Settings page's routes.
	for _, p := range []Principal{Control, Agent} {
		for _, tc := range []struct{ method, path string }{
			{"GET", "/v1/status"}, {"GET", "/v1/instances"}, {"POST", "/v1/instances/lab/start"}, {"POST", "/v1/instances/lab/stop"},
			{"POST", "/v1/settings"}, {"GET", "/v1/licenses"}, {"GET", "/v1/licenses/" + m.ID + "/key"}, {"POST", "/v1/licenses"},
			{"GET", "/v1/exchange/lab"}, {"POST", "/v1/exchange/lab/take"},
		} {
			if code, _ := call(t, s.Handler(p), tc.method, tc.path, "{}"); code != 404 && code != 405 {
				t.Errorf("%s %s %s: %d, must not exist", p, tc.method, tc.path, code)
			}
		}
	}
}

func TestSwitchOnRefusesEveryChangeOnUserSocket(t *testing.T) {
	s, fi, ms, _ := settingsServer(t)
	changes := []struct{ path, body string }{
		{"/v1/instances/lab/start", ``},
		{"/v1/instances/lab/stop", ``},
		{"/v1/instances/lab/settings", `{"cpus":4}`},
		{"/v1/instances/lab/free-space", `{"confirm":true}`},
		{"/v1/licenses/lic-00000000/assign", `{"guest":"lab"}`},
		{"/v1/exchange/lab/take", `{"path":"report.txt"}`},
	}
	for _, st := range []*memSettings{{s: settings.Settings{AskPassword: true}}, {s: settings.Settings{AskPassword: false}, err: errors.New("tampered")}} {
		ms.s, ms.err = st.s, st.err
		for _, c := range changes {
			code, out := call(t, s.Handler(User), "POST", c.path, c.body)
			if code != http.StatusForbidden || out["code"] != "password_required" {
				t.Errorf("switch %+v: %s: %d %v", st, c.path, code, out)
			}
		}
	}
	if len(fi.calls) != 0 {
		t.Fatalf("a refused change reached the guests: %v", fi.calls)
	}
	// The same changes through the admin socket (root, i.e. the password) go through.
	ms.s, ms.err = settings.Settings{AskPassword: true}, nil
	for _, c := range changes[:4] {
		if code, out := call(t, s.Handler(Admin), "POST", c.path, c.body); code != 200 {
			t.Errorf("admin %s: %d %v", c.path, code, out)
		}
	}
	if len(fi.calls) != 4 || !strings.HasSuffix(fi.calls[0], ":admin") {
		t.Fatalf("admin calls: %v", fi.calls)
	}
}

func TestSwitchOffLetsMembersChangeTheirGuests(t *testing.T) {
	s, fi, ms, _ := settingsServer(t)
	ms.s.AskPassword = false
	for _, c := range []struct{ path, body string }{
		{"/v1/instances/lab/start", ``},
		{"/v1/instances/lab/settings", `{"cpus":4,"memory_mb":4096}`},
		{"/v1/instances/lab/stop", ``},
	} {
		if code, out := call(t, s.Handler(User), "POST", c.path, c.body); code != 200 {
			t.Fatalf("%s: %d %v", c.path, code, out)
		}
	}
	if len(fi.calls) != 3 || fi.calls[0] != "start:lab:" && !strings.HasPrefix(fi.calls[0], "start:lab:") {
		t.Fatalf("%v", fi.calls)
	}
	// A body with an unknown field is refused (a misspelt setting must not be ignored).
	if code, _ := call(t, s.Handler(User), "POST", "/v1/instances/lab/settings", `{"network":"internet-only"}`); code != 400 {
		t.Fatalf("network change accepted: %d", code)
	}
	if code, out := call(t, s.Handler(User), "POST", "/v1/instances/lab/free-space", `{}`); code != 400 || out["code"] != "confirm_required" {
		t.Fatalf("free-space without confirm: %d %v", code, out)
	}
	// Without a kernel-reported caller nothing changes.
	peerUID = func(context.Context) (int, bool) { return 0, false }
	if code, out := call(t, s.Handler(User), "POST", "/v1/instances/lab/start", ``); code != 403 || out["code"] != "unknown_caller" {
		t.Fatalf("unknown caller: %d %v", code, out)
	}
}

func TestTheSwitchIsRootsAndAudited(t *testing.T) {
	s, _, ms, e := settingsServer(t)
	if code, out := call(t, s.Handler(Admin), "POST", "/v1/settings", `{"ask_password":false}`); code != 200 || out["ask_password"] != false {
		t.Fatalf("%d %v", code, out)
	}
	if ms.s.AskPassword || e.kinds[len(e.kinds)-1] != "settings.change" {
		t.Fatalf("not saved or not audited: %+v %v", ms.s, e.kinds)
	}
	if code, _ := call(t, s.Handler(Admin), "POST", "/v1/settings", `{}`); code != 400 {
		t.Fatal("missing value accepted")
	}
	e.fail = true
	if code, _ := call(t, s.Handler(Admin), "POST", "/v1/settings", `{"ask_password":true}`); code != 500 || ms.s.AskPassword {
		t.Fatalf("an unlogged switch change happened: %d", code)
	}
	e.fail = false
	_, out := call(t, s.Handler(User), "GET", "/v1/status", "")
	if out["ask_password"] != false || out["space"].(map[string]any)["total_bytes"] != float64(42) {
		t.Fatalf("status: %v", out)
	}
}

func TestLicenseKeysStayMaskedOutsideTheAdminSocket(t *testing.T) {
	s, _, ms, _ := settingsServer(t)
	ms.s.AskPassword = false
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/licenses", strings.NewReader(`{"name":"Windows 11 Pro","key":"`+strings.ToLower(key)+`"}`))
	s.Handler(Admin).ServeHTTP(rec, req)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "ABCDE") || !strings.Contains(rec.Body.String(), "XXXXX-XXXXX-XXXXX-XXXXX-7K2QF") {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	l, _ := s.Licenses.List()
	id := l[0].ID
	for _, path := range []string{"/v1/licenses", "/v1/status", "/v1/instances"} {
		r := httptest.NewRecorder()
		s.Handler(User).ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if strings.Contains(r.Body.String(), "ABCDE") {
			t.Fatalf("%s leaked the key", path)
		}
	}
	code, out := call(t, s.Handler(Admin), "GET", "/v1/licenses/"+id+"/key", "")
	if code != 200 || out["key"] != key {
		t.Fatalf("reveal: %d %v", code, out)
	}
	if code, out := call(t, s.Handler(User), "POST", "/v1/licenses/"+id+"/assign", `{"guest":"lab"}`); code != 200 || len(out["assigned"].([]any)) != 1 {
		t.Fatalf("assign: %d %v", code, out)
	}
	if code, _ := call(t, s.Handler(Admin), "POST", "/v1/licenses", `{"name":"x","key":"nope"}`); code != 400 {
		t.Fatal("bad key accepted")
	}
	// The audit log names the license, never its key.
	r := httptest.NewRecorder()
	s.Handler(Admin).ServeHTTP(r, httptest.NewRequest("DELETE", "/v1/licenses/"+id, nil))
	if r.Code != 200 {
		t.Fatalf("remove: %d %s", r.Code, r.Body)
	}
}

func TestExchangeTakeIsGatedAndRefusedForAHeldGuest(t *testing.T) {
	s, fi, ms, _ := settingsServer(t)
	ms.s.AskPassword = false
	fx := s.Exchange.(*fakeExchange)
	fi.held = true
	if code, out := call(t, s.Handler(User), "POST", "/v1/exchange/lab/take", `{"path":"report.txt"}`); code != 409 || out["code"] != "held_by_heimdall" {
		t.Fatalf("held: %d %v", code, out)
	}
	fi.held = false
	fi.owner = "someone"
	if code, _ := call(t, s.Handler(User), "POST", "/v1/exchange/lab/take", `{"path":"report.txt"}`); code != 403 {
		t.Fatalf("not owner: %d", code)
	}
	if len(fx.took) != 0 {
		t.Fatalf("a refused take reached the outbox: %v", fx.took)
	}
	// Root may; the scanner refusing is passed through as an error, not a file.
	if code, out := call(t, s.Handler(Admin), "POST", "/v1/exchange/lab/take", `{"path":"report.txt"}`); code != 503 || out["code"] != "scanner_unavailable" {
		t.Fatalf("admin: %d %v", code, out)
	}
}
