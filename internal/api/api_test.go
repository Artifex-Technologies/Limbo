package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
)

type fakeActions struct {
	known      map[string]bool // guests with a recorded manifest
	defined    bool
	calls      []string
	holdErr    error
	releaseErr error
}

func (f *fakeActions) Guest(name string) (*manifest.Manifest, error) {
	if !f.known[name] {
		return nil, errors.New("no record of a running guest")
	}
	return &manifest.Manifest{Name: name}, nil
}
func (f *fakeActions) Defined(context.Context, *manifest.Manifest) bool { return f.defined }
func (f *fakeActions) Hold(_ context.Context, m *manifest.Manifest, l quarantine.Level) error {
	f.calls = append(f.calls, "hold:"+m.Name+":"+string(l))
	return f.holdErr
}
func (f *fakeActions) Release(_ context.Context, m *manifest.Manifest) error {
	f.calls = append(f.calls, "release:"+m.Name)
	return f.releaseErr
}
func (f *fakeActions) Down(_ context.Context, m *manifest.Manifest) error {
	f.calls = append(f.calls, "down:"+m.Name)
	return nil
}

type fakeEmitter struct {
	kinds []string
	fail  bool
}

func (f *fakeEmitter) Emit(kind, _ string, d map[string]string) error {
	if f.fail {
		return errors.New("disk full")
	}
	f.kinds = append(f.kinds, kind)
	return nil
}

type fakeRuns struct{}

func (fakeRuns) Profiles() []string { return []string{"arch-update"} }
func (fakeRuns) Skipped() any       { return []map[string]string{} }
func (fakeRuns) Details() any {
	return []map[string]any{{"name": "arch-update", "network": "none", "sudo": true, "max_seconds": 900}}
}
func (fakeRuns) Start(_ context.Context, profile, command string, _ int) (string, error) {
	if profile != "arch-update" {
		return "", errors.New("unknown profile")
	}
	return "r-1", nil
}
func (fakeRuns) Get(id string) (any, bool) { return map[string]string{"id": id}, id == "r-1" }

func newServer(t *testing.T) (*Server, *fakeActions, *fakeEmitter) {
	t.Helper()
	st, err := quarantine.Open(filepath.Join(t.TempDir(), "q"))
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeActions{known: map[string]bool{"lab": true}, defined: true}
	e := &fakeEmitter{}
	return &Server{Store: st, Actions: a, Events: e, Runs: fakeRuns{}}, a, e
}

func call(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func recID(m map[string]any) string {
	return m["record"].(map[string]any)["id"].(string)
}

// The point of the design: what Heimdall (control) and Sarina (agent) can reach.
func TestRouteTablesPerPrincipal(t *testing.T) {
	s, _, _ := newServer(t)
	_, opened := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	id := recID(opened)

	tests := []struct {
		who          Principal
		method, path string
		body         string
		want         int
	}{
		// Control may restrict and annotate...
		{Control, "POST", "/v1/quarantine", `{"guest":"lab","reason":"again"}`, 200},
		{Control, "GET", "/v1/quarantine", "", 200},
		{Control, "POST", "/v1/quarantine/" + id + "/raise", `{"level":"isolate"}`, 200},
		{Control, "POST", "/v1/quarantine/" + id + "/advisory", `{"source":"sarina","text":"looks odd"}`, 200},
		// ...but loosening and teardown do not exist on its socket.
		{Control, "POST", "/v1/quarantine/" + id + "/verdict", `{"verdict":"safe"}`, 404},
		{Control, "POST", "/v1/quarantine/" + id + "/close", `{}`, 404},
		{Control, "POST", "/v1/guests/lab/down", `{}`, 404},
		{Control, "POST", "/v1/runs", `{"profile":"arch-update","command":"true"}`, 404},
		// The agent has runs and nothing about quarantine.
		{Agent, "GET", "/v1/profiles", "", 200},
		{Agent, "POST", "/v1/runs", `{"profile":"arch-update","command":"true"}`, 202},
		{Agent, "GET", "/v1/quarantine", "", 404},
		{Agent, "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`, 404},
		{Agent, "POST", "/v1/quarantine/" + id + "/verdict", `{"verdict":"safe"}`, 404},
		{Agent, "POST", "/v1/guests/lab/down", `{}`, 404},
		// Admin has the verdict.
		{Admin, "POST", "/v1/quarantine/" + id + "/verdict", `{"verdict":"dangerous","by":"me"}`, 200},
	}
	for _, tc := range tests {
		got, _ := call(t, s.Handler(tc.who), tc.method, tc.path, tc.body)
		if got != tc.want {
			t.Errorf("%s %s %s: got %d, want %d", tc.who, tc.method, tc.path, got, tc.want)
		}
	}
}

func TestOpenAppliesHoldAndReassertsOnRepeat(t *testing.T) {
	s, a, e := newServer(t)
	h := s.Handler(Control)
	code, out := call(t, h, "POST", "/v1/quarantine", `{"guest":"lab","reason":"started with no policy","source":"heimdall"}`)
	if code != 200 || out["applied"] != true || out["created"] != true {
		t.Fatalf("%d %v", code, out)
	}
	call(t, h, "POST", "/v1/quarantine", `{"guest":"lab","reason":"still"}`)
	if len(a.calls) != 2 || a.calls[0] != "hold:lab:restrict" || a.calls[1] != "hold:lab:restrict" {
		t.Fatalf("a repeat alert must re-assert the hold: %v", a.calls)
	}
	if e.kinds[0] != "quarantine.open" || e.kinds[1] != "quarantine.raise" {
		t.Fatalf("audit: %v", e.kinds)
	}
}

func TestOpenRejectsUnknownGuestAndBadNames(t *testing.T) {
	s, a, _ := newServer(t)
	h := s.Handler(Control)
	for _, body := range []string{
		`{"guest":"ghost","reason":"x"}`,         // never started by Limbo
		`{"guest":"../etc","reason":"x"}`,        // not a valid name
		`{"guest":"lab","reason":"x","bogus":1}`, // unknown field
		`{"guest":"lab","level":"nuke"}`,         // bad level
	} {
		if code, _ := call(t, h, "POST", "/v1/quarantine", body); code < 400 {
			t.Errorf("%s accepted (%d)", body, code)
		}
	}
	if len(a.calls) != 0 {
		t.Fatalf("a rejected request touched a guest: %v", a.calls)
	}
}

func TestOpenWhenGuestNotRunningStillRecordsHold(t *testing.T) {
	s, a, _ := newServer(t)
	a.defined = false
	code, out := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	if code != 200 || out["applied"] != false || out["error"] == nil || len(a.calls) != 0 {
		t.Fatalf("%d %v %v", code, out, a.calls)
	}
	if _, held := s.Store.Holding("lab"); !held {
		t.Fatal("the record must still block the next start")
	}
}

func TestOpenReportsAFailedHoldButKeepsTheRecord(t *testing.T) {
	s, a, _ := newServer(t)
	a.holdErr = errors.New("nft exploded")
	code, out := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	if code != 200 || out["applied"] != false || !strings.Contains(out["error"].(string), "nft exploded") {
		t.Fatalf("%d %v", code, out)
	}
}

func TestVerdictSafeReleasesFirst(t *testing.T) {
	s, a, _ := newServer(t)
	_, o := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	id := recID(o)
	a.calls = nil
	code, out := call(t, s.Handler(Admin), "POST", "/v1/quarantine/"+id+"/verdict", `{"verdict":"safe","by":"greg","note":"false alarm"}`)
	if code != 200 || len(a.calls) != 1 || a.calls[0] != "release:lab" {
		t.Fatalf("%d %v %v", code, out, a.calls)
	}
	if _, held := s.Store.Holding("lab"); held {
		t.Fatal("safe verdict must free the guest")
	}
}

func TestVerdictSafeFailureLeavesRecordOpen(t *testing.T) {
	s, a, _ := newServer(t)
	_, o := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	id := recID(o)
	a.releaseErr = errors.New("nft refused")
	code, _ := call(t, s.Handler(Admin), "POST", "/v1/quarantine/"+id+"/verdict", `{"verdict":"safe"}`)
	if code != http.StatusBadGateway {
		t.Fatalf("got %d", code)
	}
	if rec, _ := s.Store.Get(id); rec.Status != quarantine.StatusOpen {
		t.Fatalf("record marked %s although the guest is still restricted", rec.Status)
	}
}

func TestVerdictDangerousIsolates(t *testing.T) {
	s, a, _ := newServer(t)
	_, o := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	id := recID(o)
	a.calls = nil
	call(t, s.Handler(Admin), "POST", "/v1/quarantine/"+id+"/verdict", `{"verdict":"dangerous"}`)
	if len(a.calls) != 1 || a.calls[0] != "hold:lab:isolate" {
		t.Fatalf("dangerous must isolate: %v", a.calls)
	}
}

func TestVerdictRefusedWhenAuditFails(t *testing.T) {
	s, a, e := newServer(t)
	_, o := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	id := recID(o)
	a.calls = nil
	e.fail = true
	code, _ := call(t, s.Handler(Admin), "POST", "/v1/quarantine/"+id+"/verdict", `{"verdict":"safe"}`)
	if code != http.StatusInternalServerError || len(a.calls) != 0 {
		t.Fatalf("an unlogged verdict must not proceed: %d %v", code, a.calls)
	}
	if rec, _ := s.Store.Get(id); rec.Status != quarantine.StatusOpen {
		t.Fatalf("status changed to %s without an audit record", rec.Status)
	}
}

func TestLoweringLevelRefused(t *testing.T) {
	s, _, _ := newServer(t)
	_, o := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x","level":"isolate"}`)
	id := recID(o)
	if code, _ := call(t, s.Handler(Control), "POST", "/v1/quarantine/"+id+"/raise", `{"level":"restrict"}`); code != http.StatusBadRequest {
		t.Fatalf("lowering returned %d", code)
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	s, _, _ := newServer(t)
	big := `{"guest":"lab","reason":"` + strings.Repeat("A", maxBody+10) + `"}`
	if code, _ := call(t, s.Handler(Control), "POST", "/v1/quarantine", big); code < 400 {
		t.Fatalf("oversized body accepted: %d", code)
	}
}

func TestAgentHasNoRoutesWithoutARunService(t *testing.T) {
	s, _, _ := newServer(t)
	s.Runs = nil
	if code, _ := call(t, s.Handler(Agent), "GET", "/v1/profiles", ""); code != 404 {
		t.Fatalf("got %d", code)
	}
}

func TestCloseRefusedWhileTheGuestStillExists(t *testing.T) {
	s, a, _ := newServer(t)
	_, o := call(t, s.Handler(Control), "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`)
	id := recID(o)
	call(t, s.Handler(Admin), "POST", "/v1/quarantine/"+id+"/verdict", `{"verdict":"dangerous"}`)
	if code, _ := call(t, s.Handler(Admin), "POST", "/v1/quarantine/"+id+"/close", `{}`); code != http.StatusConflict {
		t.Fatalf("closing while the guest runs returned %d", code)
	}
	if _, held := s.Store.Holding("lab"); !held {
		t.Fatal("hold dropped while the condemned guest still exists")
	}
	a.defined = false // the human tore it down
	if code, _ := call(t, s.Handler(Admin), "POST", "/v1/quarantine/"+id+"/close", `{}`); code != 200 {
		t.Fatalf("close after teardown returned %d", code)
	}
}

func TestProfilesEndpointKeepsTheNameListAndAddsReadOnlyDetails(t *testing.T) {
	s, _, _ := newServer(t)
	code, out := call(t, s.Handler(Agent), "GET", "/v1/profiles", "")
	if code != 200 {
		t.Fatalf("got %d", code)
	}
	names, _ := out["profiles"].([]any)
	details, _ := out["details"].([]any)
	if len(names) != 1 || names[0] != "arch-update" {
		t.Fatalf("the plain name list must remain for older clients: %v", out)
	}
	d, _ := details[0].(map[string]any)
	if d["network"] != "none" || d["sudo"] != true || d["max_seconds"] != float64(900) {
		t.Fatalf("details: %v", d)
	}
	// Details describe a profile; nothing in them can be sent back to change it.
	if code, _ := call(t, s.Handler(Agent), "POST", "/v1/profiles", `{"name":"arch-update","sudo":false}`); code != 405 && code != 404 {
		t.Fatalf("profiles must be read-only; POST returned %d", code)
	}
}

func TestProfilesEndpointAddsASkippedListAndKeepsTheOldKeys(t *testing.T) {
	s, _, _ := newServer(t)
	_, out := call(t, s.Handler(Agent), "GET", "/v1/profiles", "")
	sk, ok := out["skipped"].([]any)
	if !ok || sk == nil {
		t.Fatalf("skipped must be a (possibly empty) array, never null: %v", out)
	}
	if _, ok := out["profiles"].([]any); !ok {
		t.Fatalf("profiles key lost: %v", out)
	}
	if _, ok := out["details"].([]any); !ok {
		t.Fatalf("details key lost: %v", out)
	}
}

// sampleRuns is fakeRuns plus the admin-only sample and stop routes.
type sampleRuns struct {
	fakeRuns
	gotSample string
	stopped   bool
}

func (s *sampleRuns) StartSample(_ context.Context, profile, command, sample string, _ int) (string, error) {
	s.gotSample = sample
	return "s1", nil
}
func (s *sampleRuns) StopAgentRuns() int { s.stopped = true; return 2 }

func TestSampleRunsAndStoppingAgentRunsAreForRootOnly(t *testing.T) {
	s, _, _ := newServer(t)
	sr := &sampleRuns{}
	s.Runs = sr
	body := `{"profile":"malware-analysis","command":"limbo-decompile triage sample","sample":"abc.sample"}`
	for _, p := range []Principal{Agent, Control} {
		if code, _ := call(t, s.Handler(p), "POST", "/v1/sample-runs", body); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Fatalf("principal %v reached the sample route: %d", p, code)
		}
		if code, _ := call(t, s.Handler(p), "POST", "/v1/agent-runs/stop", ""); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Fatalf("principal %v reached the stop route: %d", p, code)
		}
	}
	if code, out := call(t, s.Handler(Admin), "POST", "/v1/sample-runs", body); code != http.StatusAccepted || sr.gotSample != "abc.sample" {
		t.Fatal(code, out)
	}
	if code, out := call(t, s.Handler(Admin), "POST", "/v1/agent-runs/stop", "{}"); code != http.StatusOK || !sr.stopped || out["stopped"] != float64(2) {
		t.Fatal(code, out)
	}
}
