package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/engine"
	"github.com/Artifex-Technologies/Limbo/internal/exchange"
	"github.com/Artifex-Technologies/Limbo/internal/instances"
	"github.com/Artifex-Technologies/Limbo/internal/license"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/parity"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/settings"
)

// The fakes the parity scenarios run with; rust/limbo/tests/parity_api.rs has the same ones.

type pActions struct {
	known                       map[string]bool
	defined                     bool
	holdErr, releaseErr, downEr string
	calls                       []string
}

func (f *pActions) Guest(name string) (*manifest.Manifest, error) {
	if !f.known[name] {
		return nil, errors.New("engine: no record of a running guest " + fmt.Sprintf("%q", name))
	}
	return &manifest.Manifest{Name: name}, nil
}
func (f *pActions) Defined(context.Context, *manifest.Manifest) bool { return f.defined }
func (f *pActions) Hold(_ context.Context, m *manifest.Manifest, l quarantine.Level) error {
	f.calls = append(f.calls, "hold:"+m.Name+":"+string(l))
	if f.holdErr != "" {
		return errors.New(f.holdErr)
	}
	return nil
}
func (f *pActions) Release(_ context.Context, m *manifest.Manifest) error {
	f.calls = append(f.calls, "release:"+m.Name)
	if f.releaseErr != "" {
		return errors.New(f.releaseErr)
	}
	return nil
}
func (f *pActions) Down(_ context.Context, m *manifest.Manifest) error {
	f.calls = append(f.calls, "down:"+m.Name)
	if f.downEr != "" {
		return errors.New(f.downEr)
	}
	return nil
}

type pEvents struct {
	evs       []map[string]any
	failAfter int // fail every emit once this many were written (0: never)
}

func (f *pEvents) Emit(kind, guest string, d map[string]string) error {
	if f.failAfter > 0 && len(f.evs) >= f.failAfter {
		return errors.New("disk full")
	}
	f.evs = append(f.evs, map[string]any{"kind": kind, "guest": guest, "detail": d})
	return nil
}

// pRuns answers by profile name: "arch-update" starts r00000001, "busy" is busy, "gone" is profile_unknown, "plain" an
// uncoded error.
type pRuns struct{ stopped int }

func (pRuns) Profiles() []string { return []string{"arch-update"} }
func (pRuns) Details() any {
	return []map[string]any{{"name": "arch-update", "network": "none", "sudo": true, "passthrough": false, "max_seconds": 900}}
}
func (pRuns) Skipped() any {
	return []map[string]string{{"name": "broken", "code": "profile_invalid", "reason": "the profile file is not valid JSON or has unknown fields", "remedy": "ask the operator to fix the profile file"}}
}
func (pRuns) start(profile string) (string, error) {
	switch profile {
	case "arch-update":
		return "r00000001", nil
	case "busy":
		return "", badRequest{"busy", "2 validation runs are already in progress", "wait about a minute and retry"}
	case "gone":
		return "", badRequest{"profile_unknown", "there is no profile named \"gone\"", "call limbo_profiles for the names that exist"}
	}
	return "", errors.New("unknown profile")
}
func (r pRuns) Start(_ context.Context, profile, _ string, _ int) (string, error) {
	return r.start(profile)
}
func (r pRuns) StartBundle(_ context.Context, profile, _ string, _ []byte, _ int) (string, error) {
	return r.start(profile)
}
func (r pRuns) StartSample(_ context.Context, profile, _, _ string, _ int) (string, error) {
	return r.start(profile)
}
func (r *pRuns) StopAgentRuns() int { r.stopped++; return r.stopped }
func (pRuns) Get(id string) (any, bool) {
	return map[string]any{"id": id, "status": "running"}, id == "r00000001"
}

type pSettings struct {
	s   settings.Settings
	err string
}

func (f *pSettings) Load() (settings.Settings, error) {
	if f.err != "" {
		return settings.Default(), errors.New(f.err)
	}
	return f.s, nil
}
func (f *pSettings) Save(s settings.Settings) error { f.s = s; return nil }

// Step is one request of a scenario; {q1}, {q2}, ... in the path stand for the quarantine records made so far.
type Step struct {
	P      string `json:"p"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
}

// Scenario is a server set up a certain way and the requests sent to it.
type Scenario struct {
	Name       string   `json:"name"`
	Known      []string `json:"known"`
	Defined    bool     `json:"defined"`
	HoldErr    string   `json:"hold_err"`
	ReleaseErr string   `json:"release_err"`
	DownErr    string   `json:"down_err"`
	FailAfter  int      `json:"fail_after"`
	NoRuns     bool     `json:"no_runs"`
	Ask        bool     `json:"ask"`
	SettingErr string   `json:"settings_err"`
	Steps      []Step   `json:"steps"`
}

var principals = map[string]Principal{"admin": Admin, "control": Control, "agent": Agent, "user": User}

var (
	timeRe = regexp.MustCompile(`"\d{4}-\d\d-\d\dT[0-9:.]+Z"`)
)

func st(p, m, path, body string) Step { return Step{p, m, path, body} }

func apiScenarios() []Scenario {
	q := `{"guest":"lab","reason":"started with no policy","source":"heimdall:limbo-guest"}`
	all := []Scenario{
		{Name: "route tables", Known: []string{"lab"}, Defined: true, Steps: []Step{
			st("control", "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab","reason":"again"}`),
			st("control", "GET", "/v1/quarantine", ""),
			st("control", "GET", "/v1/quarantine/{q1}", ""),
			st("control", "POST", "/v1/quarantine/{q1}/raise", `{"level":"isolate"}`),
			st("control", "POST", "/v1/quarantine/{q1}/advisory", `{"source":"sarina","text":"looks odd"}`),
			st("control", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"safe"}`),
			st("control", "POST", "/v1/quarantine/{q1}/close", `{}`),
			st("control", "POST", "/v1/guests/lab/down", `{}`),
			st("control", "POST", "/v1/runs", `{"profile":"arch-update","command":"true"}`),
			st("control", "GET", "/v1/status", ""),
			st("control", "POST", "/v1/settings", `{"ask_password":false}`),
			st("agent", "GET", "/v1/profiles", ""),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","command":"true"}`),
			st("agent", "GET", "/v1/runs/r00000001", ""),
			st("agent", "GET", "/v1/quarantine", ""),
			st("agent", "POST", "/v1/quarantine", `{"guest":"lab","reason":"x"}`),
			st("agent", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"safe"}`),
			st("agent", "POST", "/v1/guests/lab/down", `{}`),
			st("agent", "POST", "/v1/sample-runs", `{}`),
			st("agent", "POST", "/v1/agent-runs/stop", `{}`),
			st("agent", "GET", "/v1/instances", ""),
			st("control", "GET", "/v1/guests/lab", ""),
			st("admin", "GET", "/v1/guests/lab", ""),
			st("agent", "GET", "/v1/guests/lab", ""),
			st("control", "GET", "/v1/guests/torn-down", ""),
			st("user", "GET", "/v1/quarantine", ""),
			st("user", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"safe"}`),
			st("user", "POST", "/v1/settings", `{"ask_password":false}`),
			st("user", "GET", "/v1/settings", ""),
			st("admin", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"dangerous","by":"me"}`),
			st("admin", "POST", "/v1/quarantine/{q1}/close", `{"by":"me"}`),
		}},
		{Name: "mux", Known: []string{"lab"}, Defined: true, Steps: []Step{
			st("control", "GET", "/v1/quarantine/", ""),
			st("control", "GET", "/v1//quarantine", ""),
			st("control", "GET", "/v1/quarantine/../quarantine", ""),
			st("control", "POST", "/v1/./quarantine", `{}`),
			st("control", "DELETE", "/v1/quarantine", ""),
			st("control", "PUT", "/v1/guests/lab", ""),
			st("control", "HEAD", "/v1/quarantine", ""),
			st("control", "GET", "/v1/guests/l%61b", ""),
			st("control", "GET", "/v1/guests/a%2Fb", ""),
			st("control", "GET", "/v1/quarantine/x/raise", ""),
			st("control", "GET", "/", ""),
			st("control", "GET", "/v1", ""),
			st("admin", "PATCH", "/v1/instances/lab", ""),
			st("admin", "GET", "/v1/licenses/lic-00000000/assign", ""),
			st("agent", "POST", "/v1/runs/r00000001", ""),
			st("agent", "GET", "/v1/profiles?x=1", ""),
			st("agent", "GET", "/V1/PROFILES", ""),
		}},
		{Name: "open, repeat, decode errors", Known: []string{"lab"}, Defined: true, Steps: []Step{
			st("control", "POST", "/v1/quarantine", q),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab","reason":"still","level":"isolate","evidence":{"rule":"x","\u0000k":"v\u001b"}}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"ghost","reason":"x"}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"../etc","reason":"x"}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab","reason":"x","bogus":1}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab","level":"nuke"}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab","level":5}`),
			st("control", "POST", "/v1/quarantine", `{"guest":["lab"]}`),
			st("control", "POST", "/v1/quarantine", `{"GUEST":"lab","Reason":"case"}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab",`),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab"} {"x":`),
			st("control", "POST", "/v1/quarantine", `[]`),
			st("control", "POST", "/v1/quarantine", `nul`),
			st("control", "POST", "/v1/quarantine", `{'guest':1}`),
			st("control", "POST", "/v1/quarantine", ``),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab","evidence":{"a":1}}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"lab","reason":"`+strings.Repeat("A", 70000)+`"}`),
			st("control", "POST", "/v1/quarantine/{q1}/raise", `{"level":"restrict"}`),
			st("control", "POST", "/v1/quarantine/{q1}/raise", `{"level":"other"}`),
			st("control", "POST", "/v1/quarantine/q-ffffffffffff/raise", `{"level":"isolate"}`),
			st("control", "POST", "/v1/quarantine/{q1}/raise", `{"level":true}`),
			st("control", "POST", "/v1/quarantine/{q1}/advisory", `{"source":"sarina","text":"\u001b[31mred"}`),
			st("control", "POST", "/v1/quarantine/{q1}/advisory", `{"source":1}`),
			st("control", "GET", "/v1/quarantine/q-ffffffffffff", ""),
			st("control", "GET", "/v1/quarantine", ""),
		}},
		{Name: "not running", Known: []string{"lab"}, Defined: false, Steps: []Step{
			st("control", "POST", "/v1/quarantine", q),
			st("admin", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"safe","by":" root ","note":"fine"}`),
		}},
		{Name: "hold fails", Known: []string{"lab", "web"}, Defined: true, HoldErr: "nft: boom", Steps: []Step{
			st("control", "POST", "/v1/quarantine", q),
			st("control", "POST", "/v1/quarantine/{q1}/raise", `{"level":"isolate"}`),
			st("admin", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"dangerous"}`),
			st("admin", "POST", "/v1/quarantine/{q1}/close", `{"by":"root"}`),
		}},
		{Name: "verdicts", Known: []string{"lab", "web", "db"}, Defined: true, Steps: []Step{
			st("control", "POST", "/v1/quarantine", q),
			st("control", "POST", "/v1/quarantine", `{"guest":"web","reason":"r"}`),
			st("control", "POST", "/v1/quarantine", `{"guest":"db","reason":"r"}`),
			st("admin", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"safe","by":"root"}`),
			st("admin", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"dangerous"}`),
			st("admin", "POST", "/v1/quarantine/{q2}/verdict", `{"verdict":"maybe"}`),
			st("admin", "POST", "/v1/quarantine/{q2}/verdict", `{"verdict":"dangerous","by":"root","note":"bad"}`),
			st("admin", "POST", "/v1/quarantine/{q2}/close", `{"by":"root"}`),
			st("admin", "POST", "/v1/quarantine/{q1}/close", `{"by":"root"}`),
			st("admin", "POST", "/v1/quarantine/q-ffffffffffff/verdict", `{"verdict":"safe"}`),
			st("admin", "POST", "/v1/guests/web/down", `{}`),
			st("admin", "POST", "/v1/guests/ghost/down", `{}`),
			st("control", "POST", "/v1/quarantine/{q2}/raise", `{"level":"isolate"}`),
			st("admin", "GET", "/v1/quarantine", ""),
		}},
		{Name: "release fails", Known: []string{"lab"}, Defined: true, ReleaseErr: "nft: boom", DownErr: "virsh: gone", Steps: []Step{
			st("control", "POST", "/v1/quarantine", q),
			st("admin", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"safe"}`),
			st("admin", "GET", "/v1/quarantine/{q1}", ""),
			st("admin", "POST", "/v1/guests/lab/down", `{}`),
		}},
		{Name: "audit fails", Known: []string{"lab"}, Defined: true, FailAfter: 1, Steps: []Step{
			st("control", "POST", "/v1/quarantine", q),
			st("admin", "POST", "/v1/quarantine/{q1}/verdict", `{"verdict":"safe"}`),
			st("admin", "POST", "/v1/settings", `{"ask_password":false}`),
			st("admin", "GET", "/v1/quarantine/{q1}", ""),
		}},
		{Name: "agent", Known: []string{"lab"}, Defined: true, Steps: []Step{
			st("agent", "GET", "/v1/profiles", ""),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","command":"pacman -Syu","timeout_seconds":60}`),
			st("agent", "POST", "/v1/runs", `{"profile":"busy","command":"true"}`),
			st("agent", "POST", "/v1/runs", `{"profile":"gone","command":"true"}`),
			st("agent", "POST", "/v1/runs", `{"profile":"plain","command":"true"}`),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","command":"true","bogus":true}`),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","command":"`+strings.Repeat("x", 70000)+`"}`),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","timeout_seconds":"60"}`),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","timeout_seconds":1.5}`),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","command":"x","bundle":"aGVsbG8="}`),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","command":"x","bundle":"not base64!"}`),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","command":"x","bundle":"aGVsbG8"}`),
			st("agent", "POST", "/v1/runs", `{"profile":"busy","command":"x","bundle":"aGk="}`),
			st("agent", "GET", "/v1/runs/r00000001", ""),
			st("agent", "GET", "/v1/runs/r99999999", ""),
			st("admin", "POST", "/v1/sample-runs", `{"profile":"arch-update","command":"file sample","sample":"x.bin"}`),
			st("admin", "POST", "/v1/sample-runs", `{"profile":"busy","command":"x","sample":"x.bin"}`),
			st("admin", "POST", "/v1/sample-runs", `{"profile":"arch-update","nope":1}`),
			st("admin", "POST", "/v1/agent-runs/stop", `{}`),
			st("admin", "GET", "/v1/runs/r00000001", ""),
		}},
		{Name: "no run service", Known: []string{"lab"}, NoRuns: true, Steps: []Step{
			st("agent", "GET", "/v1/profiles", ""),
			st("agent", "POST", "/v1/runs", `{"profile":"arch-update","command":"true"}`),
			st("admin", "POST", "/v1/sample-runs", `{}`),
		}},
		{Name: "settings switch on", Known: []string{"lab"}, Ask: true, Steps: []Step{
			st("user", "GET", "/v1/settings", ""),
			st("user", "POST", "/v1/instances/lab/start", `{}`),
			st("user", "POST", "/v1/instances/lab/stop", `{}`),
			st("user", "POST", "/v1/instances/lab/settings", `{"cpus":2}`),
			st("user", "POST", "/v1/instances/lab/free-space", `{"confirm":true}`),
			st("user", "POST", "/v1/licenses/lic-00000000/assign", `{"guest":"lab"}`),
			st("user", "POST", "/v1/exchange/lab/take", `{"path":"a.txt"}`),
			st("admin", "POST", "/v1/settings", `{"ask_password":false}`),
			st("admin", "POST", "/v1/settings", `{}`),
			st("admin", "POST", "/v1/settings", `{"ask_password":"no"}`),
			st("admin", "POST", "/v1/settings", `{"ask_password":true,"x":1}`),
			st("user", "GET", "/v1/settings", ""),
		}},
		{Name: "settings switch off, caller unknown", Known: []string{"lab"}, Ask: false, Steps: []Step{
			st("user", "GET", "/v1/settings", ""),
			st("user", "POST", "/v1/instances/lab/start", `{}`),
			st("user", "POST", "/v1/exchange/lab/take", `{"path":"a.txt"}`),
		}},
		{Name: "settings unreadable", Known: []string{"lab"}, Ask: false, SettingErr: "settings: /etc/limbo/settings.json is not owned by root", Steps: []Step{
			st("user", "GET", "/v1/settings", ""),
			st("user", "POST", "/v1/instances/lab/stop", `{}`),
		}},
	}
	return all
}

// TestParityAPI runs the scenarios through the Go handlers with the fakes above and records every answer and event.
func TestParityAPI(t *testing.T) {
	var cases []parity.Case
	for _, sc := range apiScenarios() {
		dir := t.TempDir()
		store, err := quarantine.Open(filepath.Join(dir, "q"))
		if err != nil {
			t.Fatal(err)
		}
		known := map[string]bool{}
		for _, k := range sc.Known {
			known[k] = true
		}
		a := &pActions{known: known, defined: sc.Defined, holdErr: sc.HoldErr, releaseErr: sc.ReleaseErr, downEr: sc.DownErr}
		ev := &pEvents{failAfter: sc.FailAfter}
		srv := &Server{Store: store, Actions: a, Events: ev, Settings: &pSettings{s: settings.Settings{AskPassword: sc.Ask}, err: sc.SettingErr}}
		if !sc.NoRuns {
			srv.Runs = &pRuns{}
		}
		// the Settings page's services, empty: their routes exist, and these scenarios only reach their gates
		e := &engine.Engine{Runner: noRunner{}, Events: ev, StateDir: filepath.Join(dir, "state")}
		srv.Instances = &instances.Service{Dir: filepath.Join(dir, "instances"), StateDir: filepath.Join(dir, "state"), LimboRoot: dir,
			ExchangeRoot: filepath.Join(dir, "exchange"), Guests: e, Holds: store, Events: ev}
		srv.Licenses = noLicenses{}
		srv.Exchange = &exchange.Service{Root: filepath.Join(dir, "exchange")}
		var ids []string
		var steps []map[string]any
		for _, s := range sc.Steps {
			path := s.Path
			for i, id := range ids {
				path = strings.ReplaceAll(path, fmt.Sprintf("{q%d}", i+1), id)
			}
			req := httptest.NewRequest(s.Method, path, strings.NewReader(s.Body))
			rec := httptest.NewRecorder()
			srv.Handler(principals[s.P]).ServeHTTP(rec, req)
			body := rec.Body.String()
			for _, m := range regexp.MustCompile(`q-[0-9a-f]{12}`).FindAllString(body, -1) {
				seen := false
				for _, id := range ids {
					seen = seen || id == m
				}
				if !seen && m != "q-ffffffffffff" {
					ids = append(ids, m)
				}
			}
			steps = append(steps, map[string]any{"status": rec.Code, "body": body, "content_type": rec.Header().Get("Content-Type"),
				"allow": rec.Header().Get("Allow"), "location": rec.Header().Get("Location")})
		}
		norm := func(x string) string {
			for i, id := range ids {
				x = strings.ReplaceAll(x, id, fmt.Sprintf("q-%012d", i+1))
			}
			return timeRe.ReplaceAllString(x, `"T"`)
		}
		for _, s := range steps {
			s["body"] = norm(s["body"].(string))
		}
		evs, _ := json.Marshal(ev.evs)
		in, _ := json.Marshal(sc)
		cases = append(cases, parity.Case{Fn: "api", In: json.RawMessage(in), Out: map[string]any{"steps": steps, "events": norm(string(evs)), "calls": a.calls}})
	}
	parity.Fixture(t, "api", cases)
}

type noRunner struct{}

func (noRunner) Run(context.Context, string, string, ...string) error { return errors.New("no runner") }

type noLicenses struct{}

func (noLicenses) List() ([]license.Masked, error) { return []license.Masked{}, nil }
func (noLicenses) Add(string, string) (license.Masked, error) {
	return license.Masked{}, license.ErrBadKey
}
func (noLicenses) Remove(string) error           { return license.ErrNoLicense }
func (noLicenses) Reveal(string) (string, error) { return "", license.ErrNoLicense }
func (noLicenses) Assign(string, string) (license.Masked, error) {
	return license.Masked{}, license.ErrNoLicense
}
func (noLicenses) Unassign(string, string) (license.Masked, error) {
	return license.Masked{}, license.ErrNoLicense
}
