package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The agent socket's failures reach Sarina as {"error": one line}, which is all
// its client shows the model, so that line must carry the code and the remedy.

type startErrRuns struct {
	fakeRuns
	err error
	ctx *context.Context
}

func (f startErrRuns) Start(ctx context.Context, _, _ string, _ int) (string, error) {
	if f.ctx != nil {
		*f.ctx = ctx
	}
	return "", f.err
}

type codedTest struct{ code string }

func (c codedTest) Error() string      { return c.code + ": msg. Remedy: fix it" }
func (c codedTest) ErrCode() string    { return c.code }
func (c codedTest) ErrMessage() string { return "msg" }
func (c codedTest) ErrRemedy() string  { return "fix it" }

func fields(t *testing.T, out map[string]any, want ...string) {
	t.Helper()
	for _, k := range want {
		if s, _ := out[k].(string); s == "" {
			t.Fatalf("response lacks %q: %v", k, out)
		}
	}
}

func TestMalformedRunRequestIsBadRequestAndLogged(t *testing.T) {
	s, _, e := newServer(t)
	for _, body := range []string{`{not json`, `{"profile":"arch-update","comand":"x"}`} {
		code, out := call(t, s.Handler(Agent), "POST", "/v1/runs", body)
		if code != http.StatusBadRequest || out["code"] != "bad_request" {
			t.Fatalf("%q: %d %v", body, code, out)
		}
		fields(t, out, "error", "message", "remedy")
		if !strings.HasPrefix(out["error"].(string), "bad_request: ") {
			t.Fatalf("the error line must lead with the code: %v", out["error"])
		}
	}
	if n := strings.Count(strings.Join(e.kinds, ","), "run.error"); n != 2 {
		t.Fatalf("each bad request must be logged: %v", e.kinds)
	}
}

func TestOversizedRunRequestIsBadRequestWithAnExplanation(t *testing.T) {
	s, _, _ := newServer(t)
	body := `{"profile":"arch-update","command":"` + strings.Repeat("A", maxBody+10) + `"}`
	code, out := call(t, s.Handler(Agent), "POST", "/v1/runs", body)
	if code != http.StatusBadRequest || out["code"] != "bad_request" || !strings.Contains(out["message"].(string), "larger than") {
		t.Fatalf("%d %v", code, out)
	}
}

func TestUnknownRunIsRunUnknownWithAHintAboutRestarts(t *testing.T) {
	s, _, _ := newServer(t)
	code, out := call(t, s.Handler(Agent), "GET", "/v1/runs/r00000000", "")
	if code != http.StatusNotFound || out["code"] != "run_unknown" || !strings.Contains(out["remedy"].(string), "restarted") {
		t.Fatalf("%d %v", code, out)
	}
}

func TestStartRefusalsKeepTheirCodeAndBusyIs429(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
	}{{"profile_unknown", 400}, {"profile_invalid", 400}, {"image_missing", 400}, {"busy", 429}} {
		s, _, _ := newServer(t)
		s.Runs = startErrRuns{err: codedTest{tc.code}}
		status, out := call(t, s.Handler(Agent), "POST", "/v1/runs", `{"profile":"x","command":"true"}`)
		if status != tc.status || out["code"] != tc.code || out["remedy"] != "fix it" || !strings.HasPrefix(out["error"].(string), tc.code+": ") {
			t.Fatalf("%s: %d %v", tc.code, status, out)
		}
	}
}

func TestUncodedErrorsStillGetACodeFromTheirStatus(t *testing.T) {
	s, _, _ := newServer(t)
	_, out := call(t, s.Handler(Control), "GET", "/v1/quarantine/nope", "")
	if out["code"] != "not_found" {
		t.Fatalf("%v", out)
	}
}

// The client of POST /v1/runs may disconnect at once; the run must not be
// cancelled with it (that is what keeps the guest from being orphaned half-built).
func TestRunOutlivesItsRequest(t *testing.T) {
	s, _, _ := newServer(t)
	var got context.Context
	s.Runs = startErrRuns{err: nil, ctx: &got}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/v1/runs", strings.NewReader(`{"profile":"x","command":"true"}`)).WithContext(ctx)
	cancel()
	s.Handler(Agent).ServeHTTP(httptest.NewRecorder(), req)
	if got == nil || got.Err() != nil {
		t.Fatalf("run context was cancelled with the request: %v", got)
	}
}
