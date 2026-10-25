// Package api is Limbo's local control surface. See docs/QUARANTINE.md.
//
// There is one handler per principal, each registering only the routes that
// principal may use. A route a principal may not use does not exist on its
// socket (404), rather than existing and being refused: there is no forgotten
// authorization check to bypass, and no handler code is reachable from the
// wrong socket. Which principal a caller is comes from which socket it reached
// (file permissions); the peer's uid and pid are recorded in the audit log as
// evidence, not used for access control.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
)

// Principal is who a socket is for.
type Principal string

const (
	Admin   Principal = "admin"   // the human
	Control Principal = "control" // Heimdall: may restrict, never loosen
	Agent   Principal = "agent"   // Sarina: validation runs only
)

// Actions are the side effects the API may trigger on guests.
type Actions interface {
	// Guest loads the manifest recorded when the guest was brought up.
	Guest(name string) (*manifest.Manifest, error)
	// Defined reports whether the guest currently exists in libvirt.
	Defined(ctx context.Context, m *manifest.Manifest) bool
	Hold(ctx context.Context, m *manifest.Manifest, level quarantine.Level) error
	Release(ctx context.Context, m *manifest.Manifest) error
	Down(ctx context.Context, m *manifest.Manifest) error
}

// Emitter writes the audit log.
type Emitter interface {
	Emit(kind, guest string, detail map[string]string) error
}

// RunService is the validation-run backend (package runs). May be nil, in which
// case the agent socket serves nothing.
type RunService interface {
	Profiles() []string
	// Details describes the profiles (network mode, sudo, time cap), read-only.
	Details() any
	// Skipped says why each profile file that exists is not offered (never nil).
	Skipped() any
	Start(ctx context.Context, profile, command string, timeoutSeconds int) (id string, err error)
	Get(id string) (any, bool)
}

// BundleRunService is a RunService that can start a run carrying a small tar of files.
type BundleRunService interface {
	StartBundle(ctx context.Context, profile, command string, bundle []byte, timeoutSeconds int) (id string, err error)
}

// SampleRunService is the part of the run backend only root uses (admin socket): analysing one file in a sealed guest for Heimdall,
// and stopping Sarina's agent runs when Heimdall contains her.
type SampleRunService interface {
	StartSample(ctx context.Context, profile, command, sampleName string, timeoutSeconds int) (id string, err error)
	StopAgentRuns() int
}

// Server holds what the handlers need.
type Server struct {
	Store   *quarantine.Store
	Actions Actions
	Events  Emitter
	Runs    RunService
}

const maxBody = 64 << 10

// Handler returns the route table for one principal.
func (s *Server) Handler(p Principal) http.Handler {
	mux := http.NewServeMux()
	switch p {
	case Control, Admin:
		mux.HandleFunc("POST /v1/quarantine", s.wrap(p, s.open))
		mux.HandleFunc("GET /v1/quarantine", s.wrap(p, s.list))
		mux.HandleFunc("GET /v1/quarantine/{id}", s.wrap(p, s.get))
		mux.HandleFunc("POST /v1/quarantine/{id}/raise", s.wrap(p, s.raise))
		mux.HandleFunc("POST /v1/quarantine/{id}/advisory", s.wrap(p, s.advisory))
	}
	if p == Admin {
		mux.HandleFunc("POST /v1/quarantine/{id}/verdict", s.wrap(p, s.verdict))
		mux.HandleFunc("POST /v1/quarantine/{id}/close", s.wrap(p, s.closeRec))
		mux.HandleFunc("POST /v1/guests/{name}/down", s.wrap(p, s.down))
		if _, ok := s.Runs.(SampleRunService); ok {
			mux.HandleFunc("POST /v1/sample-runs", s.wrap(p, s.startSampleRun))
			mux.HandleFunc("GET /v1/runs/{id}", s.wrap(p, s.getRun))
			mux.HandleFunc("POST /v1/agent-runs/stop", s.wrap(p, s.stopAgentRuns))
		}
	}
	if p == Agent && s.Runs != nil {
		mux.HandleFunc("GET /v1/profiles", s.wrap(p, s.profiles))
		mux.HandleFunc("POST /v1/runs", s.wrap(p, s.startRun))
		mux.HandleFunc("GET /v1/runs/{id}", s.wrap(p, s.getRun))
	}
	return mux
}

type handler func(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error)

// wrap applies the body cap, JSON encoding and error shaping common to every route.
func (s *Server) wrap(p Principal, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		out, status, err := h(w, r, p)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(errorBody(status, err))
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}
}

// coded is a failure with a stable machine-readable code (runs.Error satisfies it).
type coded interface {
	error
	ErrCode() string
	ErrMessage() string
	ErrRemedy() string
}

// badRequest is an API-level coded error, for what is wrong before a run is attempted.
type badRequest struct{ code, msg, remedy string }

func (e badRequest) Error() string      { return e.code + ": " + e.msg + ". Remedy: " + e.remedy }
func (e badRequest) ErrCode() string    { return e.code }
func (e badRequest) ErrMessage() string { return e.msg }
func (e badRequest) ErrRemedy() string  { return e.remedy }

// errorBody is the JSON every failure carries: "error" is one self-contained
// line (what a client that only reads "error" shows the model), and code,
// message and remedy are the same thing split for clients that want to act on it.
func errorBody(status int, err error) map[string]string {
	var c coded
	if errors.As(err, &c) {
		return map[string]string{"error": c.Error(), "code": c.ErrCode(), "message": c.ErrMessage(), "remedy": c.ErrRemedy()}
	}
	code := map[int]string{http.StatusBadRequest: "bad_request", http.StatusNotFound: "not_found", http.StatusConflict: "conflict"}[status]
	if code == "" {
		code = "internal"
	}
	return map[string]string{"error": err.Error(), "code": code}
}

// decode reads a JSON body, rejecting unknown fields so a misspelt security
// field is an error rather than silently ignored.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return badRequest{"bad_request", fmt.Sprintf("the request body is larger than %d bytes", maxBody), "send a shorter command"}
		}
		return badRequest{"bad_request", fmt.Sprintf("the request body is not valid JSON for this route (%v)", err), "send {\"profile\":\"...\",\"command\":\"...\",\"timeout_seconds\":N} and nothing else"}
	}
	return nil
}

// audit records a request in the event log, with the principal and the peer's
// credentials. Failures are returned so loosening actions can refuse to proceed.
func (s *Server) audit(r *http.Request, p Principal, kind, guest string, detail map[string]string) error {
	if detail == nil {
		detail = map[string]string{}
	}
	detail["principal"] = string(p)
	detail["peer"] = peerOf(r.Context())
	return s.Events.Emit(kind, guest, detail)
}

func stateErr(err error) (int, error) {
	switch {
	case errors.Is(err, quarantine.ErrNotFound):
		return http.StatusNotFound, err
	case errors.Is(err, quarantine.ErrNotOpen), errors.Is(err, quarantine.ErrNotDanger):
		return http.StatusConflict, err
	case errors.Is(err, quarantine.ErrLowerLevel), errors.Is(err, quarantine.ErrBadLevel),
		errors.Is(err, quarantine.ErrBadVerdict), errors.Is(err, quarantine.ErrTooManyAdvs):
		return http.StatusBadRequest, err
	}
	return http.StatusInternalServerError, err
}

// Result of an action that changes quarantine state: the record, and whether
// the hold was actually applied to the running guest.
type Result struct {
	Record  quarantine.Record `json:"record"`
	Created bool              `json:"created,omitempty"`
	Applied bool              `json:"applied"`
	Error   string            `json:"error,omitempty"`
}

type openReq struct {
	Guest    string            `json:"guest"`
	Reason   string            `json:"reason"`
	Source   string            `json:"source"`
	Level    quarantine.Level  `json:"level"`
	Evidence map[string]string `json:"evidence"`
}

func (s *Server) open(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in openReq
	if err := decode(r, &in); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if in.Level == "" {
		in.Level = quarantine.LevelRestrict
	}
	probe := &manifest.Manifest{Name: in.Guest}
	if err := probe.ValidateName(); err != nil {
		return nil, http.StatusBadRequest, err
	}
	m, err := s.Actions.Guest(in.Guest)
	if err != nil {
		// Only guests Limbo has actually started can be quarantined, so the
		// control socket cannot be used to squat on arbitrary names.
		return nil, http.StatusNotFound, err
	}
	if in.Source == "" {
		in.Source = string(p)
	}
	rec, created, err := s.Store.Quarantine(in.Guest, in.Reason, in.Source, in.Level, in.Evidence)
	if err != nil {
		st, e := stateErr(err)
		return nil, st, e
	}
	kind := events.QuarantineOpen
	if !created {
		kind = events.QuarantineRaise
	}
	_ = s.audit(r, p, kind, in.Guest, map[string]string{"id": rec.ID, "level": string(rec.Level), "reason": rec.Reason, "source": rec.Source})
	return s.apply(r.Context(), m, rec, created), http.StatusOK, nil
}

// apply enforces the record's level on the guest if it exists. It is safe to
// call repeatedly: a repeat alert re-asserts the hold.
func (s *Server) apply(ctx context.Context, m *manifest.Manifest, rec quarantine.Record, created bool) Result {
	res := Result{Record: rec, Created: created}
	if !s.Actions.Defined(ctx, m) {
		res.Error = "guest is not currently running; hold recorded and will block the next start"
		return res
	}
	if err := s.Actions.Hold(ctx, m, rec.Level); err != nil {
		res.Error = err.Error()
		return res
	}
	res.Applied = true
	return res
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	return s.Store.List(), http.StatusOK, nil
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	rec, err := s.Store.Get(r.PathValue("id"))
	if err != nil {
		st, e := stateErr(err)
		return nil, st, e
	}
	return rec, http.StatusOK, nil
}

func (s *Server) raise(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		Level quarantine.Level `json:"level"`
	}
	if err := decode(r, &in); err != nil {
		return nil, http.StatusBadRequest, err
	}
	rec, err := s.Store.Raise(r.PathValue("id"), in.Level)
	if err != nil {
		st, e := stateErr(err)
		return nil, st, e
	}
	_ = s.audit(r, p, events.QuarantineRaise, rec.Guest, map[string]string{"id": rec.ID, "level": string(rec.Level)})
	m, err := s.Actions.Guest(rec.Guest)
	if err != nil {
		return Result{Record: rec, Error: err.Error()}, http.StatusOK, nil
	}
	return s.apply(r.Context(), m, rec, false), http.StatusOK, nil
}

func (s *Server) advisory(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		Source string `json:"source"`
		Text   string `json:"text"`
	}
	if err := decode(r, &in); err != nil {
		return nil, http.StatusBadRequest, err
	}
	rec, err := s.Store.AddAdvisory(r.PathValue("id"), in.Source, in.Text)
	if err != nil {
		st, e := stateErr(err)
		return nil, st, e
	}
	_ = s.audit(r, p, events.QuarantineAdvisory, rec.Guest, map[string]string{"id": rec.ID, "source": in.Source})
	return rec, http.StatusOK, nil
}

// verdict is the only path out of an open quarantine, and it exists only on the
// admin socket.
func (s *Server) verdict(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		Verdict quarantine.Status `json:"verdict"`
		By      string            `json:"by"`
		Note    string            `json:"note"`
	}
	if err := decode(r, &in); err != nil {
		return nil, http.StatusBadRequest, err
	}
	id := r.PathValue("id")
	rec, err := s.Store.Get(id)
	if err != nil {
		st, e := stateErr(err)
		return nil, st, e
	}
	if rec.Status != quarantine.StatusOpen {
		return nil, http.StatusConflict, quarantine.ErrNotOpen
	}
	if in.Verdict != quarantine.StatusSafe && in.Verdict != quarantine.StatusDangerous {
		return nil, http.StatusBadRequest, quarantine.ErrBadVerdict
	}
	by := fmt.Sprintf("%s (peer %s)", strings.TrimSpace(in.By), peerOf(r.Context()))

	// The audit entry comes first and failing to write it stops a verdict: this
	// is the decision the whole design exists to keep accountable.
	if err := s.audit(r, p, events.QuarantineVerdict, rec.Guest, map[string]string{"id": id, "verdict": string(in.Verdict), "by": by, "note": in.Note}); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("cannot record verdict in the audit log: %w", err)
	}

	m, gerr := s.Actions.Guest(rec.Guest)
	defined := gerr == nil && s.Actions.Defined(r.Context(), m)
	res := Result{}
	switch in.Verdict {
	case quarantine.StatusSafe:
		if defined {
			// Release before recording the verdict: if lifting the hold fails
			// the record stays open and the guest stays restricted.
			if err := s.Actions.Release(r.Context(), m); err != nil {
				return nil, http.StatusBadGateway, fmt.Errorf("could not lift restrictions, record left open: %w", err)
			}
			res.Applied = true
		}
	case quarantine.StatusDangerous:
		if defined {
			if err := s.Actions.Hold(r.Context(), m, quarantine.LevelIsolate); err != nil {
				res.Error = "could not isolate: " + err.Error()
			} else {
				res.Applied = true
			}
		}
	}
	out, err := s.Store.Decide(id, in.Verdict, by, in.Note)
	if err != nil {
		st, e := stateErr(err)
		return nil, st, e
	}
	res.Record = out
	return res, http.StatusOK, nil
}

func (s *Server) closeRec(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		By string `json:"by"`
	}
	if err := decode(r, &in); err != nil {
		return nil, http.StatusBadRequest, err
	}
	by := fmt.Sprintf("%s (peer %s)", strings.TrimSpace(in.By), peerOf(r.Context()))
	// Closing frees the guest name for reuse, so the condemned guest must be
	// gone first; otherwise the hold on it would be dropped while it still runs.
	if cur, err := s.Store.Get(r.PathValue("id")); err == nil {
		if m, gerr := s.Actions.Guest(cur.Guest); gerr == nil && s.Actions.Defined(r.Context(), m) {
			return nil, http.StatusConflict, fmt.Errorf("guest %q still exists; tear it down before closing its record", cur.Guest)
		}
	}
	rec, err := s.Store.Close(r.PathValue("id"), by)
	if err != nil {
		st, e := stateErr(err)
		return nil, st, e
	}
	_ = s.audit(r, p, events.QuarantineVerdict, rec.Guest, map[string]string{"id": rec.ID, "verdict": "closed", "by": by})
	return rec, http.StatusOK, nil
}

func (s *Server) down(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	m, err := s.Actions.Guest(r.PathValue("name"))
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	_ = s.audit(r, p, events.GuestStop, m.Name, map[string]string{"via": "api"})
	if err := s.Actions.Down(r.Context(), m); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return map[string]string{"status": "down"}, http.StatusOK, nil
}

func (s *Server) profiles(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	// "profiles" stays a plain list of names for older clients; "details" adds
	// what a caller needs to choose well.
	return map[string]any{"profiles": s.Runs.Profiles(), "details": s.Runs.Details(), "skipped": s.Runs.Skipped()}, http.StatusOK, nil
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		Profile        string `json:"profile"`
		Command        string `json:"command"`
		TimeoutSeconds int    `json:"timeout_seconds"`
		Bundle         string `json:"bundle"` // base64 of a small tar of source files (profiles with allow_bundle only)
	}
	if err := decode(r, &in); err != nil {
		_ = s.audit(r, p, events.RunError, "", map[string]string{"code": "bad_request"})
		return nil, http.StatusBadRequest, err
	}
	// The run outlives this request, so it must not inherit its cancellation.
	var id string
	var err error
	if in.Bundle != "" {
		bs, ok := s.Runs.(BundleRunService)
		raw, derr := base64.StdEncoding.DecodeString(in.Bundle)
		if !ok || derr != nil {
			return nil, http.StatusBadRequest, badRequest{"bad_request", "the bundle is not accepted here or is not valid base64", "send the tar as standard base64, to a profile that allows bundles"}
		}
		id, err = bs.StartBundle(context.WithoutCancel(r.Context()), in.Profile, in.Command, raw, in.TimeoutSeconds)
	} else {
		id, err = s.Runs.Start(context.WithoutCancel(r.Context()), in.Profile, in.Command, in.TimeoutSeconds)
	}
	if err != nil {
		var c coded
		if errors.As(err, &c) && c.ErrCode() == "busy" {
			return nil, http.StatusTooManyRequests, err
		}
		return nil, http.StatusBadRequest, err
	}
	return map[string]string{"id": id}, http.StatusAccepted, nil
}

// startSampleRun (admin): {"profile", "command", "sample" (a file name in Limbo's inbox), "timeout_seconds"}.
func (s *Server) startSampleRun(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		Profile        string `json:"profile"`
		Command        string `json:"command"`
		Sample         string `json:"sample"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := decode(r, &in); err != nil {
		return nil, http.StatusBadRequest, err
	}
	id, err := s.Runs.(SampleRunService).StartSample(context.WithoutCancel(r.Context()), in.Profile, in.Command, in.Sample, in.TimeoutSeconds)
	if err != nil {
		var c coded
		if errors.As(err, &c) && c.ErrCode() == "busy" {
			return nil, http.StatusTooManyRequests, err
		}
		return nil, http.StatusBadRequest, err
	}
	return map[string]string{"id": id}, http.StatusAccepted, nil
}

// stopAgentRuns (admin): Heimdall contained Sarina; every run her agents started ends now.
func (s *Server) stopAgentRuns(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	n := s.Runs.(SampleRunService).StopAgentRuns()
	return map[string]int{"stopped": n}, http.StatusOK, nil
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	v, ok := s.Runs.Get(r.PathValue("id"))
	if !ok {
		return nil, http.StatusNotFound, badRequest{"run_unknown", "there is no run with that id", "the id may have expired or Limbo restarted (its guest is destroyed either way); start the run again"}
	}
	return v, http.StatusOK, nil
}
