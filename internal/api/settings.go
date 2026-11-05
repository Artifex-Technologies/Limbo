package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"strconv"

	"github.com/Artifex-Technologies/Limbo/internal/instances"
	"github.com/Artifex-Technologies/Limbo/internal/license"
	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/settings"
)

// User is a member of the limbo-users group, through user.sock (the Settings page). It may always read the figures;
// it may change its guests only while the password switch is off; and some things it may never do (verdicts,
// loosening a held guest, the switch, licenses' keys, group membership): those routes do not exist on its socket.
const User Principal = "user"

// InstanceService is package instances.
type InstanceService interface {
	List(ctx context.Context, c instances.Caller) []instances.View
	Get(ctx context.Context, name string, c instances.Caller) (instances.View, error)
	Space(ctx context.Context) instances.Space
	Start(ctx context.Context, name string, c instances.Caller) (instances.View, error)
	Stop(ctx context.Context, name string, c instances.Caller) (instances.View, error)
	Configure(ctx context.Context, name string, ch instances.Change, c instances.Caller) (instances.View, error)
	FreeSpace(ctx context.Context, name string, c instances.Caller) (int64, error)
	Add(m *manifest.Manifest, owner string, c instances.Caller) (instances.View, error)
	Remove(ctx context.Context, name string, deleteDisk bool, c instances.Caller) error
}

// LicenseService is the Windows license store (package license).
type LicenseService interface {
	List() ([]license.Masked, error)
	Add(name, key string) (license.Masked, error)
	Remove(id string) error
	Reveal(id string) (string, error)
	Assign(id, guest string) (license.Masked, error)
	Unassign(id, guest string) (license.Masked, error)
}

// SettingsFile reads and writes the password switch.
type SettingsFile struct{ Path string }

func (f SettingsFile) Load() (settings.Settings, error) { return settings.Load(f.Path) }
func (f SettingsFile) Save(s settings.Settings) error   { return settings.Save(f.Path, s) }

// SettingsStore is SettingsFile, or a fake in tests.
type SettingsStore interface {
	Load() (settings.Settings, error)
	Save(settings.Settings) error
}

// Version is reported by GET /v1/status; cmd/limbo sets it.
var Version = "dev"

// KVMAvailable reports whether /dev/kvm is there; replaced in tests.
var KVMAvailable = func() bool {
	fi, err := os.Stat("/dev/kvm")
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// peerUID is the connecting process's uid (SO_PEERCRED); replaced in tests.
var peerUID = realPeerUID

// apiError is a coded refusal with its HTTP status.
type apiError struct {
	status                int
	code, message, remedy string
}

func (e *apiError) Error() string      { return e.code + ": " + e.message + ". Remedy: " + e.remedy }
func (e *apiError) ErrCode() string    { return e.code }
func (e *apiError) ErrMessage() string { return e.message }
func (e *apiError) ErrRemedy() string  { return e.remedy }
func (e *apiError) HTTPStatus() int    { return e.status }

func fail(status int, code, remedy, format string, a ...any) (any, int, error) {
	return nil, status, &apiError{status, code, fmt.Sprintf(format, a...), remedy}
}

// failWith turns a service error into a response, keeping its status when it carries one.
func failWith(err error) (any, int, error) {
	var st interface{ HTTPStatus() int }
	if errors.As(err, &st) {
		return nil, st.HTTPStatus(), err
	}
	switch {
	case errors.Is(err, license.ErrNoLicense):
		return fail(http.StatusNotFound, "not_found", "list the licenses for the ids that exist", "%v", err)
	case errors.Is(err, license.ErrBadKey):
		return fail(http.StatusBadRequest, "bad_key", "check the key and type it again", "%v", err)
	case errors.Is(err, license.ErrBadName):
		return fail(http.StatusBadRequest, "bad_name", "give a short name such as \"Windows 11 Pro, old PC\"", "%v", err)
	case errors.Is(err, license.ErrDuplicate):
		return fail(http.StatusConflict, "exists", "it is already stored", "%v", err)
	case errors.Is(err, license.ErrTooMany), errors.Is(err, license.ErrBadGuest):
		return fail(http.StatusBadRequest, "bad_request", "check the request", "%v", err)
	}
	return nil, http.StatusInternalServerError, err
}

// decodeStrict reads a JSON body (unknown fields refused) with a remedy that fits the route.
func decodeStrict(r *http.Request, v any, shape string) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return &apiError{http.StatusBadRequest, "bad_request", "the request body is not valid JSON for this route", "send " + shape}
	}
	return nil
}

// caller says who is asking. On user.sock the uid comes from the kernel (SO_PEERCRED); without it nothing may change.
func caller(r *http.Request, p Principal) (instances.Caller, bool) {
	if p == Admin {
		return instances.Caller{Admin: true, UID: 0, User: "root"}, true
	}
	uid, ok := peerUID(r.Context())
	if !ok {
		return instances.Caller{UID: -1}, false
	}
	c := instances.Caller{UID: uid}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		c.User = u.Username
	}
	return c, true
}

// askPassword reports whether user.sock may change anything now. Any doubt about the switch means yes.
func (s *Server) askPassword() bool {
	if s.Settings == nil {
		return true
	}
	st, err := s.Settings.Load()
	return err != nil || st.AskPassword
}

// gated wraps a changing route on user.sock: with the switch on (or unknown), or a caller the kernel cannot name, it
// is refused before the handler runs. On the admin socket it always runs.
func (s *Server) gated(p Principal, h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
		if p != Admin {
			if s.askPassword() {
				return fail(http.StatusForbidden, "password_required",
					"use the password: run the same action with pkexec or sudo (limbo ...), or turn off \"Ask for my password for Limbo changes\"",
					"Limbo changes need the password on this computer")
			}
			if _, ok := caller(r, p); !ok {
				return fail(http.StatusForbidden, "unknown_caller", "connect over the unix socket", "the caller's account could not be read")
			}
		}
		return h(w, r, p)
	}
}

func (s *Server) settingsRoutes(mux *http.ServeMux, p Principal) {
	if p != User && p != Admin {
		return
	}
	if s.Instances != nil {
		mux.HandleFunc("GET /v1/status", s.wrap(p, s.status))
		mux.HandleFunc("GET /v1/settings", s.wrap(p, s.getSettings))
		mux.HandleFunc("GET /v1/instances", s.wrap(p, s.listInstances))
		mux.HandleFunc("GET /v1/instances/{name}", s.wrap(p, s.getInstance))
		mux.HandleFunc("POST /v1/instances/{name}/start", s.wrap(p, s.gated(p, s.startInstance)))
		mux.HandleFunc("POST /v1/instances/{name}/stop", s.wrap(p, s.gated(p, s.stopInstance)))
		mux.HandleFunc("POST /v1/instances/{name}/settings", s.wrap(p, s.gated(p, s.configureInstance)))
		mux.HandleFunc("POST /v1/instances/{name}/free-space", s.wrap(p, s.gated(p, s.freeSpace)))
	}
	if s.Licenses != nil {
		mux.HandleFunc("GET /v1/licenses", s.wrap(p, s.listLicenses))
		mux.HandleFunc("POST /v1/licenses/{id}/assign", s.wrap(p, s.gated(p, s.assignLicense(true))))
		mux.HandleFunc("POST /v1/licenses/{id}/unassign", s.wrap(p, s.gated(p, s.assignLicense(false))))
	}
	if p != Admin {
		return
	}
	// Root only, whatever the switch says.
	mux.HandleFunc("POST /v1/settings", s.wrap(p, s.putSettings))
	if s.Instances != nil {
		mux.HandleFunc("POST /v1/instances", s.wrap(p, s.addInstance))
		mux.HandleFunc("DELETE /v1/instances/{name}", s.wrap(p, s.removeInstance))
	}
	if s.Licenses != nil {
		mux.HandleFunc("POST /v1/licenses", s.wrap(p, s.addLicense))
		mux.HandleFunc("DELETE /v1/licenses/{id}", s.wrap(p, s.removeLicense))
		mux.HandleFunc("GET /v1/licenses/{id}/key", s.wrap(p, s.revealLicense))
	}
}

// StatusView is GET /v1/status.
type StatusView struct {
	Version     string          `json:"version"`
	Running     bool            `json:"running"`
	KVM         bool            `json:"kvm"`
	AskPassword bool            `json:"ask_password"`
	Space       instances.Space `json:"space"`
	Instances   struct {
		Total   int `json:"total"`
		Running int `json:"running"`
		Held    int `json:"held"`
	} `json:"instances"`
}

func (s *Server) status(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	c, _ := caller(r, p)
	out := StatusView{Version: Version, Running: true, KVM: KVMAvailable(), AskPassword: s.askPassword(), Space: s.Instances.Space(r.Context())}
	for _, v := range s.Instances.List(r.Context(), c) {
		out.Instances.Total++
		if v.Running {
			out.Instances.Running++
		}
		if v.Hold != nil {
			out.Instances.Held++
		}
	}
	return out, http.StatusOK, nil
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	return map[string]bool{"ask_password": s.askPassword()}, http.StatusOK, nil
}

// putSettings (admin): {"ask_password": bool}. Logged before it is saved; if it cannot be logged it is not saved.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		AskPassword *bool `json:"ask_password"`
	}
	if err := decodeStrict(r, &in, `{"ask_password": true|false}`); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if in.AskPassword == nil {
		return fail(http.StatusBadRequest, "bad_request", `send {"ask_password": true|false}`, "ask_password is missing")
	}
	if s.Settings == nil {
		return fail(http.StatusInternalServerError, "internal", "see the Limbo log", "no settings file is configured")
	}
	if err := s.audit(r, p, "settings.change", "", map[string]string{"ask_password": strconv.FormatBool(*in.AskPassword)}); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("cannot record the change in the audit log: %w", err)
	}
	if err := s.Settings.Save(settings.Settings{AskPassword: *in.AskPassword}); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return map[string]bool{"ask_password": *in.AskPassword}, http.StatusOK, nil
}

func (s *Server) listInstances(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	c, _ := caller(r, p)
	return map[string]any{"instances": s.Instances.List(r.Context(), c)}, http.StatusOK, nil
}

func (s *Server) getInstance(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	c, _ := caller(r, p)
	v, err := s.Instances.Get(r.Context(), r.PathValue("name"), c)
	if err != nil {
		return failWith(err)
	}
	return v, http.StatusOK, nil
}

func (s *Server) startInstance(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	c, _ := caller(r, p)
	v, err := s.Instances.Start(context.WithoutCancel(r.Context()), r.PathValue("name"), c)
	if err != nil {
		return failWith(err)
	}
	return v, http.StatusOK, nil
}

// stopInstance: stopping only ever restricts, but it is still a change, so it follows the switch; a held guest is
// refused by package instances (its disk and state are evidence).
func (s *Server) stopInstance(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	c, _ := caller(r, p)
	v, err := s.Instances.Stop(context.WithoutCancel(r.Context()), r.PathValue("name"), c)
	if err != nil {
		return failWith(err)
	}
	return v, http.StatusOK, nil
}

func (s *Server) configureInstance(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var ch instances.Change
	if err := decodeStrict(r, &ch, `{"cpus":N,"memory_mb":N,"disk_gb":N,"shared_folder":"off|on","clipboard":"off|text","devices":["0000:03:00.0"]} (any of them)`); err != nil {
		return nil, http.StatusBadRequest, err
	}
	c, _ := caller(r, p)
	v, err := s.Instances.Configure(r.Context(), r.PathValue("name"), ch, c)
	if err != nil {
		return failWith(err)
	}
	return v, http.StatusOK, nil
}

func (s *Server) freeSpace(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeStrict(r, &in, `{"confirm": true}`); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if !in.Confirm {
		return fail(http.StatusBadRequest, "confirm_required", `send {"confirm": true}`, "freeing space deletes everything the guest changed since its base image")
	}
	c, _ := caller(r, p)
	n, err := s.Instances.FreeSpace(r.Context(), r.PathValue("name"), c)
	if err != nil {
		return failWith(err)
	}
	return map[string]int64{"freed_bytes": n}, http.StatusOK, nil
}

// addInstance (admin): {"manifest": {...}, "owner": "account"}.
func (s *Server) addInstance(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		Manifest *manifest.Manifest `json:"manifest"`
		Owner    string             `json:"owner"`
	}
	if err := decodeStrict(r, &in, `{"manifest": {...}, "owner": "account"}`); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if in.Manifest == nil {
		return fail(http.StatusBadRequest, "bad_request", `send {"manifest": {...}}`, "manifest is missing")
	}
	c, _ := caller(r, p)
	v, err := s.Instances.Add(in.Manifest, in.Owner, c)
	if err != nil {
		return failWith(err)
	}
	return v, http.StatusOK, nil
}

// removeInstance (admin): body {"delete_disk": bool} optional.
func (s *Server) removeInstance(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		DeleteDisk bool `json:"delete_disk"`
	}
	if err := decodeStrict(r, &in, `{"delete_disk": true|false}`); err != nil {
		return nil, http.StatusBadRequest, err
	}
	c, _ := caller(r, p)
	if err := s.Instances.Remove(r.Context(), r.PathValue("name"), in.DeleteDisk, c); err != nil {
		return failWith(err)
	}
	return map[string]string{"removed": r.PathValue("name")}, http.StatusOK, nil
}

func (s *Server) listLicenses(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	l, err := s.Licenses.List()
	if err != nil {
		return nil, http.StatusInternalServerError, errors.New("the license store cannot be read")
	}
	return map[string]any{"licenses": l}, http.StatusOK, nil
}

// addLicense (admin): {"name": "...", "key": "XXXXX-..."}. The key is never logged or echoed.
func (s *Server) addLicense(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	var in struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	}
	if err := decodeStrict(r, &in, `{"name": "...", "key": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}`); err != nil {
		return nil, http.StatusBadRequest, err
	}
	m, err := s.Licenses.Add(in.Name, in.Key)
	if err != nil {
		return failWith(err)
	}
	_ = s.audit(r, p, "license.add", "", map[string]string{"id": m.ID})
	return m, http.StatusOK, nil
}

func (s *Server) removeLicense(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	id := r.PathValue("id")
	if err := s.Licenses.Remove(id); err != nil {
		return failWith(err)
	}
	_ = s.audit(r, p, "license.remove", "", map[string]string{"id": id})
	return map[string]string{"removed": id}, http.StatusOK, nil
}

// revealLicense (admin): the full key. Recorded (the id, never the key) before it is shown.
func (s *Server) revealLicense(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	id := r.PathValue("id")
	if err := s.audit(r, p, "license.reveal", "", map[string]string{"id": id}); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("cannot record the request in the audit log: %w", err)
	}
	k, err := s.Licenses.Reveal(id)
	if err != nil {
		return failWith(err)
	}
	return map[string]string{"id": id, "key": k}, http.StatusOK, nil
}

func (s *Server) assignLicense(assign bool) handler {
	return func(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
		var in struct {
			Guest string `json:"guest"`
		}
		if err := decodeStrict(r, &in, `{"guest": "name"}`); err != nil {
			return nil, http.StatusBadRequest, err
		}
		c, _ := caller(r, p)
		if s.Instances != nil {
			v, err := s.Instances.Get(r.Context(), in.Guest, c)
			if err != nil {
				return failWith(err)
			}
			if v.Kind != "instance" || v.OS != manifest.OSWindows {
				return fail(http.StatusBadRequest, "bad_request", "assign licenses to Windows instances only", "%q is not a Windows instance", in.Guest)
			}
			if !v.Mine {
				return fail(http.StatusForbidden, instances.CodeNotOwner, "ask its owner or use the password", "instance %q belongs to %s", in.Guest, v.Owner)
			}
		}
		var m license.Masked
		var err error
		kind := "license.assign"
		if assign {
			m, err = s.Licenses.Assign(r.PathValue("id"), in.Guest)
		} else {
			kind = "license.unassign"
			m, err = s.Licenses.Unassign(r.PathValue("id"), in.Guest)
		}
		if err != nil {
			return failWith(err)
		}
		_ = s.audit(r, p, kind, in.Guest, map[string]string{"id": m.ID})
		return m, http.StatusOK, nil
	}
}
