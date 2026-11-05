package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/Artifex-Technologies/Limbo/internal/exchange"
)

// ExchangeService is package exchange: a guest's outbox, scanned before anything leaves it.
type ExchangeService interface {
	List(guest string) (exchange.Listing, error)
	Take(ctx context.Context, guest, rel string, detail map[string]string) (*exchange.Taken, error)
}

// exchangeRoutes: listing an outbox is a figure (any member); taking a file out follows the password switch on
// user.sock, and never from a guest Heimdall holds unless root asks. Heimdall and Sarina have no route to it.
func (s *Server) exchangeRoutes(mux *http.ServeMux, p Principal) {
	if s.Exchange == nil || (p != User && p != Admin) {
		return
	}
	mux.HandleFunc("GET /v1/exchange/{guest}", s.wrap(p, s.listExchange))
	mux.HandleFunc("POST /v1/exchange/{guest}/take", s.takeExchange(p))
}

func (s *Server) listExchange(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
	l, err := s.Exchange.List(r.PathValue("guest"))
	if err != nil {
		return failWith(err)
	}
	return l, http.StatusOK, nil
}

// takeExchange answers with the file's bytes (application/octet-stream) and its hash in X-Limbo-Sha256, or with the
// usual JSON error.
func (s *Server) takeExchange(p Principal) http.HandlerFunc {
	check := s.gated(p, func(w http.ResponseWriter, r *http.Request, p Principal) (any, int, error) {
		guest := r.PathValue("guest")
		if s.Instances != nil && p != Admin {
			c, _ := caller(r, p)
			v, err := s.Instances.Get(r.Context(), guest, c)
			if err != nil {
				return failWith(err)
			}
			if v.Hold != nil {
				return fail(http.StatusConflict, "held_by_heimdall", "decide about the guest on Heimdall's page (Settings > Security) first", "guest %q is held", guest)
			}
			if !v.Mine {
				return fail(http.StatusForbidden, "not_owner", "ask its owner or use the password", "guest %q belongs to %s", guest, v.Owner)
			}
		}
		return nil, http.StatusOK, nil
	})
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		writeErr := func(status int, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(errorBody(status, err))
		}
		if _, status, err := check(w, r, p); err != nil {
			writeErr(status, err)
			return
		}
		var in struct {
			Path string `json:"path"`
		}
		if err := decodeStrict(r, &in, `{"path": "name as listed"}`); err != nil {
			writeErr(http.StatusBadRequest, err)
			return
		}
		detail := map[string]string{"principal": string(p), "peer": peerOf(r.Context())}
		t, err := s.Exchange.Take(context.WithoutCancel(r.Context()), r.PathValue("guest"), in.Path, detail)
		if err != nil {
			_, status, e := failWith(err)
			writeErr(status, e)
			return
		}
		defer t.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(t.Size, 10))
		w.Header().Set("X-Limbo-Sha256", t.SHA256)
		w.Header().Set("X-Limbo-Scan", exchange.Clean)
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, t.File); err != nil {
			fmt.Println("limbo: sending an exchange file failed:", err)
		}
	}
}
