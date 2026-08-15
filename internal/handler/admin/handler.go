// Package admin exposes the administrative plane over HTTP.
//
// It is JSON and bearer-token only. Cookie authentication is deliberately not
// implemented and must not be added: an ambient credential would make every
// endpoint here CSRF-able from an admin's browser. A UI that needs access does
// the token exchange itself and holds the token in memory.
package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/manjushsh/auth-service/internal/httpx"
	adminsvc "github.com/manjushsh/auth-service/internal/service/admin"
	authsvc "github.com/manjushsh/auth-service/internal/service/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

type Handler struct {
	svc *adminsvc.Service
}

func New(s *adminsvc.Service) *Handler { return &Handler{svc: s} }

// --- caller propagation ---

type callerKey struct{}

// callerFrom returns the authenticated caller. It panics when absent, because
// that can only mean a handler was registered outside requireRole — a wiring
// bug that must fail loudly in tests rather than quietly serve an
// unauthenticated request.
func callerFrom(ctx context.Context) adminsvc.Caller {
	c, ok := ctx.Value(callerKey{}).(adminsvc.Caller)
	if !ok {
		panic("admin: handler reached without an authenticated caller")
	}
	return c
}

// requireRole is the single authentication and authorization gate.
//
// Note that it does not call the public plane's Introspect. That reports an
// invalid token as a *successful call returning Active:false*, so the obvious
// `if err != nil { 401 }` shape fails open — which on this plane is the
// difference between a 401 and an unauthenticated caller holding user deletion.
// Authenticate returns an error for every outcome that is not a live,
// privileged, active account.
func (h *Handler) requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := h.svc.Authenticate(r.Context(), httpx.BearerToken(r), metaFrom(r))
		if err != nil {
			h.fail(w, err)
			return
		}
		if err := h.svc.Authorize(r.Context(), caller, role); err != nil {
			h.fail(w, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller)))
	}
}

func metaFrom(r *http.Request) store.RequestMeta {
	return store.RequestMeta{
		// The TCP peer, never a header: the audit log must not record an
		// attacker-chosen origin as if it were the truth.
		RemoteAddr:   httpx.RemoteIP(r),
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		UserAgent:    r.Header.Get("User-Agent"),
	}
}

// --- error mapping ---

// failure maps one error onto its wire representation. Keeping the table here,
// rather than a switch in every handler, is what makes the mapping auditable.
type failure struct {
	status  int
	code    string
	message string
}

var failures = []struct {
	err error
	failure
}{
	{adminsvc.ErrUnauthenticated, failure{http.StatusUnauthorized, "unauthenticated", "invalid or missing credentials"}},
	{adminsvc.ErrForbidden, failure{http.StatusForbidden, "forbidden", "insufficient role"}},
	{adminsvc.ErrNotFound, failure{http.StatusNotFound, "not_found", "no such record"}},
	{adminsvc.ErrConflict, failure{http.StatusConflict, "conflict", "record already exists"}},
	{adminsvc.ErrLastAdmin, failure{http.StatusConflict, "last_admin", "cannot remove the last remaining admin"}},
	{adminsvc.ErrSelfTarget, failure{http.StatusConflict, "self_target", "cannot perform this action on your own account"}},
	{adminsvc.ErrConfirmationMismatch, failure{http.StatusBadRequest, "confirmation_mismatch", "confirmation value does not match the target"}},
	{adminsvc.ErrBadInput, failure{http.StatusBadRequest, "invalid_request", "invalid request"}},
	// Login delegates credential checking to the auth service, so its
	// sentinels surface here too.
	{authsvc.ErrAccountLocked, failure{http.StatusTooManyRequests, "account_locked", "account locked, try again later"}},
	{authsvc.ErrInvalidCredentials, failure{http.StatusUnauthorized, "unauthenticated", "invalid or missing credentials"}},
	{authsvc.ErrBadRequest, failure{http.StatusBadRequest, "invalid_request", "invalid request"}},
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	for _, f := range failures {
		if errors.Is(err, f.err) {
			httpx.WriteError(w, f.status, f.code, f.message)
			return
		}
	}
	// Anything unmapped is an infrastructure failure. Log it with detail;
	// return none.
	slog.Error("admin: unhandled error", "error", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

// --- request helpers ---

// decodeBody decodes a JSON body into T. An empty body yields the zero value,
// so endpoints whose parameters are all optional need no body at all.
func decodeBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var dst T
	err := httpx.DecodeJSON(r, &dst)
	if err != nil && !errors.Is(err, io.EOF) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return dst, false
	}
	return dst, true
}

// requireBody is decodeBody for endpoints where an absent body is an error.
func requireBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var dst T
	if err := httpx.DecodeJSON(r, &dst); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid or missing request body")
		return dst, false
	}
	return dst, true
}

// parsePage reads keyset-pagination parameters. A malformed cursor or limit is
// a 400 rather than a silent fallback, so a broken client is visible.
func parsePage(w http.ResponseWriter, r *http.Request) (store.Page, bool) {
	q := r.URL.Query()

	page := store.Page{}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
			return store.Page{}, false
		}
		page.Limit = n
	}

	cursor, err := store.DecodeCursor(q.Get("cursor"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed cursor")
		return store.Page{}, false
	}
	page.Cursor = cursor

	return page.Normalize(), true
}

// parseTime reads an optional RFC 3339 query parameter.
func parseTime(w http.ResponseWriter, r *http.Request, name string) (time.Time, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", name+" must be an RFC 3339 timestamp")
		return time.Time{}, false
	}
	return t, true
}
