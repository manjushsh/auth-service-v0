// Package httpx holds the small HTTP helpers shared by every handler package:
// JSON encode/decode, error bodies, bearer extraction and client-IP resolution.
//
// It exists to stop each handler package growing its own slightly-different
// copy of the same five functions.
package httpx

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// WriteJSON writes v as JSON. Every response this service produces is
// credential-adjacent, so callers rely on the no-store header set by the
// SecurityHeaders middleware rather than setting cache directives here.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already written, so this can only be logged.
		slog.Error("httpx: encode response", "error", err)
	}
}

// ErrorBody is the structured error shape used by the admin plane. The public
// plane still returns plain text via http.Error; that inconsistency is
// deliberate (see docs/ADMIN_API_PLAN.md §8.1) and retrofitting it is a
// separate, breaking change.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorBody{Error: ErrorDetail{Code: code, Message: message}})
}

// DecodeJSON decodes a request body, rejecting unknown fields so a typo in an
// admin request fails loudly instead of silently doing something else.
func DecodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// BearerToken returns the token from an Authorization header, or "".
func BearerToken(r *http.Request) string {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found {
		return ""
	}
	return strings.TrimSpace(token)
}

// RemoteIP is the TCP peer address, ignoring every proxy header. Use this
// wherever the value must not be attacker-controlled — the admin rate limiter
// and the audit log's remote_addr column.
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ClientIP prefers proxy headers, falling back to the peer address.
//
// X-Forwarded-For is trusted unconditionally here, which is spoofable whenever
// the service is reachable without a proxy in front of it. That is a known,
// documented gap for the public rate limiter (ARCHITECTURE §9). Anything that
// must not be spoofable uses RemoteIP instead.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Comma-separated list; the leftmost entry is the client.
		return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return RemoteIP(r)
}
