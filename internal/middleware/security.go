package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeaders sets a baseline set of hardening headers on every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")

		// Almost everything this service returns is a credential: a one-time
		// code, a JWT, a password-reset token. Default to unstorable and let
		// the only genuinely cacheable route opt back in, rather than trying to
		// enumerate the sensitive ones.
		if strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "public, max-age=3600")
		} else {
			h.Set("Cache-Control", "no-store")
		}

		next.ServeHTTP(w, r)
	})
}
