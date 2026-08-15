package auth

import (
	"net/http"

	"github.com/manjushsh/auth-service/internal/httpx"
)

// Routes is the public JSON API surface.
//
// Declared as data, like the admin plane's, so the rate-limit tier of every
// endpoint is visible in one place and testable. The invariant that matters:
// anything accepting a password, a one-time code or a reset token sits on
// TierCredential. Choosing the limiter at each registration call site made that
// a matter of remembering.
func (h *Handler) Routes() []httpx.Route {
	post := func(path string, tier httpx.Tier, fn http.HandlerFunc) httpx.Route {
		return httpx.Route{Method: http.MethodPost, Path: path, Tier: tier, Handler: fn}
	}

	return []httpx.Route{
		post("/api/auth/register", httpx.TierCredential, h.Register),
		// Login and code routes are the same handler; /code is kept so the API
		// reads clearly for callers who are not doing a browser login.
		post("/api/auth/login", httpx.TierCredential, h.GenerateCode),
		post("/api/auth/code", httpx.TierCredential, h.GenerateCode),
		// Redemption half of the admin-issued password reset. Unauthenticated by
		// design — the single-use token is the credential — so it takes the
		// tight tier.
		post("/api/auth/password-reset", httpx.TierCredential, h.RedeemPasswordReset),

		// These take an already-issued token rather than a secret, so guessing
		// is not the threat and the looser limit applies.
		post("/api/auth/token", httpx.TierToken, h.ExchangeToken),
		post("/api/auth/logout", httpx.TierToken, h.Logout),
		post("/api/auth/introspect", httpx.TierToken, h.Introspect),

		{Method: http.MethodGet, Path: "/health", Tier: httpx.TierNone, Handler: http.HandlerFunc(h.Health)},
	}
}

// Health is liveness only: it deliberately touches no dependency, so it answers
// "is this process running" and nothing more. Readiness — which pings Postgres
// and Redis — lives on the admin plane's /admin/health.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
