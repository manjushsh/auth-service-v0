package auth

import (
	"testing"

	"github.com/manjushsh/auth-service/internal/httpx"
)

// TestRoutes_RateLimitTiers pins every public route to its tier.
//
// This is the public plane's equivalent of the admin plane's authorization
// table. The failure it prevents: someone adds an endpoint that accepts a
// password or a reset token, wires it to the looser tier, and nothing notices —
// the route works, the tests pass, and the credential-guessing limit is three
// times weaker than intended for that path.
//
// A new route fails this test until it is listed, which forces the tier to be a
// decision someone made rather than one they inherited.
func TestRoutes_RateLimitTiers(t *testing.T) {
	want := map[string]httpx.Tier{
		// Anything accepting a secret — a password, a one-time code, a reset
		// token — takes the tight limit.
		"POST /api/auth/register":       httpx.TierCredential,
		"POST /api/auth/login":          httpx.TierCredential,
		"POST /api/auth/code":           httpx.TierCredential,
		"POST /api/auth/password-reset": httpx.TierCredential,

		// These take an already-issued token, so guessing is not the threat.
		"POST /api/auth/token":      httpx.TierToken,
		"POST /api/auth/logout":     httpx.TierToken,
		"POST /api/auth/introspect": httpx.TierToken,

		"GET /health": httpx.TierNone,
	}

	h := New(&fakeService{})
	seen := map[string]bool{}

	for _, route := range h.Routes() {
		key := route.Method + " " + route.Path
		seen[key] = true

		expected, listed := want[key]
		if !listed {
			t.Errorf("%s is not listed in this test; add it with the tier you intend", key)
			continue
		}
		if route.Tier != expected {
			t.Errorf("%s is on tier %q, want %q", key, route.Tier, expected)
		}
	}

	for key := range want {
		if !seen[key] {
			t.Errorf("%s is listed here but no longer registered; remove it or restore the route", key)
		}
	}
}

// Every route must have a handler and a method — an entry missing either would
// register a pattern that matches nothing, or panic at mount time.
func TestRoutes_AreWellFormed(t *testing.T) {
	for _, route := range New(&fakeService{}).Routes() {
		if route.Path == "" || route.Handler == nil {
			t.Errorf("malformed route: %+v", route)
		}
		if route.Method == "" {
			t.Errorf("%s has no method; the public API registers none as a subtree", route.Path)
		}
	}
}
