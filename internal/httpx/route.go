package httpx

import "net/http"

// Tier names a rate-limit class. Declaring it per route, rather than choosing a
// limiter at the registration call site, is what makes the choice reviewable:
// putting a credential endpoint on the loose tier becomes a visible diff and a
// failing test instead of a silent weakening.
type Tier string

const (
	// TierNone is for routes that need no limit — page renders, static assets,
	// liveness.
	TierNone Tier = ""
	// TierCredential is the tight limit. Everything that accepts a password,
	// a one-time code or a reset token belongs here.
	TierCredential Tier = "credential"
	// TierToken is the looser limit for routes that take an already-issued
	// token: exchange, introspect, logout.
	TierToken Tier = "token"
)

// Route is one endpoint of the public plane.
type Route struct {
	Method  string
	Path    string
	Tier    Tier
	Handler http.Handler
}

// Limiters maps each tier to the middleware that enforces it. A tier with no
// entry is registered unwrapped.
type Limiters map[Tier]func(http.Handler) http.Handler

// Mount registers routes on mux, wrapping each in the limiter for its tier.
func Mount(mux *http.ServeMux, routes []Route, limiters Limiters) {
	for _, route := range routes {
		handler := route.Handler
		if limit, ok := limiters[route.Tier]; ok && limit != nil {
			handler = limit(handler)
		}

		pattern := route.Path
		if route.Method != "" {
			pattern = route.Method + " " + route.Path
		}
		mux.Handle(pattern, handler)
	}
}
