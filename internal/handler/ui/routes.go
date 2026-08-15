package ui

import (
	"net/http"

	"github.com/manjushsh/auth-service/internal/httpx"
)

// Routes is the hosted HTML surface.
//
// The GET routes render forms and take no credentials, so they carry no limit;
// the POST routes submit them and take the same tight tier as their JSON
// equivalents. Static assets are served here rather than wired separately so
// the whole public surface is described in one place.
func (h *Handler) Routes() []httpx.Route {
	return []httpx.Route{
		{Method: http.MethodGet, Path: "/login", Tier: httpx.TierNone, Handler: http.HandlerFunc(h.LoginPage)},
		{Method: http.MethodPost, Path: "/login", Tier: httpx.TierCredential, Handler: http.HandlerFunc(h.LoginSubmit)},
		{Method: http.MethodGet, Path: "/register", Tier: httpx.TierNone, Handler: http.HandlerFunc(h.RegisterPage)},
		{Method: http.MethodPost, Path: "/register", Tier: httpx.TierCredential, Handler: http.HandlerFunc(h.RegisterSubmit)},
		// No method: a file server handles the whole subtree.
		{Path: "/static/", Tier: httpx.TierNone, Handler: http.FileServer(http.FS(StaticFS))},
	}
}
