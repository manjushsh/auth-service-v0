package admin

import (
	"net/http"

	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// Route is one admin endpoint and the role it demands.
//
// Routes are data rather than a sequence of mux.Handle calls so the
// authorization test can enumerate them: every route with a Role is asserted to
// reject an anonymous caller, a user-audience token and an under-privileged
// token. An endpoint added without a role therefore fails the suite instead of
// shipping open.
type Route struct {
	Method  string
	Path    string
	Role    string // "" means the endpoint authenticates callers itself
	Handler http.HandlerFunc
}

// Public reports whether a route is reachable without an admin token.
func (r Route) Public() bool { return r.Role == "" }

func (h *Handler) Routes() []Route {
	const (
		support = store.RoleSupport
		admin   = store.RoleAdmin
	)

	return []Route{
		// Authentication. Login is necessarily unauthenticated; logout and
		// whoami accept any privileged role.
		{http.MethodPost, "/admin/auth/login", "", h.Login},
		{http.MethodPost, "/admin/auth/logout", support, h.Logout},
		{http.MethodGet, "/admin/auth/whoami", support, h.WhoAmI},

		// Health is unauthenticated on purpose: it is what an orchestrator
		// probes, it reveals only up/down, and the listener is not public.
		//
		// It answers on both paths. /admin/health keeps every route on this
		// listener under one prefix; /health is where probes and humans
		// actually look first, and a 404 there reads like the service is broken
		// rather than like the path is wrong. Two URLs for one resource is a
		// small price for not misleading whoever is debugging at 3am.
		{http.MethodGet, "/admin/health", "", h.Health},
		{http.MethodGet, "/health", "", h.Health},

		// Clients.
		{http.MethodGet, "/admin/clients", support, h.ListClients},
		{http.MethodPost, "/admin/clients", admin, h.CreateClient},
		{http.MethodGet, "/admin/clients/{id}", support, h.GetClient},
		{http.MethodPatch, "/admin/clients/{id}", admin, h.UpdateClient},
		{http.MethodPost, "/admin/clients/{id}/disable", admin, h.DisableClient},
		{http.MethodPost, "/admin/clients/{id}/enable", admin, h.EnableClient},
		{http.MethodDelete, "/admin/clients/{id}", admin, h.DeleteClient},

		// Users: read and the support-tier recovery actions.
		{http.MethodGet, "/admin/users", support, h.ListUsers},
		{http.MethodGet, "/admin/users/{id}", support, h.GetUser},
		{http.MethodPost, "/admin/users/{id}/unlock", support, h.Unlock},
		{http.MethodPost, "/admin/users/{id}/revoke-sessions", support, h.RevokeSessions},

		// Users: admin-tier. Password reset is here, not at support level,
		// because it is the action that hands over a path into an account.
		{http.MethodPatch, "/admin/users/{id}", admin, h.UpdateUser},
		{http.MethodDelete, "/admin/users/{id}", admin, h.DeleteUser},
		{http.MethodPost, "/admin/users/{id}/password-reset", admin, h.IssuePasswordReset},

		{http.MethodGet, "/admin/audit", admin, h.ListAudit},
	}
}

// Mount registers every route on mux, wrapping each in its role gate. mw is
// applied outermost-first to the whole set (rate limiting, etc.).
func Mount(mux *http.ServeMux, h *Handler, mw ...func(http.Handler) http.Handler) {
	for _, route := range h.Routes() {
		handler := route.Handler
		if !route.Public() {
			handler = h.requireRole(route.Role, handler)
		}

		var wrapped http.Handler = handler
		for i := len(mw) - 1; i >= 0; i-- {
			wrapped = mw[i](wrapped)
		}
		mux.Handle(route.Method+" "+route.Path, wrapped)
	}
}
