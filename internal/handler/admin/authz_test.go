package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	adminmodel "github.com/manjushsh/auth-service/internal/model/admin"
	authmodel "github.com/manjushsh/auth-service/internal/model/auth"
	"github.com/manjushsh/auth-service/internal/secret"
	adminsvc "github.com/manjushsh/auth-service/internal/service/admin"
	authsvc "github.com/manjushsh/auth-service/internal/service/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
	"github.com/manjushsh/auth-service/internal/store/memory"
	"github.com/manjushsh/auth-service/internal/token"
)

const testPassword = "correct-horse-battery-staple"

type fixture struct {
	t       *testing.T
	mux     *http.ServeMux
	handler *Handler
	store   *store.MemoryStore
	tokens  *token.Manager
	auth    *authsvc.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	st := store.NewMemoryStore()
	vol := memory.New()

	tokens, err := token.NewManager([]byte(strings.Repeat("s", token.MinSecretLen)), secret.NewToken, time.Now)
	if err != nil {
		t.Fatalf("token.NewManager: %v", err)
	}

	authService, err := authsvc.New(authsvc.Deps{
		Store: st, Codes: vol, Blocklist: vol, Locker: vol,
		Epochs: vol, Resets: vol, Audit: st, Tokens: tokens,
	}, authsvc.Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatalf("authsvc.New: %v", err)
	}

	adminService, err := adminsvc.New(adminsvc.Deps{
		Store: st, Accounts: authService, Blocklist: vol, Tokens: tokens,
		Verifier: &token.Verifier{Manager: tokens, Blocklist: vol, Epochs: vol},
		HealthChecks: map[string]func(context.Context) error{
			"memory": func(context.Context) error { return nil },
		},
	}, adminsvc.Config{})
	if err != nil {
		t.Fatalf("adminsvc.New: %v", err)
	}

	f := &fixture{
		t: t, mux: http.NewServeMux(), handler: New(adminService),
		store: st, tokens: tokens, auth: authService,
	}
	Mount(f.mux, f.handler)

	// One account per role, so the table below can log in as any of them.
	f.register("admin@example.com", store.RoleAdmin)
	f.register("support@example.com", store.RoleSupport)
	f.register("user@example.com", store.RoleUser)
	return f
}

func (f *fixture) register(email, role string) store.UserRecord {
	f.t.Helper()
	ctx := context.Background()

	err := f.auth.Register(ctx, authmodel.RegisterRequest{
		Credentials: authmodel.Credentials{Email: email, Password: testPassword},
	})
	if err != nil {
		f.t.Fatalf("Register(%s): %v", email, err)
	}
	u, err := f.store.GetUser(ctx, email)
	if err != nil {
		f.t.Fatalf("GetUser(%s): %v", email, err)
	}
	if role != store.RoleUser {
		// Seeded rather than applied through the API: fixture setup is not an
		// administrative action and must not appear in the audit log.
		f.store.SeedRole(u.ID, role)
		u.Role = role
	}
	return u
}

// adminToken logs in through the real endpoint and returns the bearer token.
func (f *fixture) adminToken(email string) string {
	f.t.Helper()

	rec := f.do(http.MethodPost, "/admin/auth/login", "",
		`{"email":"`+email+`","password":"`+testPassword+`"}`)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("login as %s: status %d, body %s", email, rec.Code, rec.Body)
	}

	var resp adminmodel.LoginResponse
	decodeJSON(f.t, rec, &resp)
	return resp.Token
}

// userToken mints a token for the public plane — the credential that must never
// open this one.
func (f *fixture) userToken(email string) string {
	f.t.Helper()

	u, err := f.store.GetUser(context.Background(), email)
	if err != nil {
		f.t.Fatalf("GetUser: %v", err)
	}
	minted, err := f.tokens.Mint(token.Grant{
		Subject: u.ID, Audience: token.AudienceUser, TTL: time.Hour, Role: u.Role,
	})
	if err != nil {
		f.t.Fatalf("Mint: %v", err)
	}
	return minted.Raw
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response %s: %v", rec.Body, err)
	}
}

func (f *fixture) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	f.t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

// concretePath substitutes a plausible id for the {id} wildcard so requests
// reach the role gate rather than failing to route.
func concretePath(pattern string) string {
	return strings.ReplaceAll(pattern, "{id}", "00000000-0000-4000-8000-000000000000")
}

// TestRoutes_RejectUnauthorizedCallers is the guard the whole plane rests on.
//
// It is driven from the route table itself rather than a hand-maintained list,
// so an endpoint added without a role gate fails here instead of shipping open.
func TestRoutes_RejectUnauthorizedCallers(t *testing.T) {
	f := newFixture(t)

	adminTok := f.adminToken("admin@example.com")
	supportTok := f.adminToken("support@example.com")
	userAudienceTok := f.userToken("admin@example.com")

	// A well-formed JWT signed with the wrong key.
	otherManager, err := token.NewManager([]byte(strings.Repeat("x", token.MinSecretLen)), secret.NewToken, time.Now)
	if err != nil {
		t.Fatalf("token.NewManager: %v", err)
	}
	forged, err := otherManager.Mint(token.Grant{
		Subject: "00000000-0000-4000-8000-000000000000", Audience: token.AudienceAdmin, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	credentials := []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"garbage token", "not-a-jwt", http.StatusUnauthorized},
		{"wrongly signed token", forged.Raw, http.StatusUnauthorized},
		// The one that matters most: a valid token for the same admin, minted
		// for the public plane.
		{"user-audience token", userAudienceTok, http.StatusUnauthorized},
	}

	for _, route := range f.handler.Routes() {
		if route.Public() {
			continue
		}
		for _, cred := range credentials {
			name := route.Method + " " + route.Path + "/" + cred.name
			t.Run(name, func(t *testing.T) {
				rec := f.do(route.Method, concretePath(route.Path), cred.token, "{}")
				if rec.Code != cred.want {
					t.Fatalf("status %d, want %d (body %s)", rec.Code, cred.want, rec.Body)
				}
			})
		}

		// A support token on an admin-only route must be 403, not 401: the
		// caller is authenticated, just not permitted.
		if route.Role == store.RoleAdmin {
			t.Run(route.Method+" "+route.Path+"/support token", func(t *testing.T) {
				rec := f.do(route.Method, concretePath(route.Path), supportTok, "{}")
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status %d, want 403 (body %s)", rec.Code, rec.Body)
				}
			})
		}
	}

	// Sanity check on the fixture itself: the admin token must actually work,
	// or every assertion above would pass for the wrong reason.
	if rec := f.do(http.MethodGet, "/admin/auth/whoami", adminTok, ""); rec.Code != http.StatusOK {
		t.Fatalf("whoami with a valid admin token: status %d, body %s", rec.Code, rec.Body)
	}
}

// Every route must declare a role, except the two that authenticate callers
// themselves. Without this, "forgot to add a role" is indistinguishable from
// "deliberately public".
func TestRoutes_OnlyLoginAndHealthArePublic(t *testing.T) {
	f := newFixture(t)

	allowed := map[string]bool{
		"POST /admin/auth/login": true,
		"GET /admin/health":      true,
		"GET /health":            true, // alias of the above, same handler
	}
	for _, route := range f.handler.Routes() {
		key := route.Method + " " + route.Path
		if route.Public() && !allowed[key] {
			t.Errorf("%s has no role gate; add one or add it to the allow-list with a reason", key)
		}
	}
}

func TestSuspendedAdminCannotAuthenticate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// A second admin, so the last-admin guard permits the suspension.
	victim := f.register("second@example.com", store.RoleAdmin)
	tok := f.adminToken("second@example.com")

	ev := store.AuditEvent{ActorEmail: "test", ActorRole: "test", Action: "user.suspend", Result: store.AuditOK}
	if err := f.store.SetUserStatus(ctx, victim.ID, store.StatusSuspended, ev); err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}

	if rec := f.do(http.MethodGet, "/admin/auth/whoami", tok, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("suspended admin: status %d, want 401 (body %s)", rec.Code, rec.Body)
	}
}
