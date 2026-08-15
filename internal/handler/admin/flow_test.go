package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/manjushsh/auth-service/internal/middleware"
	adminmodel "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// TestClientLifecycle_OverHTTP walks the workflow this plane exists to replace:
// onboarding a relying application without a psql session.
func TestClientLifecycle_OverHTTP(t *testing.T) {
	f := newFixture(t)
	tok := f.adminToken("admin@example.com")

	// Create.
	rec := f.do(http.MethodPost, "/admin/clients", tok,
		`{"name":"my-app","redirect_uri":"https://app.example.com/callback"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", rec.Code, rec.Body)
	}
	var created adminmodel.Client
	decodeJSON(t, rec, &created)
	if created.ID == "" || created.Disabled {
		t.Fatalf("unexpected created client: %+v", created)
	}

	// Duplicate.
	rec = f.do(http.MethodPost, "/admin/clients", tok,
		`{"name":"copy","redirect_uri":"https://app.example.com/callback"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: status %d, want 409 (body %s)", rec.Code, rec.Body)
	}

	// A redirect_uri change is refused with an explanation, not ignored.
	rec = f.do(http.MethodPatch, "/admin/clients/"+created.ID, tok,
		`{"redirect_uri":"https://elsewhere.example.com/cb"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("redirect_uri patch: status %d, want 400 (body %s)", rec.Code, rec.Body)
	}

	// Rename.
	rec = f.do(http.MethodPatch, "/admin/clients/"+created.ID, tok, `{"name":"renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename: status %d, body %s", rec.Code, rec.Body)
	}

	// List sees it.
	rec = f.do(http.MethodGet, "/admin/clients", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", rec.Code, rec.Body)
	}
	var list adminmodel.ClientList
	decodeJSON(t, rec, &list)
	if len(list.Clients) != 1 || list.Clients[0].Name != "renamed" {
		t.Fatalf("unexpected list: %+v", list.Clients)
	}

	// Disable, then delete with the confirmation echo.
	if rec = f.do(http.MethodPost, "/admin/clients/"+created.ID+"/disable", tok, ""); rec.Code != http.StatusOK {
		t.Fatalf("disable: status %d, body %s", rec.Code, rec.Body)
	}
	rec = f.do(http.MethodDelete, "/admin/clients/"+created.ID, tok, `{"redirect_uri":"https://wrong.example.com/cb"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete with wrong confirmation: status %d, want 400 (body %s)", rec.Code, rec.Body)
	}
	rec = f.do(http.MethodDelete, "/admin/clients/"+created.ID, tok, `{"redirect_uri":"https://app.example.com/callback"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, want 204 (body %s)", rec.Code, rec.Body)
	}

	// 404 for the now-missing client, and for a malformed id.
	for _, id := range []string{created.ID, "not-a-uuid"} {
		if rec = f.do(http.MethodGet, "/admin/clients/"+id, tok, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("get %q: status %d, want 404 (body %s)", id, rec.Code, rec.Body)
		}
	}
}

// TestUserSupportFlow_OverHTTP covers the support-tier operations and confirms
// the audit log records them.
func TestUserSupportFlow_OverHTTP(t *testing.T) {
	f := newFixture(t)
	supportTok := f.adminToken("support@example.com")
	adminTok := f.adminToken("admin@example.com")

	victim := f.register("victim@example.com", store.RoleUser)

	// Support can read, unlock and revoke.
	rec := f.do(http.MethodGet, "/admin/users?email=victim@example.com", supportTok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list users: status %d, body %s", rec.Code, rec.Body)
	}
	var list adminmodel.UserList
	decodeJSON(t, rec, &list)
	if len(list.Users) != 1 || list.Users[0].ID != victim.ID {
		t.Fatalf("unexpected user list: %+v", list.Users)
	}

	for _, path := range []string{"/unlock", "/revoke-sessions"} {
		if rec = f.do(http.MethodPost, "/admin/users/"+victim.ID+path, supportTok, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: status %d, want 204 (body %s)", path, rec.Code, rec.Body)
		}
	}

	// Password reset is admin-only — that split is what stops the common role
	// taking an account over on its own.
	rec = f.do(http.MethodPost, "/admin/users/"+victim.ID+"/password-reset", supportTok, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("support password reset: status %d, want 403 (body %s)", rec.Code, rec.Body)
	}
	rec = f.do(http.MethodPost, "/admin/users/"+victim.ID+"/password-reset", adminTok, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin password reset: status %d, want 201 (body %s)", rec.Code, rec.Body)
	}
	var reset adminmodel.PasswordResetResponse
	decodeJSON(t, rec, &reset)
	if reset.ResetToken == "" {
		t.Fatal("expected a reset token")
	}

	// The audit endpoint shows the trail, and the token is not in it.
	rec = f.do(http.MethodGet, "/admin/audit?target="+victim.ID, adminTok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("audit: status %d, body %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "user.unlock") || !strings.Contains(body, "user.revoke_sessions") {
		t.Fatalf("audit trail missing the support actions: %s", body)
	}
	if strings.Contains(body, reset.ResetToken) {
		t.Fatal("the reset token appears in the audit log")
	}
}

// TestCredentialResponsesAreNotCacheable guards the header that keeps a reset
// token out of an intermediary's cache.
func TestCredentialResponsesAreNotCacheable(t *testing.T) {
	f := newFixture(t)
	// SecurityHeaders is applied by the server chain, not the mux, so assert on
	// the middleware directly against a handler from this package.
	rec := f.do(http.MethodGet, "/admin/health", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health: status %d, body %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	// The header itself comes from SecurityHeaders, which the server chain
	// wraps around this mux.
	wrapped := middleware.SecurityHeaders(f.mux)
	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	inner := httptest.NewRecorder()
	wrapped.ServeHTTP(inner, req)
	if cc := inner.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

// /health answers on the admin listener as well as /admin/health. Probes and
// humans look for the bare path first, and a 404 there reads like the service
// is down rather than like the URL is wrong.
func TestHealth_AnsweredOnBothPaths(t *testing.T) {
	f := newFixture(t)

	for _, path := range []string{"/admin/health", "/health"} {
		rec := f.do(http.MethodGet, path, "", "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200 (body %s)", path, rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), `"status"`) {
			t.Errorf("GET %s: unexpected body %s", path, rec.Body)
		}
	}
}
