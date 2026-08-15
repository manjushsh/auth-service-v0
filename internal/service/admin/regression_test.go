package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	model "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
	"github.com/manjushsh/auth-service/internal/token"
)

// failingEpochs makes RevokeSessions fail, so the ordering between "revoke the
// user's sessions" and "apply the change" becomes observable.
type failingEpochs struct {
	accountOps
	fail bool
}

func (f *failingEpochs) RevokeSessions(ctx context.Context, userID string) error {
	if f.fail {
		return errors.New("redis unavailable")
	}
	return f.accountOps.RevokeSessions(ctx, userID)
}

func newBrokenRevokeHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.admin.accounts = &failingEpochs{accountOps: h.admin.accounts, fail: true}
	return h
}

// A suspension that commits while session revocation fails would leave the
// account suspended in Postgres with live tokens for up to a token lifetime —
// which is precisely the guarantee the endpoint exists to provide. Revoking
// first makes the failure mode "logged out for a change that did not happen".
func TestUpdateUser_DoesNotApplyTheChangeWhenRevocationFails(t *testing.T) {
	h := newBrokenRevokeHarness(t)
	admin, _ := h.admins()
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	_, err := h.admin.UpdateUser(ctx, admin, victim.ID,
		model.UpdateUserRequest{Status: ptr(store.StatusSuspended)})
	if err == nil {
		t.Fatal("expected the update to fail when sessions cannot be revoked")
	}

	after, err := h.store.GetUserByID(ctx, victim.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.Status != store.StatusActive {
		t.Fatalf("status = %q; the change must not commit when revocation fails", after.Status)
	}
	if n := len(h.store.AuditEvents()); n != 0 {
		t.Fatalf("expected no audit rows for a change that did not happen, got %d", n)
	}
}

func TestDeleteUser_DoesNotDeleteWhenRevocationFails(t *testing.T) {
	h := newBrokenRevokeHarness(t)
	admin, _ := h.admins()
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	err := h.admin.DeleteUser(ctx, admin, victim.ID, model.DeleteUserRequest{Email: victim.Email})
	if err == nil {
		t.Fatal("expected the delete to fail when sessions cannot be revoked")
	}
	if _, err := h.store.GetUserByID(ctx, victim.ID); err != nil {
		t.Fatalf("the user must survive a failed delete: %v", err)
	}
}

// A PATCH that sets both fields is one transaction: the last-admin guard must
// reject it whole, not apply the status change and then fail on the role.
func TestUpdateUser_AppliesBothFieldsAtomically(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", store.RoleAdmin)
	support := h.caller(h.user("support@example.com", store.RoleSupport))
	ctx := context.Background()

	// Suspending *and* demoting the only admin: both halves remove admin
	// capability, so the guard fires and neither may land.
	_, err := h.admin.UpdateUser(ctx, support, admin.ID, model.UpdateUserRequest{
		Status: ptr(store.StatusSuspended),
		Role:   ptr(store.RoleUser),
	})
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("got %v, want ErrLastAdmin", err)
	}

	after, err := h.store.GetUserByID(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.Status != store.StatusActive || after.Role != store.RoleAdmin {
		t.Fatalf("partial application: status=%q role=%q, want active/admin", after.Status, after.Role)
	}
}

// A successful two-field PATCH still records one row per distinct change, so
// "who suspended this account" and "who demoted them" remain separate answers.
func TestUpdateUser_RecordsOneAuditRowPerChange(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	h.user("second@example.com", store.RoleAdmin)
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	before := len(h.store.AuditEvents())
	_, err := h.admin.UpdateUser(ctx, admin, victim.ID, model.UpdateUserRequest{
		Status: ptr(store.StatusSuspended),
		Role:   ptr(store.RoleSupport),
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	if got := len(h.store.AuditEvents()) - before; got != 2 {
		t.Fatalf("wrote %d audit rows, want 2 (suspend + role change): %v", got, h.auditActions())
	}
	for _, action := range []string{"user.suspend", "user.role_change"} {
		if h.countAudit(action) != 1 {
			t.Errorf("%s: got %d records, want 1", action, h.countAudit(action))
		}
	}
}

// The creation event must name the client it created, or the first query anyone
// runs during an incident — filter the log by target — silently misses it.
func TestCreateClient_AuditRecordNamesTheNewClient(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	ctx := context.Background()

	created := createClient(t, h, admin, "my-app", testRedirect)

	list, err := h.admin.ListAudit(ctx, store.AuditFilter{TargetID: created.ID})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	found := false
	for _, r := range list.Records {
		if r.Action == "client.create" {
			found = true
		}
	}
	if !found {
		t.Fatalf("client.create is not retrievable by its target id %q; records: %+v", created.ID, list.Records)
	}
}

// The break-glass tool must never report "no privileged accounts" on a system
// that has them. Filtering a page of users in memory did exactly that once the
// user count passed one page.
func TestListPrivilegedUsers_FindsAdminsBeyondTheFirstPage(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// The admin is created first, so it is the *oldest* row and falls off the
	// newest-first page once enough ordinary users exist.
	admin := h.user("admin@example.com", store.RoleAdmin)
	for i := range store.MaxPageSize + 10 {
		h.user(fmt.Sprintf("user%03d@example.com", i), store.RoleUser)
	}

	// Demonstrate the trap the old implementation fell into.
	page, err := h.store.ListUsers(ctx, "", store.Page{Limit: store.MaxPageSize})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	inPage := false
	for _, u := range page {
		if u.ID == admin.ID {
			inPage = true
		}
	}
	if inPage {
		t.Skip("fixture too small: the admin still lands in the first page")
	}

	privileged, err := h.store.ListPrivilegedUsers(ctx)
	if err != nil {
		t.Fatalf("ListPrivilegedUsers: %v", err)
	}
	for _, u := range privileged {
		if u.ID == admin.ID {
			return
		}
	}
	t.Fatalf("the admin is missing from %d privileged accounts", len(privileged))
}

// A readiness probe that cannot fail is worse than none.
func TestNew_RequiresAtLeastOneHealthCheck(t *testing.T) {
	h := newHarness(t)

	_, err := New(Deps{
		Store: h.store, Accounts: h.auth, Blocklist: h.volatile,
		Tokens: h.tokens, Verifier: &token.Verifier{Manager: h.tokens, Blocklist: h.volatile, Epochs: h.volatile},
	}, Config{})
	if err == nil {
		t.Fatal("expected New to reject a service with no health checks")
	}
}

// Health must not hand an unauthenticated caller the contents of a driver
// error, which routinely names the host and database.
func TestHealth_DoesNotLeakErrorDetail(t *testing.T) {
	h := newHarness(t)
	const secret = "postgres://auth:hunter2@db.internal:5432/authdb"

	svc, err := New(Deps{
		Store: h.store, Accounts: h.auth, Blocklist: h.volatile,
		Tokens: h.tokens, Verifier: &token.Verifier{Manager: h.tokens, Blocklist: h.volatile, Epochs: h.volatile},
		HealthChecks: map[string]func(context.Context) error{
			"postgres": func(context.Context) error { return errors.New("dial " + secret + ": refused") },
		},
	}, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	healthy, components := svc.Health(context.Background())
	if healthy {
		t.Fatal("expected an unhealthy report")
	}
	if got := components["postgres"]; got != "error" {
		t.Fatalf("component status = %q, want a bare %q", got, "error")
	}
	if strings.Contains(fmt.Sprint(components), secret) {
		t.Fatalf("health response leaked connection detail: %v", components)
	}
}

// An empty page must serialize as [] rather than null, or a client iterating
// the result breaks on "no matches". The two stores disagreed on this once:
// the in-memory one returned an empty slice and Postgres returned nil.
func TestListEndpoints_ReturnEmptySlicesNotNil(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	audit, err := h.admin.ListAudit(ctx, store.AuditFilter{Action: "no-such-action"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	users, err := h.admin.ListUsers(ctx, "nobody@example.com", store.Page{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	clients, err := h.admin.ListClients(ctx, store.Page{})
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}

	for name, blob := range map[string]any{
		"audit": audit, "users": users, "clients": clients,
	} {
		encoded, err := json.Marshal(blob)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		if strings.Contains(string(encoded), "null") {
			t.Errorf("%s encodes an empty list as null: %s", name, encoded)
		}
	}
}
