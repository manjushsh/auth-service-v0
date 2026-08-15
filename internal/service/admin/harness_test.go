package admin

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	authmodel "github.com/manjushsh/auth-service/internal/model/auth"
	"github.com/manjushsh/auth-service/internal/secret"
	authsvc "github.com/manjushsh/auth-service/internal/service/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
	"github.com/manjushsh/auth-service/internal/store/memory"
	"github.com/manjushsh/auth-service/internal/token"
)

const testPassword = "correct-horse-battery-staple"

// harness wires the admin service against the real auth service and the real
// in-memory stores. Nothing here is a stub: the point of these tests is the
// interaction between the two services, which a fake accountOps would hide.
type harness struct {
	t        *testing.T
	store    *store.MemoryStore
	volatile *memory.Store
	auth     *authsvc.Service
	tokens   *token.Manager
	admin    *Service
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	st := store.NewMemoryStore()
	vol := memory.New()

	tokens, err := token.NewManager([]byte(strings.Repeat("s", token.MinSecretLen)), secret.NewToken, time.Now)
	if err != nil {
		t.Fatalf("token.NewManager: %v", err)
	}
	verifier := &token.Verifier{Manager: tokens, Blocklist: vol, Epochs: vol}

	authService, err := authsvc.New(authsvc.Deps{
		Store: st, Codes: vol, Blocklist: vol, Locker: vol,
		Epochs: vol, Resets: vol, Audit: st, Tokens: tokens,
	}, authsvc.Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatalf("authsvc.New: %v", err)
	}

	adminService, err := New(Deps{
		Store: st, Accounts: authService, Blocklist: vol,
		Tokens: tokens, Verifier: verifier,
		HealthChecks: map[string]func(context.Context) error{
			"memory": func(context.Context) error { return nil },
		},
	}, Config{})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}

	return &harness{t: t, store: st, volatile: vol, auth: authService, tokens: tokens, admin: adminService}
}

// user registers an account with the given role.
func (h *harness) user(email, role string) store.UserRecord {
	h.t.Helper()
	ctx := context.Background()

	err := h.auth.Register(ctx, authmodel.RegisterRequest{
		Credentials: authmodel.Credentials{Email: email, Password: testPassword},
	})
	if err != nil {
		h.t.Fatalf("Register(%s): %v", email, err)
	}

	u, err := h.store.GetUser(ctx, email)
	if err != nil {
		h.t.Fatalf("GetUser(%s): %v", email, err)
	}
	if role == store.RoleUser {
		return u
	}

	// Seeded, not applied through the API: this stands in for the adminctl
	// bootstrap path, and building a fixture must not leave audit rows that the
	// tests then count.
	h.store.SeedRole(u.ID, role)
	u.Role = role
	return u
}

// caller builds the Caller a handler would have produced for this account.
func (h *harness) caller(u store.UserRecord) Caller {
	return Caller{
		UserID: u.ID, Email: u.Email, Role: u.Role,
		Meta: store.RequestMeta{RemoteAddr: "10.0.0.1"},
	}
}

// admins registers one admin and one support account, the usual starting point.
func (h *harness) admins() (admin, support Caller) {
	return h.caller(h.user("admin@example.com", store.RoleAdmin)),
		h.caller(h.user("support@example.com", store.RoleSupport))
}

// auditActions returns every recorded action, in order.
func (h *harness) auditActions() []string {
	records := h.store.AuditEvents()
	actions := make([]string, 0, len(records))
	for _, r := range records {
		actions = append(actions, r.Action)
	}
	return actions
}

// countAudit counts records for one action.
func (h *harness) countAudit(action string) int {
	n := 0
	for _, a := range h.auditActions() {
		if a == action {
			n++
		}
	}
	return n
}
