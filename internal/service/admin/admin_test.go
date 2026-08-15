package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	model "github.com/manjushsh/auth-service/internal/model/admin"
	authmodel "github.com/manjushsh/auth-service/internal/model/auth"
	authsvc "github.com/manjushsh/auth-service/internal/service/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
	"github.com/manjushsh/auth-service/internal/token"
)

func ptr[T any](v T) *T { return &v }

// --- authentication ---

func TestLogin_RequiresAPrivilegedRole(t *testing.T) {
	h := newHarness(t)
	h.user("nobody@example.com", store.RoleUser)

	_, err := h.admin.Login(context.Background(),
		model.LoginRequest{Email: "nobody@example.com", Password: testPassword},
		store.RequestMeta{})
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ordinary user login: got %v, want ErrUnauthenticated", err)
	}
}

// The audit table records failures against accounts that can actually use this
// plane, and only those.
//
// admin/auth/login is unauthenticated, so recording every attempt would let
// anyone who can reach the port write unbounded rows about accounts that do not
// exist. Attempts against a real admin are the opposite: they are the signal
// worth keeping.
func TestLogin_AuditsFailuresOnlyForPrivilegedAccounts(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", store.RoleAdmin)
	h.user("nobody@example.com", store.RoleUser)
	ctx := context.Background()

	attempts := []string{
		"nobody@example.com", // exists, not privileged
		"ghost@example.com",  // does not exist at all
		"admin@example.com",  // privileged: this one counts
	}
	for _, email := range attempts {
		_, _ = h.admin.Login(ctx,
			model.LoginRequest{Email: email, Password: "wrong-password"}, store.RequestMeta{})
	}

	if got := h.countAudit("admin.login.failed"); got != 1 {
		t.Fatalf("recorded %d login failures, want exactly 1 (the privileged account); actions: %v",
			got, h.auditActions())
	}

	// And the row is attributable, not a bare email string.
	for _, r := range h.store.AuditEvents() {
		if r.Action != "admin.login.failed" {
			continue
		}
		if r.ActorID == "" || r.ActorRole != store.RoleAdmin {
			t.Fatalf("login-failure record is not attributable: %+v", r)
		}
	}
}

func TestLogin_SucceedsForAdminAndAudits(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", store.RoleAdmin)

	resp, err := h.admin.Login(context.Background(),
		model.LoginRequest{Email: "admin@example.com", Password: testPassword},
		store.RequestMeta{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.Token == "" || resp.Role != store.RoleAdmin || resp.ExpiresIn <= 0 {
		t.Fatalf("unexpected login response: %+v", resp)
	}
	if h.countAudit("admin.login.ok") != 1 {
		t.Fatalf("expected one successful-login record, got %v", h.auditActions())
	}
}

// Login routes through the auth service's VerifyPassword, so it inherits the
// account lockout instead of being an unthrottled password oracle that bypasses
// MAX_LOGIN_ATTEMPTS entirely.
func TestLogin_SharesTheAccountLockout(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", store.RoleAdmin)
	ctx := context.Background()

	for range authsvc.DefaultMaxLoginAttempts {
		_, err := h.admin.Login(ctx,
			model.LoginRequest{Email: "admin@example.com", Password: "wrong-password"},
			store.RequestMeta{})
		if !errors.Is(err, authsvc.ErrInvalidCredentials) {
			t.Fatalf("wrong password: got %v, want ErrInvalidCredentials", err)
		}
	}

	_, err := h.admin.Login(ctx,
		model.LoginRequest{Email: "admin@example.com", Password: testPassword},
		store.RequestMeta{})
	if !errors.Is(err, authsvc.ErrAccountLocked) {
		t.Fatalf("after %d failures: got %v, want ErrAccountLocked", authsvc.DefaultMaxLoginAttempts, err)
	}
}

// The single most important guard in this package: user JWTs are handed to
// third-party relying applications by design, so one must never open the admin
// plane.
func TestAuthenticate_RejectsUserAudienceToken(t *testing.T) {
	h := newHarness(t)
	u := h.user("admin@example.com", store.RoleAdmin)
	ctx := context.Background()

	// A token for the same admin, minted for the public plane.
	minted, err := h.tokens.Mint(token.Grant{
		Subject: u.ID, Audience: token.AudienceUser, TTL: time.Hour, Role: store.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if _, err := h.admin.Authenticate(ctx, minted.Raw, store.RequestMeta{}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("user-audience token: got %v, want ErrUnauthenticated", err)
	}
}

func TestAuthenticate_RejectsRevokedSuspendedAndDemoted(t *testing.T) {
	h := newHarness(t)
	u := h.user("admin@example.com", store.RoleAdmin)
	other := h.user("second@example.com", store.RoleAdmin) // keeps the last-admin guard happy
	ctx := context.Background()

	login := func() string {
		t.Helper()
		resp, err := h.admin.Login(ctx,
			model.LoginRequest{Email: u.Email, Password: testPassword}, store.RequestMeta{})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		return resp.Token
	}

	t.Run("logout revokes", func(t *testing.T) {
		tok := login()
		if err := h.admin.Logout(ctx, tok); err != nil {
			t.Fatalf("Logout: %v", err)
		}
		if _, err := h.admin.Authenticate(ctx, tok, store.RequestMeta{}); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("after logout: got %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("suspension revokes", func(t *testing.T) {
		tok := login()
		_, err := h.admin.UpdateUser(ctx, h.caller(other), u.ID,
			model.UpdateUserRequest{Status: ptr(store.StatusSuspended)})
		if err != nil {
			t.Fatalf("suspend: %v", err)
		}
		if _, err := h.admin.Authenticate(ctx, tok, store.RequestMeta{}); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("after suspension: got %v, want ErrUnauthenticated", err)
		}
	})
}

// The role in the token is advisory; authorization re-reads it, so a demotion
// takes effect on the next request rather than at token expiry.
func TestAuthenticate_ReadsRoleFreshFromTheStore(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", store.RoleAdmin)
	h.user("second@example.com", store.RoleAdmin)
	ctx := context.Background()

	resp, err := h.admin.Login(ctx,
		model.LoginRequest{Email: admin.Email, Password: testPassword}, store.RequestMeta{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Demote behind the token's back, without bumping the epoch, so only the
	// fresh read can catch it.
	ev := store.AuditEvent{ActorEmail: "t", ActorRole: "t", Action: "user.role_change", Result: store.AuditOK}
	if err := h.store.SetUserRole(ctx, admin.ID, store.RoleSupport, ev); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}

	caller, err := h.admin.Authenticate(ctx, resp.Token, store.RequestMeta{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if caller.Role != store.RoleSupport {
		t.Fatalf("caller role = %q, want the freshly-read %q", caller.Role, store.RoleSupport)
	}
}

func TestAuthorize_DeniesAndAudits(t *testing.T) {
	h := newHarness(t)
	_, support := h.admins()
	ctx := context.Background()

	if err := h.admin.Authorize(ctx, support, store.RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Fatalf("support on an admin route: got %v, want ErrForbidden", err)
	}
	if h.countAudit("authz.denied") != 1 {
		t.Fatalf("expected the denial to be audited, got %v", h.auditActions())
	}
	// admin satisfies a support requirement: roles are a ladder.
	adminCaller := h.caller(h.user("boss@example.com", store.RoleAdmin))
	if err := h.admin.Authorize(ctx, adminCaller, store.RoleSupport); err != nil {
		t.Fatalf("admin on a support route: %v", err)
	}
}

// --- last-admin and self-target guards ---

func TestUpdateUser_RefusesToRemoveTheLastAdmin(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", store.RoleAdmin)
	support := h.caller(h.user("support@example.com", store.RoleSupport))
	ctx := context.Background()

	// Demotion, suspension and deletion all remove admin capability, so all
	// three take the guard.
	cases := map[string]func() error{
		"demote": func() error {
			_, err := h.admin.UpdateUser(ctx, support, admin.ID, model.UpdateUserRequest{Role: ptr(store.RoleUser)})
			return err
		},
		"suspend": func() error {
			_, err := h.admin.UpdateUser(ctx, support, admin.ID, model.UpdateUserRequest{Status: ptr(store.StatusSuspended)})
			return err
		},
		"delete": func() error {
			return h.admin.DeleteUser(ctx, support, admin.ID, model.DeleteUserRequest{Email: admin.Email})
		},
	}
	for name, action := range cases {
		t.Run(name, func(t *testing.T) {
			if err := action(); !errors.Is(err, ErrLastAdmin) {
				t.Fatalf("%s the only admin: got %v, want ErrLastAdmin", name, err)
			}
		})
	}

	// With a second admin present, the demotion succeeds.
	second := h.user("second@example.com", store.RoleAdmin)
	if _, err := h.admin.UpdateUser(ctx, support, second.ID, model.UpdateUserRequest{Role: ptr(store.RoleUser)}); err != nil {
		t.Fatalf("demoting a non-final admin: %v", err)
	}
}

func TestUpdateUser_RefusesSelfTarget(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	h.user("second@example.com", store.RoleAdmin)
	ctx := context.Background()

	_, err := h.admin.UpdateUser(ctx, admin, admin.UserID, model.UpdateUserRequest{Role: ptr(store.RoleUser)})
	if !errors.Is(err, ErrSelfTarget) {
		t.Fatalf("self-demotion: got %v, want ErrSelfTarget", err)
	}
	err = h.admin.DeleteUser(ctx, admin, admin.UserID, model.DeleteUserRequest{Email: admin.Email})
	if !errors.Is(err, ErrSelfTarget) {
		t.Fatalf("self-deletion: got %v, want ErrSelfTarget", err)
	}
}

// --- confirmation echo ---

func TestDeleteUser_RequiresMatchingEmailAndRevokesSessions(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	for _, wrong := range []string{"", "someone-else@example.com"} {
		err := h.admin.DeleteUser(ctx, admin, victim.ID, model.DeleteUserRequest{Email: wrong})
		if !errors.Is(err, ErrConfirmationMismatch) {
			t.Fatalf("delete with confirmation %q: got %v, want ErrConfirmationMismatch", wrong, err)
		}
	}
	if _, err := h.store.GetUserByID(ctx, victim.ID); err != nil {
		t.Fatalf("victim must still exist after a refused delete: %v", err)
	}

	if err := h.admin.DeleteUser(ctx, admin, victim.ID, model.DeleteUserRequest{Email: victim.Email}); err != nil {
		t.Fatalf("delete with the right confirmation: %v", err)
	}
	if _, err := h.store.GetUserByID(ctx, victim.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
	// The row is gone; the tokens must be too.
	if epoch, err := h.volatile.Epoch(ctx, victim.ID); err != nil || epoch.IsZero() {
		t.Fatalf("delete must revoke the user's sessions (epoch %v, err %v)", epoch, err)
	}
}

// --- account operations ---

func TestUnlock_ReleasesTheLockoutAndAudits(t *testing.T) {
	h := newHarness(t)
	_, support := h.admins()
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	for range authsvc.DefaultMaxLoginAttempts {
		h.auth.GenerateCode(ctx, authmodel.GenerateCodeRequest{ //nolint:errcheck // failure is the point
			Credentials: authmodel.Credentials{Email: victim.Email, Password: "wrong-password"},
		})
	}
	if locked, _ := h.auth.LockState(ctx, victim.Email); !locked {
		t.Fatal("expected the victim to be locked out")
	}

	if err := h.admin.Unlock(ctx, support, victim.ID, model.UnlockRequest{}); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if locked, _ := h.auth.LockState(ctx, victim.Email); locked {
		t.Fatal("expected the lockout to be released")
	}
	if h.countAudit("user.unlock") != 1 {
		t.Fatalf("expected one unlock record, got %v", h.auditActions())
	}

	// Idempotent, and an unknown scope is a bad request rather than a silent
	// no-op that reports success.
	if err := h.admin.Unlock(ctx, support, victim.ID, model.UnlockRequest{Scope: "all"}); err != nil {
		t.Fatalf("second Unlock: %v", err)
	}
	if err := h.admin.Unlock(ctx, support, victim.ID, model.UnlockRequest{Scope: "nonsense"}); !errors.Is(err, ErrBadInput) {
		t.Fatalf("unknown scope: got %v, want ErrBadInput", err)
	}
}

func TestRevokeSessions_BumpsTheEpochAndAudits(t *testing.T) {
	h := newHarness(t)
	_, support := h.admins()
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	if err := h.admin.RevokeSessions(ctx, support, victim.ID); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}
	if epoch, err := h.volatile.Epoch(ctx, victim.ID); err != nil || epoch.IsZero() {
		t.Fatalf("expected an epoch (got %v, err %v)", epoch, err)
	}
	if h.countAudit("user.revoke_sessions") != 1 {
		t.Fatalf("expected one revoke record, got %v", h.auditActions())
	}
}

func TestIssuePasswordReset_ReturnsARedeemableTokenAndAuditsWithoutIt(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	resp, err := h.admin.IssuePasswordReset(ctx, admin, victim.ID)
	if err != nil {
		t.Fatalf("IssuePasswordReset: %v", err)
	}
	if resp.ResetToken == "" || resp.ExpiresIn <= 0 {
		t.Fatalf("unexpected response: %+v", resp)
	}

	// The token must never reach the log.
	for _, r := range h.store.AuditEvents() {
		for _, v := range r.Metadata {
			if s, ok := v.(string); ok && s == resp.ResetToken {
				t.Fatal("the reset token was written to the audit log")
			}
		}
	}
	if h.countAudit("user.password_reset.issued") != 1 {
		t.Fatalf("expected one issue record, got %v", h.auditActions())
	}

	// The user, not the admin, completes it on the public plane.
	err = h.auth.RedeemPasswordReset(ctx, authmodel.PasswordResetRequest{
		ResetToken: resp.ResetToken, NewPassword: "an-entirely-different-password",
	}, store.RequestMeta{})
	if err != nil {
		t.Fatalf("RedeemPasswordReset: %v", err)
	}
}

func TestGetUser_ReportsLiveLockAndRevocationState(t *testing.T) {
	h := newHarness(t)
	_, support := h.admins()
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	view, err := h.admin.GetUser(ctx, victim.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if view.Locked == nil || *view.Locked {
		t.Fatalf("expected an explicit unlocked state, got %v", view.Locked)
	}
	if view.SessionsRevokedAt != nil {
		t.Fatalf("expected no revocation, got %v", view.SessionsRevokedAt)
	}

	if err := h.admin.RevokeSessions(ctx, support, victim.ID); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}
	if view, err = h.admin.GetUser(ctx, victim.ID); err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if view.SessionsRevokedAt == nil {
		t.Fatal("expected the revocation timestamp to be reported")
	}
}

func TestGetUser_UnknownIDIsNotFound(t *testing.T) {
	h := newHarness(t)
	if _, err := h.admin.GetUser(context.Background(), "no-such-user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// The admin view is a separate type from store.UserRecord precisely so the
// password hash has nowhere to go.
func TestUserView_CarriesNoPasswordHash(t *testing.T) {
	h := newHarness(t)
	u := h.user("victim@example.com", store.RoleUser)

	view, err := h.admin.GetUser(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	blob, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(blob), u.PasswordHash) || strings.Contains(string(blob), "password") {
		t.Fatalf("admin user view leaked credential material: %s", blob)
	}
}
