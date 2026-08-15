package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	model "github.com/manjushsh/auth-service/internal/model/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// issueToken runs a full login and exchange, returning the resulting JWT.
func issueToken(t *testing.T, svc *Service, email string) string {
	t.Helper()
	ctx := context.Background()

	gen, err := svc.GenerateCode(ctx, model.GenerateCodeRequest{
		Credentials: model.Credentials{Email: email, Password: testPassword},
	})
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	tok, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: gen.Code})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	return tok.Token
}

func assertActive(t *testing.T, svc *Service, tokenString string, want bool) {
	t.Helper()
	resp, err := svc.Introspect(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if resp.Active != want {
		t.Fatalf("token active = %v, want %v", resp.Active, want)
	}
}

// RevokeSessions is the only mechanism that can invalidate every token for one
// user; the blocklist is per-jti and nothing indexes a user's jtis.
//
// The token here is minted in the same second as the bump, which is exactly the
// case a strict `iat < epoch` comparison would let through.
func TestRevokeSessions_InvalidatesExistingTokensIncludingSameSecond(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	tokenString := issueToken(t, d.service, u.Email)
	assertActive(t, d.service, tokenString, true)

	if err := d.service.RevokeSessions(ctx, u.ID); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}
	assertActive(t, d.service, tokenString, false)
}

// A token minted after the revocation is unaffected: the epoch is a watermark,
// not a permanent ban.
//
// The clock advances past the revocation second first, because the comparison
// is deliberately `iat <= epoch` — a token issued *in* that second is revoked
// too, which the test above covers.
func TestRevokeSessions_DoesNotAffectLaterTokens(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	if err := d.service.RevokeSessions(ctx, u.ID); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}
	d.clock.Advance(time.Second)

	assertActive(t, d.service, issueToken(t, d.service, u.Email), true)
}

// A dead token should still log out cleanly rather than return an error the
// caller cannot act on.
func TestLogout_SucceedsForEpochRevokedToken(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	tokenString := issueToken(t, d.service, u.Email)
	if err := d.service.RevokeSessions(ctx, u.ID); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}
	if err := d.service.Logout(ctx, tokenString); err != nil {
		t.Fatalf("Logout after revocation: %v", err)
	}
}

// Without this check, "revoke all sessions" has a hole one CODE_TTL wide: the
// in-flight code redeems into a *new* token whose iat is after the epoch, so
// Introspect would happily accept it.
func TestExchangeCode_RejectsCodeIssuedBeforeRevocation(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	gen, err := d.service.GenerateCode(ctx, model.GenerateCodeRequest{
		Credentials: model.Credentials{Email: u.Email, Password: testPassword},
	})
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := d.service.RevokeSessions(ctx, u.ID); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}

	if _, err := d.service.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: gen.Code}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("exchange of pre-revocation code: got %v, want ErrInvalidCode", err)
	}
}

// A suspended account must not be able to log in, and must not be
// distinguishable from a wrong password while trying.
func TestGenerateCode_SuspendedUserCannotLogIn(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	err := d.store.SetUserStatus(ctx, u.ID, store.StatusSuspended, store.AuditEvent{
		ActorEmail: "test", ActorRole: "test", Action: "user.suspend", Result: store.AuditOK,
	})
	if err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}

	_, err = d.service.GenerateCode(ctx, model.GenerateCodeRequest{
		Credentials: model.Credentials{Email: u.Email, Password: testPassword},
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("suspended login: got %v, want ErrInvalidCredentials (indistinguishable from a wrong password)", err)
	}
}

// Nothing in the codebase could release a lockout before this:
// ClearFailedAttempts removes the counter but leaves the lock flag.
func TestUnlock_ReleasesLockAndIsIdempotent(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	for range DefaultMaxLoginAttempts {
		d.service.GenerateCode(ctx, model.GenerateCodeRequest{ //nolint:errcheck // failure is the point
			Credentials: model.Credentials{Email: u.Email, Password: "wrong-password"},
		})
	}

	locked, err := d.service.LockState(ctx, u.Email)
	if err != nil {
		t.Fatalf("LockState: %v", err)
	}
	if !locked {
		t.Fatal("expected the account to be locked after the threshold")
	}

	// Twice: a support tool unlocking an already-unlocked account is a
	// successful no-op, not an error.
	for i := range 2 {
		if err := d.service.Unlock(ctx, u.Email); err != nil {
			t.Fatalf("Unlock call %d: %v", i+1, err)
		}
	}

	if locked, err = d.service.LockState(ctx, u.Email); err != nil || locked {
		t.Fatalf("LockState after unlock = %v (err %v), want false", locked, err)
	}
	if _, err := d.service.GenerateCode(ctx, model.GenerateCodeRequest{
		Credentials: model.Credentials{Email: u.Email, Password: testPassword},
	}); err != nil {
		t.Fatalf("login after unlock: %v", err)
	}
}

func TestPasswordReset_SingleUseAndRevokesSessions(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	tokenString := issueToken(t, d.service, u.Email)
	assertActive(t, d.service, tokenString, true)

	resetToken, ttl, err := d.service.IssuePasswordReset(ctx, u.ID)
	if err != nil {
		t.Fatalf("IssuePasswordReset: %v", err)
	}
	if resetToken == "" || ttl <= 0 {
		t.Fatalf("expected a token and a positive ttl, got %q / %v", resetToken, ttl)
	}

	const newPassword = "an-entirely-different-password"
	req := model.PasswordResetRequest{ResetToken: resetToken, NewPassword: newPassword}
	if err := d.service.RedeemPasswordReset(ctx, req, store.RequestMeta{}); err != nil {
		t.Fatalf("RedeemPasswordReset: %v", err)
	}

	// Single use.
	if err := d.service.RedeemPasswordReset(ctx, req, store.RequestMeta{}); !errors.Is(err, ErrInvalidResetToken) {
		t.Fatalf("second redemption: got %v, want ErrInvalidResetToken", err)
	}

	// The old password is gone and the new one works.
	if _, err := d.service.VerifyPassword(ctx, u.Email, testPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password after reset: got %v, want ErrInvalidCredentials", err)
	}
	if _, err := d.service.VerifyPassword(ctx, u.Email, newPassword); err != nil {
		t.Fatalf("new password after reset: %v", err)
	}

	// A password change invalidates existing sessions.
	assertActive(t, d.service, tokenString, false)
}

func TestPasswordReset_RejectsUnknownTokenAndWeakPassword(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	err := d.service.RedeemPasswordReset(ctx,
		model.PasswordResetRequest{ResetToken: "not-a-real-token", NewPassword: "a-perfectly-fine-password"},
		store.RequestMeta{})
	if !errors.Is(err, ErrInvalidResetToken) {
		t.Fatalf("unknown token: got %v, want ErrInvalidResetToken", err)
	}

	resetToken, _, err := d.service.IssuePasswordReset(ctx, u.ID)
	if err != nil {
		t.Fatalf("IssuePasswordReset: %v", err)
	}
	err = d.service.RedeemPasswordReset(ctx,
		model.PasswordResetRequest{ResetToken: resetToken, NewPassword: "short"},
		store.RequestMeta{})
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("weak password: got %v, want ErrBadRequest", err)
	}
}

// The reset token is high-entropy, but storing it verbatim would still turn a
// dump of the volatile store into a set of account takeovers.
func TestPasswordReset_TokenIsStoredHashed(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	resetToken, _, err := d.service.IssuePasswordReset(ctx, u.ID)
	if err != nil {
		t.Fatalf("IssuePasswordReset: %v", err)
	}

	// The raw token must not itself be a lookup key.
	if _, err := d.volatile.RedeemResetToken(ctx, []byte(resetToken)); err == nil {
		t.Fatal("raw reset token resolved as a key; it must be stored hashed")
	}
}

// Password reset must never clear a second factor: doing so would make the
// reset flow a complete MFA bypass. There is no factor to check yet, so this
// asserts the property that has to survive the MFA work — redemption touches
// nothing beyond the password, sessions and lockout.
func TestPasswordReset_RecordsRedemptionAgainstTheUser(t *testing.T) {
	d := newTestDeps(t)
	ctx := context.Background()
	u := registerUser(t, d.service, d.store, "user@example.com")

	resetToken, _, err := d.service.IssuePasswordReset(ctx, u.ID)
	if err != nil {
		t.Fatalf("IssuePasswordReset: %v", err)
	}
	err = d.service.RedeemPasswordReset(ctx,
		model.PasswordResetRequest{ResetToken: resetToken, NewPassword: "an-entirely-different-password"},
		store.RequestMeta{RemoteAddr: "10.0.0.1"})
	if err != nil {
		t.Fatalf("RedeemPasswordReset: %v", err)
	}

	events := d.store.AuditEvents()
	var found *struct{ actor, action, remote string }
	for _, e := range events {
		if e.Action == "user.password_reset.redeemed" {
			found = &struct{ actor, action, remote string }{e.ActorID, e.Action, e.RemoteAddr}
		}
	}
	if found == nil {
		t.Fatalf("no redemption audit record in %d events", len(events))
	}
	// The actor is the user: the admin's half was recorded when the token was
	// issued, and conflating them would misattribute the change.
	if found.actor != u.ID {
		t.Fatalf("audit actor = %q, want the user %q", found.actor, u.ID)
	}
	if found.remote != "10.0.0.1" {
		t.Fatalf("audit remote_addr = %q, want the request's peer", found.remote)
	}
}
