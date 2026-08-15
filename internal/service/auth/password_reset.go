package auth

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"

	model "github.com/manjushsh/auth-service/internal/model/auth"
	"github.com/manjushsh/auth-service/internal/secret"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// IssuePasswordReset mints a single-use reset token for a user.
//
// It deliberately does not set a password. An admin who sets a temporary
// password knows a credential that works, with no expiry and no forced change;
// a short-lived token that only the user can spend avoids that. The caller
// (the admin plane) delivers the token out of band after verifying identity.
//
// Only the token's hash is stored, so a dump of Redis is not a set of usable
// account takeovers.
func (s *Service) IssuePasswordReset(ctx context.Context, userID string) (string, time.Duration, error) {
	raw, err := secret.NewToken()
	if err != nil {
		return "", 0, err
	}
	if err := s.resets.StoreResetToken(ctx, secret.Hash(raw), userID, s.cfg.PasswordResetTTL); err != nil {
		return "", 0, err
	}
	return raw, s.cfg.PasswordResetTTL, nil
}

// RedeemPasswordReset exchanges a reset token for a new password. It runs on
// the public plane, unauthenticated — the token is the credential.
//
// The same endpoint would serve a future email-based flow unchanged; only the
// delivery of the token differs.
func (s *Service) RedeemPasswordReset(ctx context.Context, req model.PasswordResetRequest, meta store.RequestMeta) error {
	if req.ResetToken == "" {
		return ErrInvalidResetToken
	}
	if err := validatePassword(req.NewPassword); err != nil {
		return err
	}

	// GETDEL: atomic, so two concurrent redemptions cannot both win.
	userID, err := s.resets.RedeemResetToken(ctx, secret.Hash(req.ResetToken))
	if err != nil {
		return ErrInvalidResetToken
	}

	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		// The token outlived its user. Nothing to reset.
		return ErrInvalidResetToken
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), s.cfg.BcryptCost)
	if err != nil {
		return err
	}

	// The audit actor is the user: they performed this, not an admin. The
	// admin's half was recorded separately when the token was issued.
	ev := store.AuditEvent{
		ActorID:     u.ID,
		ActorEmail:  u.Email,
		ActorRole:   u.Role,
		Action:      "user.password_reset.redeemed",
		TargetType:  store.TargetUser,
		TargetID:    u.ID,
		TargetLabel: u.Email,
		Result:      store.AuditOK,
		RequestMeta: meta,
	}
	if err := s.store.SetUserPassword(ctx, u.ID, string(hashed), ev); err != nil {
		return err
	}

	// A password change invalidates existing sessions. Note that it must *not*
	// clear any second factor: doing so would turn reset into a complete MFA
	// bypass, and the second factor would protect nothing.
	if err := s.RevokeSessions(ctx, u.ID); err != nil {
		return err
	}
	if err := s.Unlock(ctx, u.Email, store.LockScopePassword); err != nil {
		// Best effort: the password is already changed, and the lockout will
		// expire on its own. Refusing here would leave the caller unable to act.
		slog.Warn("clear lockout after password reset", "user_id", u.ID, "error", err)
	}
	return nil
}
