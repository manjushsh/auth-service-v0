package admin

import (
	"context"

	model "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// Account recovery: restoring access to someone who has lost it.
//
// Separate from users.go, which owns the account *lifecycle* (what an account
// is: its role, its status, whether it exists at all). These differ by role —
// recovery is support-tier, lifecycle is admin-tier — by risk, and by who
// performs them day to day. Recovery is also where MFA reset lands, at which
// point it becomes the larger of the two.

// Unlock releases an account lockout. Idempotent: unlocking an unlocked account
// is a successful no-op, which is what a support tool wants.
func (s *Service) Unlock(ctx context.Context, c Caller, userID string, req model.UnlockRequest) error {
	u, err := s.mustUser(ctx, userID)
	if err != nil {
		return err
	}

	scopes, err := resolveScopes(req.Scope)
	if err != nil {
		return err
	}

	// Routed through accountOps rather than building Redis keys here: the key
	// layout is the auth service's business, and hand-built keys would silently
	// stop matching the moment the scheme changes.
	if err := s.accounts.Unlock(ctx, u.Email, scopes...); err != nil {
		return err
	}

	ev := c.event("user.unlock", userTarget(u))
	ev.Metadata = map[string]any{"scopes": scopes}
	return s.record(ctx, ev)
}

// RevokeSessions invalidates every token already issued to a user. Idempotent.
func (s *Service) RevokeSessions(ctx context.Context, c Caller, userID string) error {
	u, err := s.mustUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.accounts.RevokeSessions(ctx, u.ID); err != nil {
		return err
	}
	return s.record(ctx, c.event("user.revoke_sessions", userTarget(u)))
}

// IssuePasswordReset mints a single-use token for the user to redeem on the
// public plane. The admin never learns or sets the password.
//
// This is the one recovery action reserved for the admin role. Together with a
// future MFA reset it would be account takeover, so no single role holds both.
func (s *Service) IssuePasswordReset(ctx context.Context, c Caller, userID string) (model.PasswordResetResponse, error) {
	u, err := s.mustUser(ctx, userID)
	if err != nil {
		return model.PasswordResetResponse{}, err
	}

	raw, ttl, err := s.accounts.IssuePasswordReset(ctx, u.ID)
	if err != nil {
		return model.PasswordResetResponse{}, err
	}

	// The token itself is never recorded — only that one was issued.
	if err := s.record(ctx, c.event("user.password_reset.issued", userTarget(u))); err != nil {
		return model.PasswordResetResponse{}, err
	}

	return model.PasswordResetResponse{ResetToken: raw, ExpiresIn: int(ttl.Seconds())}, nil
}

// resolveScopes maps the request's scope parameter onto lockout scopes.
// Driving "all" off store.LockScopes means a scope added later is covered
// without another edit here.
func resolveScopes(scope string) ([]string, error) {
	if scope == "" || scope == "all" {
		return store.LockScopes, nil
	}
	for _, known := range store.LockScopes {
		if scope == known {
			return []string{scope}, nil
		}
	}
	return nil, ErrBadInput
}
