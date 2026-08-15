package token

import (
	"context"
	"errors"
	"time"
)

// ErrTokenInactive means the token parsed cleanly but is no longer usable:
// revoked by jti, or superseded by a per-user session revocation.
var ErrTokenInactive = errors.New("token is not active")

// Blocklist reports per-jti revocation (logout).
type Blocklist interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// Epochs reports the per-user session-revocation watermark. A zero time means
// "never revoked".
type Epochs interface {
	Epoch(ctx context.Context, userID string) (time.Time, error)
}

// Verifier is the one place that decides whether a token is live. Both the user
// plane (Introspect) and the admin plane authenticate through it, so the
// `iat <= epoch` rule below is stated exactly once.
type Verifier struct {
	Manager   *Manager
	Blocklist Blocklist
	Epochs    Epochs
}

// Verify parses the token for the given audience and then applies both
// revocation checks. Every failure is an error — there is deliberately no
// "valid: false" return value, because a bool that callers can ignore is how
// authentication helpers end up failing open.
func (v *Verifier) Verify(ctx context.Context, raw, audience string) (*Claims, error) {
	claims, err := v.Manager.Parse(raw, audience)
	if err != nil {
		return nil, err
	}

	revoked, err := v.Blocklist.IsRevoked(ctx, claims.ID)
	if err != nil {
		return nil, err // fail closed: an unreachable blocklist is not an active token
	}
	if revoked {
		return nil, ErrTokenInactive
	}

	live, err := v.IssuedAfterEpoch(ctx, claims)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, ErrTokenInactive
	}
	return claims, nil
}

// IssuedAfterEpoch reports whether the token predates the subject's most recent
// session revocation.
//
// The comparison is `iat <= epoch`, not `<`: JWT `iat` has one-second
// granularity, so a token minted in the same second as a revocation would
// survive a strict comparison. Revoking one extra second of tokens is free; the
// alternative is a race that only shows up under load.
func (v *Verifier) IssuedAfterEpoch(ctx context.Context, claims *Claims) (bool, error) {
	epoch, err := v.Epochs.Epoch(ctx, claims.Subject)
	if err != nil {
		return false, err
	}
	if epoch.IsZero() {
		return true, nil
	}
	return claims.IssuedAt.Time.After(epoch), nil
}
