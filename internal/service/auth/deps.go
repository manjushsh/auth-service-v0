package auth

import (
	"context"
	"time"

	store "github.com/manjushsh/auth-service/internal/store/auth"
)

type codeStore interface {
	StoreCode(ctx context.Context, code, userID, redirectURI string, issuedAt time.Time, ttl time.Duration) error
	// issuedAt is returned so the exchange can reject a code that predates a
	// session revocation; the minted token's own iat cannot reveal that.
	RedeemCode(ctx context.Context, code string) (userID, redirectURI string, issuedAt time.Time, err error)
}

type blocklist interface {
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// locker is scoped so that independent failure budgets can share one
// implementation. Callers pass store.LockScopePassword today.
type locker interface {
	IsLocked(ctx context.Context, scope, key string) (bool, error)
	RecordFailedAttempt(ctx context.Context, scope, key string, ttl time.Duration) (int, error)
	LockAccount(ctx context.Context, scope, key string, ttl time.Duration) error
	ClearFailedAttempts(ctx context.Context, scope, key string) error
	Unlock(ctx context.Context, scope, key string) error
}

// epochStore holds the per-user session-revocation watermark.
type epochStore interface {
	Epoch(ctx context.Context, userID string) (time.Time, error)
	BumpEpoch(ctx context.Context, userID string, ttl time.Duration) error
}

// resetStore holds single-use password-reset tokens, keyed by hash.
type resetStore interface {
	StoreResetToken(ctx context.Context, hash []byte, userID string, ttl time.Duration) error
	RedeemResetToken(ctx context.Context, hash []byte) (string, error)
}

// auditStore records security-relevant events durably. The public plane writes
// only the events a user causes about their own account (password reset
// redemption); privileged actions come from the admin plane.
type auditStore interface {
	InsertAudit(ctx context.Context, ev store.AuditEvent) error
}
