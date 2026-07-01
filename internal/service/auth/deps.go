package auth

import (
	"context"
	"time"
)

type codeStore interface {
	StoreCode(ctx context.Context, code, userID string, ttl time.Duration) error
	RedeemCode(ctx context.Context, code string) (string, error)
}

type blocklist interface {
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

type locker interface {
	IsLocked(ctx context.Context, email string) (bool, error)
	RecordFailedAttempt(ctx context.Context, email string) (int, error)
	LockAccount(ctx context.Context, email string, ttl time.Duration) error
	ClearFailedAttempts(ctx context.Context, email string) error
}
