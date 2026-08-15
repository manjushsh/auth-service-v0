package redis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrResetTokenNotFound covers "never existed", "expired" and "already used" —
// one error, because the caller must not distinguish them for the requester.
var ErrResetTokenNotFound = errors.New("reset token not found or expired")

func (s *RedisStore) StoreResetToken(ctx context.Context, hash []byte, userID string, ttl time.Duration) error {
	return s.client.Set(ctx, resetKey(hash), userID, ttl).Err()
}

// RedeemResetToken reads and deletes in one atomic command, so two concurrent
// redemptions cannot both win.
func (s *RedisStore) RedeemResetToken(ctx context.Context, hash []byte) (string, error) {
	userID, err := s.client.GetDel(ctx, resetKey(hash)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrResetTokenNotFound
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}
