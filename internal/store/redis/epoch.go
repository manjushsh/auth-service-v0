package redis

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// The per-user epoch is the session-invalidation watermark: every token issued
// at or before it is treated as dead. It is the only way to express "revoke
// everything for user X" — the blocklist is per-jti and nothing indexes which
// jtis belong to a user.
//
// A missing key means "never revoked", so this is backward compatible with
// tokens issued before the feature existed. The key carries a TTL of at least
// one token lifetime: once every token predating the bump has expired on its
// own, the watermark carries no information, and Redis keeps its invariant that
// nothing in it needs to survive a flush.

func (s *RedisStore) BumpEpoch(ctx context.Context, userID string, ttl time.Duration) error {
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	return s.client.Set(ctx, epochKey(userID), now, ttl).Err()
}

func (s *RedisStore) Epoch(ctx context.Context, userID string) (time.Time, error) {
	raw, err := s.client.Get(ctx, epochKey(userID)).Result()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(secs, 0).UTC(), nil
}
