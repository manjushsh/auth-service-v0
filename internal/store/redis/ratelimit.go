package redis

import (
	"context"
	"time"
)

// Allow uses a fixed window counter. Returns false when the limit is exceeded.
func (s *RedisStore) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	k := rateLimitKey(key)
	count, err := s.client.Incr(ctx, k).Result()
	if err != nil {
		return false, err
	}
	if count == 1 {
		s.client.Expire(ctx, k, window)
	}
	return count <= int64(limit), nil
}
