package redis

import (
	"context"
	"time"
)

// Allow uses a fixed window counter. Returns false when the limit is exceeded.
func (s *RedisStore) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := s.incrWithExpire(ctx, rateLimitKey(key), window)
	if err != nil {
		return false, err
	}
	return count <= int64(limit), nil
}
