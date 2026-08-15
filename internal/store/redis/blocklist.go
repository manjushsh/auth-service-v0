package redis

import (
	"context"
	"time"
)

func (s *RedisStore) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	return s.client.Set(ctx, blocklistKey(jti), "1", ttl).Err()
}

func (s *RedisStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	n, err := s.client.Exists(ctx, blocklistKey(jti)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
