package redis

import (
	"context"
	"time"
)

func (s *RedisStore) IsLocked(ctx context.Context, email string) (bool, error) {
	n, err := s.client.Exists(ctx, lockedKey(email)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *RedisStore) RecordFailedAttempt(ctx context.Context, email string, ttl time.Duration) (int, error) {
	count, err := s.incrWithExpire(ctx, attemptsKey(email), ttl)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *RedisStore) LockAccount(ctx context.Context, email string, ttl time.Duration) error {
	return s.client.Set(ctx, lockedKey(email), "1", ttl).Err()
}

func (s *RedisStore) ClearFailedAttempts(ctx context.Context, email string) error {
	return s.client.Del(ctx, attemptsKey(email)).Err()
}
