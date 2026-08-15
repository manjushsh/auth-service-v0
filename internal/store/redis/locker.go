package redis

import (
	"context"
	"time"
)

// Every method takes a scope so independent failure budgets can coexist under
// one implementation. Today only the password scope is in use; the MFA plan
// adds an OTP scope whose counter a successful password login must not clear.

func (s *RedisStore) IsLocked(ctx context.Context, scope, key string) (bool, error) {
	n, err := s.client.Exists(ctx, lockedKey(scope, key)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *RedisStore) RecordFailedAttempt(ctx context.Context, scope, key string, ttl time.Duration) (int, error) {
	count, err := s.incrWithExpire(ctx, attemptsKey(scope, key), ttl)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *RedisStore) LockAccount(ctx context.Context, scope, key string, ttl time.Duration) error {
	return s.client.Set(ctx, lockedKey(scope, key), "1", ttl).Err()
}

func (s *RedisStore) ClearFailedAttempts(ctx context.Context, scope, key string) error {
	return s.client.Del(ctx, attemptsKey(scope, key)).Err()
}

// Unlock clears both the counter and the lock flag.
//
// ClearFailedAttempts alone is not enough and never was: it removes the
// counter but leaves the lock flag, so a locked account stays locked until the
// flag's TTL expires. Before the admin API there was simply no way to release
// a lock early.
func (s *RedisStore) Unlock(ctx context.Context, scope, key string) error {
	return s.client.Del(ctx, attemptsKey(scope, key), lockedKey(scope, key)).Err()
}
