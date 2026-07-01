package redis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrCodeNotFound = errors.New("code not found or expired")

func (s *RedisStore) StoreCode(ctx context.Context, code, userID string, ttl time.Duration) error {
	return s.client.Set(ctx, codeKey(code), userID, ttl).Err()
}

// RedeemCode atomically reads and deletes the code ensuring single use.
func (s *RedisStore) RedeemCode(ctx context.Context, code string) (string, error) {
	userID, err := s.client.GetDel(ctx, codeKey(code)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrCodeNotFound
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}
