package code

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrCodeNotFound = errors.New("code not found or expired")

type Store interface {
	StoreCode(ctx context.Context, code, userID string, ttl time.Duration) error
	RedeemCode(ctx context.Context, code string) (string, error)
}

type Blocklist interface {
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

func codeKey(code string) string {
	return fmt.Sprintf("auth:code:%s", code)
}

func blocklistKey(jti string) string {
	return fmt.Sprintf("auth:blocklist:%s", jti)
}

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
