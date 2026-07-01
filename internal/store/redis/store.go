package redis

import (
	"fmt"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

func codeKey(code string) string      { return fmt.Sprintf("auth:code:%s", code) }
func blocklistKey(jti string) string  { return fmt.Sprintf("auth:blocklist:%s", jti) }
func attemptsKey(email string) string { return fmt.Sprintf("auth:lockout:attempts:%s", email) }
func lockedKey(email string) string   { return fmt.Sprintf("auth:lockout:locked:%s", email) }
func rateLimitKey(key string) string  { return fmt.Sprintf("auth:ratelimit:%s", key) }
