package redis

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

func codeKey(code string) string     { return fmt.Sprintf("auth:code:%s", code) }
func blocklistKey(jti string) string { return fmt.Sprintf("auth:blocklist:%s", jti) }
func rateLimitKey(key string) string { return fmt.Sprintf("auth:ratelimit:%s", key) }
func epochKey(userID string) string  { return fmt.Sprintf("auth:user:epoch:%s", userID) }

// Lockout keys are scoped so independent failure budgets (password today, OTP
// once MFA lands) cannot reset one another — a successful password login must
// not hand an attacker a fresh OTP-guessing budget.
func attemptsKey(scope, key string) string {
	return fmt.Sprintf("auth:lockout:%s:attempts:%s", scope, key)
}

func lockedKey(scope, key string) string {
	return fmt.Sprintf("auth:lockout:%s:locked:%s", scope, key)
}

// Reset tokens are keyed by their hash, never by the token itself, so a dump of
// Redis is not a set of usable account-takeover credentials.
func resetKey(hash []byte) string {
	return fmt.Sprintf("auth:pwreset:%s", hex.EncodeToString(hash))
}

// incrWithExpire atomically increments key and, only on its first increment,
// sets its TTL — all in one Lua script so a crash between INCR and EXPIRE
// can't leave a counter with no expiry (which would otherwise persist forever).
var incrWithExpireScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
	redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return count
`)

func (s *RedisStore) incrWithExpire(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	res, err := incrWithExpireScript.Run(ctx, s.client, []string{key}, int(ttl.Seconds())).Result()
	if err != nil {
		return 0, err
	}
	count, ok := res.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected script result type %T", res)
	}
	return count, nil
}
