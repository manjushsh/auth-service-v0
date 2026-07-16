package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrCodeNotFound = errors.New("code not found or expired")

// codePayload is what a one-time code redeems to. RedirectURI is kept with
// the code so the exchange can verify the caller knows the URI the code was
// issued for.
type codePayload struct {
	UserID      string `json:"user_id"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

func (s *RedisStore) StoreCode(ctx context.Context, code, userID, redirectURI string, ttl time.Duration) error {
	payload, err := json.Marshal(codePayload{UserID: userID, RedirectURI: redirectURI})
	if err != nil {
		return fmt.Errorf("marshal code payload: %w", err)
	}
	return s.client.Set(ctx, codeKey(code), payload, ttl).Err()
}

// RedeemCode atomically reads and deletes the code ensuring single use.
func (s *RedisStore) RedeemCode(ctx context.Context, code string) (userID, redirectURI string, err error) {
	raw, err := s.client.GetDel(ctx, codeKey(code)).Result()
	if errors.Is(err, redis.Nil) {
		return "", "", ErrCodeNotFound
	}
	if err != nil {
		return "", "", err
	}
	var p codePayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return "", "", fmt.Errorf("unmarshal code payload: %w", err)
	}
	return p.UserID, p.RedirectURI, nil
}
