// Package memory is an in-process implementation of everything the service
// keeps in Redis: authorization codes, the JWT blocklist, lockout counters,
// session-revocation epochs, password-reset tokens and rate-limit windows.
//
// It mirrors internal/store/redis method for method, so a service wired to it
// exercises the same code paths production does. That makes it usable both as
// the test double for every service package — one implementation instead of a
// hand-rolled fake per package — and as a Redis-free mode for local runs.
package memory

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrCodeNotFound       = errors.New("code not found or expired")
	ErrResetTokenNotFound = errors.New("reset token not found or expired")
)

// entry is a value with an expiry, so TTL semantics match Redis rather than
// being silently ignored.
type entry struct {
	value     string
	count     int
	expiresAt time.Time
}

type Store struct {
	mu    sync.Mutex
	data  map[string]entry
	codes map[string]code
	now   func() time.Time
}

type code struct {
	userID      string
	redirectURI string
	issuedAt    time.Time
	expiresAt   time.Time
}

func New() *Store {
	return &Store{
		data:  map[string]entry{},
		codes: map[string]code{},
		now:   time.Now,
	}
}

// SetClock replaces the time source. Tests that need to cross a TTL boundary
// use it instead of sleeping.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// --- internal helpers (callers hold the lock) ---

func (s *Store) get(key string) (entry, bool) {
	e, ok := s.data[key]
	if !ok {
		return entry{}, false
	}
	if !e.expiresAt.IsZero() && !e.expiresAt.After(s.now()) {
		delete(s.data, key)
		return entry{}, false
	}
	return e, true
}

func (s *Store) set(key, value string, ttl time.Duration) {
	s.data[key] = entry{value: value, expiresAt: s.expiry(ttl)}
}

func (s *Store) expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return s.now().Add(ttl)
}

// --- authorization codes ---

func (s *Store) StoreCode(ctx context.Context, c, userID, redirectURI string, issuedAt time.Time, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Truncated to whole seconds because the Redis payload stores a Unix
	// timestamp; keeping the same granularity here means the epoch comparison
	// in ExchangeCode behaves identically against both stores.
	s.codes[c] = code{
		userID:      userID,
		redirectURI: redirectURI,
		issuedAt:    issuedAt.UTC().Truncate(time.Second),
		expiresAt:   s.expiry(ttl),
	}
	return nil
}

func (s *Store) RedeemCode(ctx context.Context, c string) (string, string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	found, ok := s.codes[c]
	if !ok {
		return "", "", time.Time{}, ErrCodeNotFound
	}
	delete(s.codes, c) // single use, whether or not it had expired
	if !found.expiresAt.IsZero() && !found.expiresAt.After(s.now()) {
		return "", "", time.Time{}, ErrCodeNotFound
	}
	return found.userID, found.redirectURI, found.issuedAt, nil
}

// --- blocklist ---

func (s *Store) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set(blocklistKey(jti), "1", ttl)
	return nil
}

func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.get(blocklistKey(jti))
	return ok, nil
}

// --- lockout ---

func (s *Store) IsLocked(ctx context.Context, scope, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.get(lockedKey(scope, key))
	return ok, nil
}

func (s *Store) RecordFailedAttempt(ctx context.Context, scope, key string, ttl time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := attemptsKey(scope, key)
	e, ok := s.get(k)
	if !ok {
		e = entry{expiresAt: s.expiry(ttl)}
	}
	e.count++
	s.data[k] = e
	return e.count, nil
}

func (s *Store) LockAccount(ctx context.Context, scope, key string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set(lockedKey(scope, key), "1", ttl)
	return nil
}

func (s *Store) ClearFailedAttempts(ctx context.Context, scope, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, attemptsKey(scope, key))
	return nil
}

func (s *Store) Unlock(ctx context.Context, scope, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, attemptsKey(scope, key))
	delete(s.data, lockedKey(scope, key))
	return nil
}

// --- session-revocation epoch ---

func (s *Store) BumpEpoch(ctx context.Context, userID string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Truncated to whole seconds exactly as the Redis implementation is, so the
	// `iat <= epoch` boundary is reachable here too rather than only in theory.
	s.set(epochKey(userID), formatUnix(s.now().UTC().Truncate(time.Second)), ttl)
	return nil
}

func (s *Store) Epoch(ctx context.Context, userID string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.get(epochKey(userID))
	if !ok {
		return time.Time{}, nil
	}
	return parseUnix(e.value)
}

// --- password reset ---

func (s *Store) StoreResetToken(ctx context.Context, hash []byte, userID string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set(resetKey(hash), userID, ttl)
	return nil
}

func (s *Store) RedeemResetToken(ctx context.Context, hash []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := resetKey(hash)
	e, ok := s.get(k)
	if !ok {
		return "", ErrResetTokenNotFound
	}
	delete(s.data, k) // single use
	return e.value, nil
}

// --- rate limiting ---

// Allow keeps its own key namespace rather than borrowing the lockout one, so
// an Unlock can never clear a rate-limit window (or vice versa) by accident.
func (s *Store) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := rateLimitKey(key)
	e, ok := s.get(k)
	if !ok {
		e = entry{expiresAt: s.expiry(window)}
	}
	e.count++
	s.data[k] = e
	return e.count <= limit, nil
}

// --- keys, mirroring internal/store/redis ---

func blocklistKey(jti string) string { return "blocklist:" + jti }
func epochKey(userID string) string  { return "epoch:" + userID }
func resetKey(hash []byte) string    { return "pwreset:" + string(hash) }
func rateLimitKey(key string) string { return "ratelimit:" + key }

func attemptsKey(scope, key string) string {
	return strings.Join([]string{"lockout", scope, "attempts", key}, ":")
}

func lockedKey(scope, key string) string {
	return strings.Join([]string{"lockout", scope, "locked", key}, ":")
}
