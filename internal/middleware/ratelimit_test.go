package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeLimiter struct {
	allow bool
	err   error
	calls int
}

func (f *fakeLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	f.calls++
	return f.allow, f.err
}

func TestRateLimit_AllowsUnderLimit(t *testing.T) {
	rl := &fakeLimiter{allow: true}
	mw := RateLimit(rl, 10, time.Minute)
	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlerCalled = true })

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if !handlerCalled {
		t.Fatal("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRateLimit_BlocksOverLimit(t *testing.T) {
	rl := &fakeLimiter{allow: false}
	mw := RateLimit(rl, 10, time.Minute)
	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlerCalled = true })

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if handlerCalled {
		t.Fatal("expected next handler NOT to be called")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header to be set")
	}
}

func TestRateLimit_FailsOpenOnLimiterError(t *testing.T) {
	rl := &fakeLimiter{err: errors.New("redis down")}
	mw := RateLimit(rl, 10, time.Minute)
	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlerCalled = true })

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if !handlerCalled {
		t.Fatal("expected fail-open to allow the request through")
	}
}
