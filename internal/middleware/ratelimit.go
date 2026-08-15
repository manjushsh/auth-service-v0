package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/manjushsh/auth-service/internal/httpx"
)

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

// RateLimitOptions configures one limiter tier.
type RateLimitOptions struct {
	Limit  int
	Window time.Duration

	// TrustProxyHeaders keys the limit on X-Forwarded-For / X-Real-IP when
	// present. Convenient behind a proxy, spoofable without one.
	TrustProxyHeaders bool

	// FailOpen serves the request when the limiter itself errors. The public
	// plane sets this: availability is prioritized over the limit. The admin
	// plane does not — it is low-traffic and internal, so a limiter outage
	// there should not silently remove the protection.
	FailOpen bool
}

// RateLimit is the public-plane tier: proxy headers trusted, fails open.
func RateLimit(rl RateLimiter, limit int, window time.Duration) func(http.Handler) http.Handler {
	return RateLimitWith(rl, RateLimitOptions{
		Limit:             limit,
		Window:            window,
		TrustProxyHeaders: true,
		FailOpen:          true,
	})
}

// RateLimitWith returns middleware allowing at most opts.Limit requests per
// window per client, per route.
func RateLimitWith(rl RateLimiter, opts RateLimitOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := httpx.RemoteIP(r)
			if opts.TrustProxyHeaders {
				ip = httpx.ClientIP(r)
			}
			key := fmt.Sprintf("%s:%s", r.URL.Path, ip)

			allowed, err := rl.Allow(r.Context(), key, opts.Limit, opts.Window)
			if err != nil {
				slog.Error("ratelimit", "key", key, "fail_open", opts.FailOpen, "error", err)
				if !opts.FailOpen {
					http.Error(w, "rate limiter unavailable", http.StatusServiceUnavailable)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(opts.Window.Seconds())))
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
