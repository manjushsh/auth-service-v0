package main

import (
	"context"

	"net/http"
	"time"

	adminHandler "github.com/manjushsh/auth-service/internal/handler/admin"
	authHandler "github.com/manjushsh/auth-service/internal/handler/auth"
	uiHandler "github.com/manjushsh/auth-service/internal/handler/ui"
	"github.com/manjushsh/auth-service/internal/httpx"
	"github.com/manjushsh/auth-service/internal/middleware"
	"github.com/manjushsh/auth-service/internal/secret"
	adminService "github.com/manjushsh/auth-service/internal/service/admin"
	authService "github.com/manjushsh/auth-service/internal/service/auth"
	authStore "github.com/manjushsh/auth-service/internal/store/auth"
	redisStore "github.com/manjushsh/auth-service/internal/store/redis"
	"github.com/manjushsh/auth-service/internal/token"
)

// https://go101.org/article/operators.html
const maxRequestBodyBytes = 1 << 20 // Bit Shift 1 by 20 bits to get 1 MiB.

// adminMaxRequestBodyBytes is much tighter than the public cap: every admin
// request body is a handful of short JSON fields.
const adminMaxRequestBodyBytes = 64 << 10

// services holds the built service layer, shared by both listeners.
type services struct {
	auth  *authService.Service
	admin *adminService.Service
	redis *redisStore.RedisStore
}

func newServices(deps *dependencies) (*services, error) {
	rs := redisStore.NewRedisStore(deps.redis)
	ps := authStore.NewPostgresStore(deps.db)

	// One token manager, one signing secret, two audiences. Minting admin
	// tokens through the same manager is what keeps the audience split
	// structural rather than a convention each caller has to remember.
	tokens, err := token.NewManager([]byte(deps.cfg.jwtSecret), secret.NewToken, time.Now)
	if err != nil {
		return nil, err
	}
	verifier := &token.Verifier{Manager: tokens, Blocklist: rs, Epochs: rs}

	authSvc, err := authService.New(authService.Deps{
		Store:     ps,
		Codes:     rs,
		Blocklist: rs,
		Locker:    rs,
		Epochs:    rs,
		Resets:    rs,
		Audit:     ps,
		Tokens:    tokens,
	}, deps.cfg.auth)
	if err != nil {
		return nil, err
	}

	adminSvc, err := adminService.New(adminService.Deps{
		Store:     ps,
		Accounts:  authSvc,
		Blocklist: rs,
		Tokens:    tokens,
		Verifier:  verifier,
		HealthChecks: map[string]func(context.Context) error{
			"postgres": deps.db.PingContext,
			"redis":    func(ctx context.Context) error { return deps.redis.Ping(ctx).Err() },
		},
	}, deps.cfg.admin.service)
	if err != nil {
		return nil, err
	}

	return &services{auth: authSvc, admin: adminSvc, redis: rs}, nil
}

// newHandler builds the public listener: the JSON API and the hosted UI.
//
// The routes themselves live with their handlers; this only supplies the
// limiter for each tier and mounts them.
func newHandler(deps *dependencies, svcs *services) http.Handler {
	mux := http.NewServeMux()

	// Rate limiters: requests per minute per IP per endpoint. Credential routes
	// get the tighter limit; routes that take an already-issued token allow more.
	limiters := httpx.Limiters{
		httpx.TierCredential: middleware.RateLimit(svcs.redis, deps.cfg.rateLimitPerMin, time.Minute),
		httpx.TierToken:      middleware.RateLimit(svcs.redis, deps.cfg.rateLimitTokenPerMin, time.Minute),
	}

	httpx.Mount(mux, authHandler.New(svcs.auth).Routes(), limiters)
	httpx.Mount(mux, uiHandler.New(svcs.auth, !deps.cfg.insecureCookies).Routes(), limiters)

	return chain(mux, maxRequestBodyBytes)
}

// newAdminHandler builds the admin listener. It is a separate handler chain,
// not a path prefix on the public mux: an authorization bug here must not be
// instantly internet-reachable, and the middleware differs (no CSRF cookies,
// no static files, a fail-closed limiter, a tighter body cap).
func newAdminHandler(deps *dependencies, svcs *services) http.Handler {
	mux := http.NewServeMux()

	rl := middleware.RateLimitWith(svcs.redis, middleware.RateLimitOptions{
		Limit:  deps.cfg.admin.rateLimitPerMin,
		Window: time.Minute,
		// Proxy headers are ignored: on a loopback-bound listener behind a
		// bastion they are attacker-supplied, so keying the limit on them would
		// make it trivially bypassable.
		TrustProxyHeaders: false,
		// And it fails closed. The public plane's fail-open is a deliberate
		// availability trade; this plane is low-traffic and internal, so a
		// limiter outage must not silently remove the protection.
		FailOpen: false,
	})

	adminHandler.Mount(mux, adminHandler.New(svcs.admin), rl)

	return chain(mux, adminMaxRequestBodyBytes)
}

// chain applies the middleware every listener shares, outermost last.
func chain(h http.Handler, maxBody int64) http.Handler {
	handler := middleware.SecurityHeaders(h)
	handler = middleware.MaxBytes(maxBody)(handler)
	return middleware.Logger(handler)
}
