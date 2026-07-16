package main

import (
	"fmt"
	"net/http"
	"time"

	authHandler "github.com/manjushsh/auth-service/internal/handler/auth"
	uiHandler "github.com/manjushsh/auth-service/internal/handler/ui"
	"github.com/manjushsh/auth-service/internal/middleware"
	authService "github.com/manjushsh/auth-service/internal/service/auth"
	authStore "github.com/manjushsh/auth-service/internal/store/auth"
	redisStore "github.com/manjushsh/auth-service/internal/store/redis"
)

// https://go101.org/article/operators.html
const maxRequestBodyBytes = 1 << 20 // Bit Shift 1 by 20 bits to get 1 MiB.

func newHandler(deps *dependencies) (http.Handler, error) {
	mux := http.NewServeMux()

	rs := redisStore.NewRedisStore(deps.redis)
	authSvc, err := authService.New(authStore.NewPostgresStore(deps.db), rs, rs, rs, []byte(deps.cfg.jwtSecret), deps.cfg.auth)
	if err != nil {
		return nil, err
	}

	// Rate limiters: requests per minute per IP per endpoint. The credential
	// routes get the tighter limit; token exchange allows more.
	rl := middleware.RateLimit(rs, deps.cfg.rateLimitPerMin, time.Minute)
	rlToken := middleware.RateLimit(rs, deps.cfg.rateLimitTokenPerMin, time.Minute)

	// API handlers
	authH := authHandler.New(authSvc)
	mux.Handle("POST /api/auth/register", rl(http.HandlerFunc(authH.Register)))
	// Login and code routes are same. Just kept for API so that won't get confused later
	mux.Handle("POST /api/auth/login", rl(http.HandlerFunc(authH.GenerateCode)))
	mux.Handle("POST /api/auth/code", rl(http.HandlerFunc(authH.GenerateCode)))
	mux.Handle("POST /api/auth/token", rlToken(http.HandlerFunc(authH.ExchangeToken)))
	mux.Handle("POST /api/auth/logout", rlToken(http.HandlerFunc(authH.Logout)))
	mux.Handle("POST /api/auth/introspect", rlToken(http.HandlerFunc(authH.Introspect)))

	// UI handlers
	uiH := uiHandler.New(authSvc, !deps.cfg.insecureCookies)
	mux.HandleFunc("GET /login", uiH.LoginPage)
	mux.Handle("POST /login", rl(http.HandlerFunc(uiH.LoginSubmit)))
	mux.HandleFunc("GET /register", uiH.RegisterPage)
	mux.Handle("POST /register", rl(http.HandlerFunc(uiH.RegisterSubmit)))
	mux.Handle("/static/", http.FileServer(http.FS(uiHandler.StaticFS)))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})

	handler := middleware.SecurityHeaders(mux)
	handler = middleware.MaxBytes(maxRequestBodyBytes)(handler)
	handler = middleware.Logger(handler)
	return handler, nil
}
