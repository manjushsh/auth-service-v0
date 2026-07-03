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

const maxRequestBodyBytes = 1 << 20 // 1 MiB

func newHandler(deps *dependencies) (http.Handler, error) {
	mux := http.NewServeMux()

	cs := redisStore.NewRedisStore(deps.redis)
	authSvc, err := authService.New(authStore.NewPostgresStore(deps.db), cs, cs, cs, deps.jwtSecret)
	if err != nil {
		return nil, err
	}

	// Rate limiter: 10 requests per minute per IP per endpoint.
	rl := middleware.RateLimit(cs, 10, time.Minute)
	// Token exchange is guessable-secret sensitive; keep it tighter.
	rlToken := middleware.RateLimit(cs, 30, time.Minute)

	// API handlers
	authH := authHandler.New(authSvc)
	mux.Handle("POST /api/auth/register", rl(http.HandlerFunc(authH.Register)))
	// Login and code routes are same. Just kept for API so that won't get confused
	mux.Handle("POST /api/auth/login", rl(http.HandlerFunc(authH.GenerateCode)))
	mux.Handle("POST /api/auth/code", rl(http.HandlerFunc(authH.GenerateCode)))
	mux.Handle("POST /api/auth/token", rlToken(http.HandlerFunc(authH.ExchangeToken)))
	mux.Handle("POST /api/auth/logout", rlToken(http.HandlerFunc(authH.Logout)))
	mux.Handle("POST /api/auth/introspect", rlToken(http.HandlerFunc(authH.Introspect)))

	// UI handlers
	uiH := uiHandler.New(authSvc, deps.secureCookies)
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
