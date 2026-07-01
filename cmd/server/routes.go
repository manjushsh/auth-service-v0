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

func newHandler(deps *dependencies) http.Handler {
	mux := http.NewServeMux()

	cs := redisStore.NewRedisStore(deps.redis)
	authSvc := authService.New(authStore.NewPostgresStore(deps.db), cs, cs, cs, deps.jwtSecret)

	// Rate limiter: 10 requests per minute per IP per endpoint.
	rl := middleware.RateLimit(cs, 10, time.Minute)

	// API handlers
	authH := authHandler.New(authSvc)
	mux.Handle("POST /api/auth/register", rl(http.HandlerFunc(authH.Register)))
	// Login and code routes are same. Just kept for API so that won't get confused
	mux.Handle("POST /api/auth/login", rl(http.HandlerFunc(authH.GenerateCode)))
	mux.Handle("POST /api/auth/code", rl(http.HandlerFunc(authH.GenerateCode)))
	mux.HandleFunc("POST /api/auth/token", authH.ExchangeToken)
	mux.HandleFunc("POST /api/auth/logout", authH.Logout)
	mux.HandleFunc("POST /api/auth/introspect", authH.Introspect)

	// UI handlers
	uiH := uiHandler.New(authSvc)
	mux.HandleFunc("GET /login", uiH.LoginPage)
	mux.HandleFunc("POST /login", uiH.LoginSubmit)
	mux.HandleFunc("GET /register", uiH.RegisterPage)
	mux.HandleFunc("POST /register", uiH.RegisterSubmit)
	mux.Handle("/static/", http.FileServer(http.FS(uiHandler.StaticFS)))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})

	return middleware.Logger(mux)
}
