package main

import (
	"fmt"
	"net/http"

	authHandler "github.com/manjushsh/auth-service/internal/handler/auth"
	"github.com/manjushsh/auth-service/internal/middleware"
	authService "github.com/manjushsh/auth-service/internal/service/auth"
	authStore "github.com/manjushsh/auth-service/internal/store/auth"
	codeStore "github.com/manjushsh/auth-service/internal/store/code"
)

func newHandler(deps *dependencies) http.Handler {
	mux := http.NewServeMux()

	cs := codeStore.NewRedisStore(deps.redis)
	authSvc := authService.New(authStore.NewPostgresStore(deps.db), cs, cs, deps.jwtSecret)
	authH := authHandler.New(authSvc)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/api/auth/register", authH.Register)
	mux.HandleFunc("/api/auth/code", authH.GenerateCode)
	mux.HandleFunc("/api/auth/token", authH.ExchangeToken)
	mux.HandleFunc("/api/auth/logout", authH.Logout)
	mux.HandleFunc("/api/auth/introspect", authH.Introspect)

	return middleware.Logger(mux)
}
