package main

import (
	"fmt"
	"net/http"

	basicHandler "github.com/manjushsh/auth-service/internal/handler/basic"
	"github.com/manjushsh/auth-service/internal/middleware"
	basicService "github.com/manjushsh/auth-service/internal/service/basic"
	basicStore "github.com/manjushsh/auth-service/internal/store/basic"
)

func newHandler(deps *dependencies) http.Handler {
	mux := http.NewServeMux()

	basicSvc := basicService.New(basicStore.NewPostgresStore(deps.db))
	basicH := basicHandler.New(basicSvc)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/api/basic/register", basicH.Register)
	mux.HandleFunc("/api/basic/login", basicH.Login)

	return middleware.Logger(mux)
}
