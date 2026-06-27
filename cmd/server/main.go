package main

import (
	"fmt"
	"log"
	"net/http"

	basicHandler "github.com/manjushsh/auth-service/internal/handler/basic"
	basicService "github.com/manjushsh/auth-service/internal/service/basic"
)

func main() {
	mux := http.NewServeMux()

	// Basic auth handlers and services
	basicSvc := basicService.New()
	basicH := basicHandler.New(basicSvc)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/api/basic/register", basicH.Register)
	mux.HandleFunc("/api/basic/login", basicH.Login)

	addr := ":8080"
	log.Printf("starting server on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
