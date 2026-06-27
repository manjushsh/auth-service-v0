package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/joho/godotenv/autoload"

	"github.com/manjushsh/auth-service/db"
	basicHandler "github.com/manjushsh/auth-service/internal/handler/basic"
	"github.com/manjushsh/auth-service/internal/middleware"
	basicService "github.com/manjushsh/auth-service/internal/service/basic"
	basicStore "github.com/manjushsh/auth-service/internal/store/basic"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	database, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("connect to db: %v", err)
	}
	log.Println("connected to db")
	defer database.Close()

	if err := db.RunMigrations(database); err != nil {
		log.Fatalf("run migrations: %v", err)
	}
	log.Println("migrations applied")

	mux := http.NewServeMux()

	// Basic auth handlers and services
	// basicSvc := basicService.New(basicStore.NewMemoryStore())
	basicSvc := basicService.New(basicStore.NewPostgresStore(database))
	basicH := basicHandler.New(basicSvc)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/api/basic/register", basicH.Register)
	mux.HandleFunc("/api/basic/login", basicH.Login)

	addr := ":8080"
	log.Printf("starting server on %s", addr)
	if err := http.ListenAndServe(addr, middleware.Logger(mux)); err != nil {
		log.Fatal(err)
	}
}
