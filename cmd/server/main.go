package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/redis/go-redis/v9"

	"github.com/manjushsh/auth-service/db"
)

type dependencies struct {
	db    *sql.DB
	redis *redis.Client
	cfg   config
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Connect to the database
	database, err := db.Open(cfg.databaseURL)
	if err != nil {
		log.Fatalf("connect to db: %v", err)
	}
	defer database.Close()
	log.Println("connected to db")

	if err := db.RunMigrations(database); err != nil {
		log.Fatalf("run migrations: %v", err)
	}
	log.Println("migrations applied")

	// Connect to redis
	redisOpts, err := redis.ParseURL(cfg.redisURL)
	if err != nil {
		log.Fatalf("parse redis url: %v", err)
	}
	redisClient := redis.NewClient(redisOpts)
	pingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		log.Fatalf("connect to redis: %v", err)
	}
	cancelPing()
	defer redisClient.Close()
	log.Println("connected to redis")

	handler, err := newHandler(&dependencies{
		db:    database,
		redis: redisClient,
		cfg:   cfg,
	})
	if err != nil {
		log.Fatalf("build handler: %v", err)
	}

	srv := &http.Server{
		Addr:         ":" + cfg.port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("forced shutdown: %v", err)
	}
	log.Println("server stopped")
}
