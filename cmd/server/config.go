package main

import (
	"fmt"
	"os"
)

type config struct {
	databaseURL     string
	jwtSecret       string
	redisURL        string
	port            string
	insecureCookies bool
}

func loadConfig() (config, error) {
	cfg := config{
		databaseURL:     os.Getenv("DATABASE_URL"),
		jwtSecret:       os.Getenv("JWT_SECRET"),
		redisURL:        os.Getenv("REDIS_URL"),
		port:            os.Getenv("SERVER_PORT"),
		insecureCookies: os.Getenv("INSECURE_COOKIES") == "true",
	}

	if cfg.databaseURL == "" {
		return config{}, fmt.Errorf("DATABASE_URL is not set")
	}
	if cfg.jwtSecret == "" {
		return config{}, fmt.Errorf("JWT_SECRET is not set")
	}
	if cfg.redisURL == "" {
		cfg.redisURL = "redis://localhost:6379"
	}
	if cfg.port == "" {
		cfg.port = "8080"
	}

	return cfg, nil
}
