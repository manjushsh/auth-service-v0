package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	authService "github.com/manjushsh/auth-service/internal/service/auth"
)

// Rate-limit defaults (requests per minute, per IP, per endpoint).
const (
	defaultRateLimitPerMin      = 10
	defaultRateLimitTokenPerMin = 30
)

type config struct {
	databaseURL     string
	jwtSecret       string
	redisURL        string
	port            string
	insecureCookies bool

	// Tuning knobs, all optional with sane defaults.
	rateLimitPerMin      int
	rateLimitTokenPerMin int
	auth                 authService.Config
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

	var err error
	if cfg.rateLimitPerMin, err = envInt("RATE_LIMIT_PER_MIN", defaultRateLimitPerMin); err != nil {
		return config{}, err
	}
	if cfg.rateLimitTokenPerMin, err = envInt("RATE_LIMIT_TOKEN_PER_MIN", defaultRateLimitTokenPerMin); err != nil {
		return config{}, err
	}
	if cfg.auth.CodeTTL, err = envDuration("CODE_TTL", authService.DefaultCodeTTL); err != nil {
		return config{}, err
	}
	if cfg.auth.TokenTTL, err = envDuration("TOKEN_TTL", authService.DefaultTokenTTL); err != nil {
		return config{}, err
	}
	if cfg.auth.MaxLoginAttempts, err = envInt("MAX_LOGIN_ATTEMPTS", authService.DefaultMaxLoginAttempts); err != nil {
		return config{}, err
	}
	if cfg.auth.LockoutDuration, err = envDuration("LOCKOUT_DURATION", authService.DefaultLockoutDuration); err != nil {
		return config{}, err
	}
	if cfg.auth.BcryptCost, err = envInt("BCRYPT_COST", authService.DefaultBcryptCost); err != nil {
		return config{}, err
	}

	return cfg, nil
}

// envInt reads a positive integer from the environment, or returns def when
// unset. A malformed or non-positive value is a startup error rather than a
// silent fallback so typos don't quietly weaken security settings.
func envInt(name string, def int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: expected a positive integer, got %q", name, raw)
	}
	return n, nil
}

// envDuration reads a positive Go duration (e.g. "90s", "15m", "1h") from the
// environment, or returns def when unset.
func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: expected a positive duration like \"90s\" or \"15m\", got %q", name, raw)
	}
	return d, nil
}
