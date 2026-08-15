package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	adminService "github.com/manjushsh/auth-service/internal/service/admin"
	authService "github.com/manjushsh/auth-service/internal/service/auth"
)

// Rate-limit defaults (requests per minute, per IP, per endpoint).
const (
	defaultRateLimitPerMin      = 10
	defaultRateLimitTokenPerMin = 30
	defaultAdminRateLimitPerMin = 60
)

// Admin listener defaults. Bound to loopback and disabled unless explicitly
// switched on: until admin accounts have a second factor, the network boundary
// is the primary control, and an environment that never opted in should have no
// admin plane to attack.
const (
	defaultAdminBindAddr = "127.0.0.1"
	defaultAdminPort     = "8081"
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

	admin adminConfig
}

type adminConfig struct {
	enabled         bool
	bindAddr        string
	port            string
	rateLimitPerMin int
	service         adminService.Config
}

func (a adminConfig) addr() string { return a.bindAddr + ":" + a.port }

func loadConfig() (config, error) {
	cfg := config{
		databaseURL: os.Getenv("DATABASE_URL"),
		jwtSecret:   os.Getenv("JWT_SECRET"),
		redisURL:    os.Getenv("REDIS_URL"),
		port:        os.Getenv("SERVER_PORT"),
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
	if cfg.insecureCookies, err = envBool("INSECURE_COOKIES", false); err != nil {
		return config{}, err
	}
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
	if cfg.auth.PasswordResetTTL, err = envDuration("ADMIN_PWRESET_TTL", authService.DefaultPasswordResetTTL); err != nil {
		return config{}, err
	}

	if cfg.admin, err = loadAdminConfig(); err != nil {
		return config{}, err
	}

	return cfg, nil
}

func loadAdminConfig() (adminConfig, error) {
	var (
		cfg adminConfig
		err error
	)
	if cfg.enabled, err = envBool("ADMIN_API_ENABLED", false); err != nil {
		return adminConfig{}, err
	}
	if cfg.bindAddr = os.Getenv("ADMIN_BIND_ADDR"); cfg.bindAddr == "" {
		cfg.bindAddr = defaultAdminBindAddr
	}
	if cfg.port = os.Getenv("ADMIN_PORT"); cfg.port == "" {
		cfg.port = defaultAdminPort
	}
	if cfg.rateLimitPerMin, err = envInt("ADMIN_RATE_LIMIT_PER_MIN", defaultAdminRateLimitPerMin); err != nil {
		return adminConfig{}, err
	}
	if cfg.service.TokenTTL, err = envDuration("ADMIN_TOKEN_TTL", adminService.DefaultTokenTTL); err != nil {
		return adminConfig{}, err
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

// envBool accepts only the forms strconv.ParseBool recognises, and treats
// anything else as a startup error.
//
// A bare `== "true"` comparison would read ADMIN_API_ENABLED=TRUE as *false*.
// That direction happens to fail safe for this flag, but the same typo in a
// future ADMIN_REQUIRE_MFA would disable a control silently, so the strictness
// is the point.
func envBool(name string, def bool) (bool, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: expected a boolean like \"true\" or \"false\", got %q", name, raw)
	}
	return v, nil
}
