package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/redis/go-redis/v9"

	"github.com/manjushsh/auth-service/db"
)

const (
	readTimeout     = 10 * time.Second
	writeTimeout    = 10 * time.Second
	idleTimeout     = 60 * time.Second
	shutdownTimeout = 15 * time.Second
)

type dependencies struct {
	db    *sql.DB
	redis *redis.Client
	cfg   config
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

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
	slog.Info("connected to db")

	if err := db.RunMigrations(database); err != nil {
		log.Fatalf("run migrations: %v", err)
	}
	slog.Info("migrations applied")

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
	slog.Info("connected to redis")

	deps := &dependencies{db: database, redis: redisClient, cfg: cfg}
	svcs, err := newServices(deps)
	if err != nil {
		log.Fatalf("build services: %v", err)
	}

	// Bind every listener before serving any of them.
	//
	// ListenAndServe would bind lazily inside the goroutine, so a port conflict
	// on the *admin* listener would surface as a log.Fatal after the public
	// plane had already started accepting traffic — turning a configuration
	// typo into an auth outage. Binding up front makes it a clean startup
	// failure instead.
	listeners := []listener{{name: "public", addr: ":" + cfg.port, handler: newHandler(deps, svcs)}}

	// The admin plane is off unless explicitly enabled, and binds to loopback
	// unless explicitly told otherwise.
	if cfg.admin.enabled {
		listeners = append(listeners, listener{
			name: "admin", addr: cfg.admin.addr(), handler: newAdminHandler(deps, svcs),
		})
		if cfg.admin.bindAddr != defaultAdminBindAddr {
			slog.Warn("admin api is not bound to loopback; ensure the network in front of it is trusted",
				"bind_addr", cfg.admin.bindAddr)
		}
	} else {
		slog.Info("admin api disabled", "hint", "set ADMIN_API_ENABLED=true to enable")
	}

	var servers []*http.Server
	for _, l := range listeners {
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			log.Fatalf("bind %s listener on %s: %v", l.name, l.addr, err)
		}
		defer ln.Close()

		srv := newServer(l.addr, l.handler)
		servers = append(servers, srv)
		slog.Info("serving", "listener", l.name, "addr", ln.Addr().String())

		go func(srv *http.Server, ln net.Listener) {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("server %s error: %v", srv.Addr, err)
			}
		}(srv, ln)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("shutdown signal received")

	// Both listeners share one deadline: in-flight requests on either get the
	// same grace period.
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Shut every listener down before reporting a failure, so one stuck server
	// does not leave the other accepting connections.
	var shutdownErr error
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("forced shutdown", "addr", srv.Addr, "error", err)
			shutdownErr = err
		}
	}
	if shutdownErr != nil {
		log.Fatalf("shutdown incomplete: %v", shutdownErr)
	}
	slog.Info("servers stopped")
}

// listener is a bound-but-not-yet-serving endpoint.
type listener struct {
	name    string
	addr    string
	handler http.Handler
}

func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
}
