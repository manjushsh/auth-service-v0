// Package admin implements the authenticated administrative plane: client
// management, user lookup, account recovery operations and the audit log.
//
// Two properties shape everything here:
//
//   - Admin tokens carry their own JWT audience. User tokens are handed to
//     third-party relying applications by design, so an admin's ordinary token
//     must never open this plane (docs/ADMIN_API_PLAN.md §3.2).
//   - No privileged mutation happens without an audit record. Postgres changes
//     carry their audit row in the same transaction; the two Redis-backed
//     operations write theirs immediately after, and a failure to record fails
//     the request.
package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	store "github.com/manjushsh/auth-service/internal/store/auth"
	"github.com/manjushsh/auth-service/internal/token"
)

// Defaults for Config; a zero Config is a valid production configuration.
const (
	// DefaultTokenTTL is deliberately much shorter than a user token's. Until
	// admin accounts have a second factor, a short lifetime is one of the few
	// compensating controls available.
	DefaultTokenTTL = 15 * time.Minute
)

type Config struct {
	TokenTTL time.Duration
}

func (c Config) withDefaults() Config {
	if c.TokenTTL <= 0 {
		c.TokenTTL = DefaultTokenTTL
	}
	return c
}

var (
	// ErrUnauthenticated means "no usable credential" — missing, malformed,
	// expired, revoked, wrong audience, or an account that may not use this
	// plane at all.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrForbidden means authenticated but insufficient role.
	ErrForbidden = errors.New("forbidden")
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflict")
	ErrBadInput  = errors.New("invalid request")
	// ErrConfirmationMismatch guards irreversible operations: the request body
	// must echo the target's own identifier.
	ErrConfirmationMismatch = errors.New("confirmation does not match target")
	// ErrLastAdmin surfaces the store's last-admin guard.
	ErrLastAdmin = store.ErrLastAdmin
	// ErrSelfTarget blocks self-demotion, self-suspension and self-deletion.
	ErrSelfTarget = errors.New("cannot perform this action on your own account")
)

// Caller is the authenticated actor plus the provenance of their request.
// Handlers build one via Authenticate and pass it to every operation, which is
// what makes every audit row attributable.
type Caller struct {
	UserID string
	Email  string
	Role   string
	Meta   store.RequestMeta
}

type Deps struct {
	Store        adminStore
	Accounts     accountOps
	Blocklist    blocklist
	Tokens       *token.Manager
	Verifier     *token.Verifier
	HealthChecks map[string]func(context.Context) error
}

type Service struct {
	store     adminStore
	accounts  accountOps
	blocklist blocklist
	tokens    *token.Manager
	verifier  *token.Verifier
	health    map[string]func(context.Context) error
	cfg       Config
}

func New(d Deps, cfg Config) (*Service, error) {
	for name, dep := range map[string]any{
		"Store": d.Store, "Accounts": d.Accounts, "Blocklist": d.Blocklist,
	} {
		if dep == nil {
			return nil, fmt.Errorf("admin service: %s dependency is required", name)
		}
	}
	if d.Tokens == nil || d.Verifier == nil {
		return nil, errors.New("admin service: Tokens and Verifier dependencies are required")
	}
	// An empty check set would make /admin/health report "ok" unconditionally —
	// a readiness probe that cannot fail is worse than none, because something
	// downstream will trust it.
	if len(d.HealthChecks) == 0 {
		return nil, errors.New("admin service: at least one health check is required")
	}

	return &Service{
		store:     d.Store,
		accounts:  d.Accounts,
		blocklist: d.Blocklist,
		tokens:    d.Tokens,
		verifier:  d.Verifier,
		health:    d.HealthChecks,
		cfg:       cfg.withDefaults(),
	}, nil
}

// --- audit plumbing ---

// target is the object an action was performed on. Grouping the three fields
// stops them being passed positionally and transposed.
type target struct {
	Type  string
	ID    string
	Label string
}

func userTarget(u store.UserRecord) target {
	return target{Type: store.TargetUser, ID: u.ID, Label: u.Email}
}

func clientTarget(c store.Client) target {
	return target{Type: store.TargetClient, ID: c.ID, Label: c.RedirectURI}
}

// event builds a successful-action record. Callers override Result for denials.
func (c Caller) event(action string, t target) store.AuditEvent {
	return store.AuditEvent{
		ActorID:     c.UserID,
		ActorEmail:  c.Email,
		ActorRole:   c.Role,
		Action:      action,
		TargetType:  t.Type,
		TargetID:    t.ID,
		TargetLabel: t.Label,
		Result:      store.AuditOK,
		RequestMeta: c.Meta,
	}
}

// record writes an audit row for an operation that could not carry it in a
// transaction — the Redis-backed mutations, and denials.
//
// The error is returned rather than logged, and callers must propagate it.
// Everywhere else in this codebase a logging failure is best-effort; here the
// inverse is correct, because an unaudited privileged action is worse than a
// failed one.
func (s *Service) record(ctx context.Context, ev store.AuditEvent) error {
	if err := s.store.InsertAudit(ctx, ev); err != nil {
		return fmt.Errorf("record audit event %q: %w", ev.Action, err)
	}
	return nil
}

// Deny records a rejected authorization attempt. A denial is the most
// interesting row in the log, so it is written like any other action.
func (s *Service) Deny(ctx context.Context, c Caller, action, reason string) error {
	ev := c.event(action, target{})
	ev.Result = store.AuditDenied
	ev.Metadata = map[string]any{"reason": reason}
	return s.record(ctx, ev)
}

// --- shared helpers ---

// mustUser resolves a target user, translating "no such row" into the admin
// plane's own not-found error.
func (s *Service) mustUser(ctx context.Context, userID string) (store.UserRecord, error) {
	u, err := s.store.GetUserByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return store.UserRecord{}, ErrNotFound
	}
	return u, err
}

func (s *Service) mustClient(ctx context.Context, id string) (store.Client, error) {
	c, err := s.store.GetClient(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Client{}, ErrNotFound
	}
	return c, err
}

// confirm enforces the echo required by irreversible operations, so a mistyped
// or stale id cannot delete the wrong account.
func confirm(supplied, expected string) error {
	if supplied == "" || supplied != expected {
		return ErrConfirmationMismatch
	}
	return nil
}

// nextCursor returns the paging cursor for the following page, or "" when this
// was the last one. A short page always means the end.
func nextCursor[T any](items []T, limit int, key func(T) store.Cursor) string {
	if len(items) == 0 || len(items) < limit {
		return ""
	}
	return key(items[len(items)-1]).Encode()
}

// Health pings every registered dependency. Unlike the public /health, which
// returns a constant, this one actually reports whether the process can serve
// a request.
//
// The response says only "ok" or "error" per component. The underlying error is
// logged, never returned: a Postgres or Redis failure message routinely carries
// the host, port and database name, and this endpoint is reachable without a
// token — harmless on loopback, an infrastructure leak the moment anyone widens
// ADMIN_BIND_ADDR.
func (s *Service) Health(ctx context.Context) (bool, map[string]string) {
	components := make(map[string]string, len(s.health))
	healthy := true
	for name, check := range s.health {
		if err := check(ctx); err != nil {
			slog.Error("admin health check failed", "component", name, "error", err)
			components[name] = "error"
			healthy = false
			continue
		}
		components[name] = "ok"
	}
	return healthy, components
}

// translate maps store-level sentinels onto the admin plane's own, so handlers
// map exactly one set of errors onto status codes.
func translate(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrDuplicate):
		return ErrConflict
	case errors.Is(err, store.ErrLastAdmin):
		return ErrLastAdmin
	default:
		return err
	}
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
