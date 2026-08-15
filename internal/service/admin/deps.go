package admin

import (
	"context"
	"time"

	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// adminStore is the persistence the admin plane needs.
//
// Every mutating method takes a store.AuditEvent. That is the point: it is not
// possible to change a user or a client without supplying the record of who
// did it, and the implementation writes both on one transaction.
type adminStore interface {
	GetUser(ctx context.Context, email string) (store.UserRecord, error)
	GetUserByID(ctx context.Context, userID string) (store.UserRecord, error)
	ListUsers(ctx context.Context, email string, page store.Page) ([]store.UserRecord, error)
	UpdateUser(ctx context.Context, userID string, upd store.UserUpdate, evs []store.AuditEvent) error
	DeleteUser(ctx context.Context, userID string, ev store.AuditEvent) error

	ListClients(ctx context.Context, page store.Page) ([]store.Client, error)
	GetClient(ctx context.Context, id string) (store.Client, error)
	CreateClient(ctx context.Context, name, redirectURI string, ev store.AuditEvent) (store.Client, error)
	RenameClient(ctx context.Context, id, name string, ev store.AuditEvent) error
	SetClientDisabled(ctx context.Context, id string, disabled bool, ev store.AuditEvent) error
	DeleteClient(ctx context.Context, id string, ev store.AuditEvent) error

	InsertAudit(ctx context.Context, ev store.AuditEvent) error
	ListAudit(ctx context.Context, f store.AuditFilter) ([]store.AuditRecord, error)
}

// accountOps are the credential and session mechanics owned by the public auth
// service. The admin plane orchestrates and audits; it deliberately does not
// re-implement lockout accounting, epoch TTLs or password hashing, so there is
// exactly one definition of each.
type accountOps interface {
	VerifyPassword(ctx context.Context, email, password string) (store.UserRecord, error)
	RevokeSessions(ctx context.Context, userID string) error
	Unlock(ctx context.Context, email string, scopes ...string) error
	IssuePasswordReset(ctx context.Context, userID string) (string, time.Duration, error)
	LockState(ctx context.Context, email string) (bool, error)
	SessionsRevokedAt(ctx context.Context, userID string) (time.Time, error)
}

// blocklist revokes an admin token by jti on logout.
type blocklist interface {
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
}
