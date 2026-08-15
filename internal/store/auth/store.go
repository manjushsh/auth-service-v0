package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrDuplicate = errors.New("record already exists")
	ErrNotFound  = errors.New("record not found")
	// ErrLastAdmin guards the admin plane against locking itself out. It is a
	// transaction-level invariant (SELECT ... FOR UPDATE), not an application
	// check, so two concurrent demotions cannot both win.
	ErrLastAdmin = errors.New("cannot remove the last remaining admin")
)

// Roles. Authorization is coarse by design: `support` covers the high-volume
// account-recovery tasks, `admin` covers everything that can hand over an
// account. See docs/ADMIN_API_PLAN.md §3.5.
const (
	RoleUser    = "user"
	RoleSupport = "support"
	RoleAdmin   = "admin"
)

// Account statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// Lockout scopes. The password path and (later) the OTP path keep independent
// failure budgets, so a successful login cannot reset the other one.
const (
	LockScopePassword = "pwd"
	LockScopeMFA      = "mfa"
)

// LockScopes is every scope an unlock can clear. Extend this when a scope is
// added and `unlock?scope=all` keeps working without further edits.
var LockScopes = []string{LockScopePassword}

func ValidRole(role string) bool {
	switch role {
	case RoleUser, RoleSupport, RoleAdmin:
		return true
	}
	return false
}

func ValidStatus(status string) bool {
	return status == StatusActive || status == StatusSuspended
}

// IsPrivileged reports whether a role may use the admin plane at all.
func IsPrivileged(role string) bool {
	return role == RoleSupport || role == RoleAdmin
}

// RoleSatisfies reports whether `have` meets the `want` requirement. Roles are
// a strict ladder: admin can do anything support can.
func RoleSatisfies(have, want string) bool {
	if have == RoleAdmin {
		return true
	}
	return have == want
}

type UserRecord struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	Status       string
	CreatedAt    time.Time
}

func (u UserRecord) Suspended() bool { return u.Status == StatusSuspended }

// UserUpdate is a partial change to an account. Pointers distinguish "not
// supplied" from "set to the zero value".
//
// Status and Role travel together so a request that changes both is one
// transaction: applying half a PATCH and then failing would leave the caller
// with an error and the account in a state nobody asked for.
type UserUpdate struct {
	Status *string
	Role   *string
}

func (u UserUpdate) IsZero() bool { return u.Status == nil && u.Role == nil }

// RemovesAdmin reports whether applying this update would strip a user of admin
// capability. Demotion and suspension both do, so both take the last-admin guard.
func (u UserUpdate) RemovesAdmin() bool {
	return (u.Role != nil && *u.Role != RoleAdmin) ||
		(u.Status != nil && *u.Status == StatusSuspended)
}

type Client struct {
	ID          string
	Name        string
	RedirectURI string
	DisabledAt  *time.Time
	CreatedAt   time.Time
}

func (c Client) Disabled() bool { return c.DisabledAt != nil }

// Store is what the public auth service needs. It stays deliberately small;
// the admin plane's wider needs are expressed by separate interfaces on the
// admin service (internal/service/admin/deps.go).
type Store interface {
	CreateUser(ctx context.Context, email, hashedPassword string) error
	GetUser(ctx context.Context, email string) (UserRecord, error)
	GetUserByID(ctx context.Context, userID string) (UserRecord, error)
	// SetUserPassword takes the audit event so the type system, not a code
	// review, enforces that a credential change is always recorded.
	SetUserPassword(ctx context.Context, userID, hashedPassword string, ev AuditEvent) error
	ValidateRedirectURI(ctx context.Context, redirectURI string) error
}

// --- audit ---

// Audit results. A denied attempt is the most interesting row in the log, so it
// is recorded like any other.
const (
	AuditOK      = "ok"
	AuditDenied  = "denied"
	AuditError   = "error"
	TargetUser   = "user"
	TargetClient = "client"
)

// AuditEvent is a privileged action to record. Mutating store methods take one
// so that the type system, not a code review, enforces "no unaudited change":
// there is no way to call them without supplying it.
type AuditEvent struct {
	ActorID     string
	ActorEmail  string
	ActorRole   string
	Action      string
	TargetType  string
	TargetID    string
	TargetLabel string
	Result      string
	Metadata    map[string]any
	RequestMeta
}

// RequestMeta is the caller-provenance half of an audit record. Handlers build
// it from the request; services pass it through untouched.
//
// RemoteAddr is the TCP peer and is trustworthy. ForwardedFor is
// attacker-supplied and is recorded only as a hint — never used for decisions.
type RequestMeta struct {
	RemoteAddr   string
	ForwardedFor string
	UserAgent    string
}

type AuditRecord struct {
	ID           int64          `json:"id"`
	ActorID      string         `json:"actor_id,omitempty"`
	ActorEmail   string         `json:"actor_email"`
	ActorRole    string         `json:"actor_role"`
	Action       string         `json:"action"`
	TargetType   string         `json:"target_type,omitempty"`
	TargetID     string         `json:"target_id,omitempty"`
	TargetLabel  string         `json:"target_label,omitempty"`
	Result       string         `json:"result"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	RemoteAddr   string         `json:"remote_addr,omitempty"`
	ForwardedFor string         `json:"forwarded_for,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

type AuditFilter struct {
	ActorID  string
	TargetID string
	Action   string
	From     time.Time
	To       time.Time
	Page     Page
}

// --- pagination ---

// DefaultPageSize / MaxPageSize bound every list endpoint.
const (
	DefaultPageSize = 25
	MaxPageSize     = 100
)

// Page is keyset pagination state. Keyset rather than OFFSET so a row inserted
// mid-scan cannot cause a skipped or duplicated result.
type Page struct {
	Limit  int
	Cursor Cursor
}

// Normalize clamps the limit into range. A zero limit means "use the default",
// so a caller that omits it gets sane behaviour.
func (p Page) Normalize() Page {
	if p.Limit <= 0 {
		p.Limit = DefaultPageSize
	}
	if p.Limit > MaxPageSize {
		p.Limit = MaxPageSize
	}
	return p
}

// Cursor points at the last row of the previous page: a (timestamp, id) pair,
// which is unique and totally ordered even when timestamps collide.
type Cursor struct {
	Time time.Time
	ID   string
}

func (c Cursor) IsZero() bool { return c.ID == "" }

// Encode renders a cursor as an opaque string. It is not a security boundary —
// it is opaque so clients don't build their own and depend on the ordering key.
func (c Cursor) Encode() string {
	if c.IsZero() {
		return ""
	}
	raw := strconv.FormatInt(c.Time.UTC().UnixNano(), 10) + "|" + c.ID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func DecodeCursor(s string) (Cursor, error) {
	if s == "" {
		return Cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, fmt.Errorf("malformed cursor")
	}
	nanos, id, ok := strings.Cut(string(raw), "|")
	if !ok || id == "" {
		return Cursor{}, fmt.Errorf("malformed cursor")
	}
	n, err := strconv.ParseInt(nanos, 10, 64)
	if err != nil {
		return Cursor{}, fmt.Errorf("malformed cursor")
	}
	return Cursor{Time: time.Unix(0, n).UTC(), ID: id}, nil
}
