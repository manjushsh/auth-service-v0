// Package admin holds the JSON wire types for the admin plane.
//
// The shapes here never carry a secret: no password hash, no live token, no
// second-factor material. The one exception is the password-reset token, which
// exists only to be handed to the user out of band.
package admin

import (
	"time"

	store "github.com/manjushsh/auth-service/internal/store/auth"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	Role      string `json:"role"`
}

type WhoAmIResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

// User is the admin view of an account. It is a separate type from
// store.UserRecord specifically because that one carries PasswordHash: a struct
// with no field for it cannot leak it through a future json.Marshal.
type User struct {
	ID                string     `json:"id"`
	Email             string     `json:"email"`
	Role              string     `json:"role"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
	Locked            *bool      `json:"locked,omitempty"`
	SessionsRevokedAt *time.Time `json:"sessions_revoked_at,omitempty"`
}

type UserList struct {
	Users      []User `json:"users"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// UpdateUserRequest uses pointers so "not supplied" is distinguishable from
// "set to the zero value".
type UpdateUserRequest struct {
	Status *string `json:"status,omitempty"`
	Role   *string `json:"role,omitempty"`
}

// DeleteUserRequest must echo the target's email. Deletion is irreversible and
// a mistyped id would otherwise silently hit the wrong account.
type DeleteUserRequest struct {
	Email string `json:"email"`
}

type UnlockRequest struct {
	Scope string `json:"scope,omitempty"` // "" or "all" clears every scope
}

type PasswordResetResponse struct {
	ResetToken string `json:"reset_token"`
	ExpiresIn  int    `json:"expires_in"`
}

type Client struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	RedirectURI string     `json:"redirect_uri"`
	Disabled    bool       `json:"disabled"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type ClientList struct {
	Clients    []Client `json:"clients"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type CreateClientRequest struct {
	Name        string `json:"name"`
	RedirectURI string `json:"redirect_uri"`
}

// UpdateClientRequest carries the name only. redirect_uri is the client's
// identity everywhere else in the system — codes are bound to the literal
// string — so changing it in place would break every code in flight. Rotation
// is create-new, migrate, disable-old.
type UpdateClientRequest struct {
	Name *string `json:"name,omitempty"`
	// RedirectURI is accepted only so the handler can reject it with an
	// explanation instead of silently ignoring it.
	RedirectURI *string `json:"redirect_uri,omitempty"`
}

type DeleteClientRequest struct {
	RedirectURI string `json:"redirect_uri"`
}

type AuditList struct {
	Records    []store.AuditRecord `json:"records"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type HealthResponse struct {
	Status     string            `json:"status"`
	Components map[string]string `json:"components"`
}
