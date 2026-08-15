package admin

import (
	"context"

	model "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// ListUsers returns one page of accounts, newest first. email, when supplied,
// is an exact match — support workflows start from an address the user gave
// them, and prefix search would need an index the schema does not carry.
func (s *Service) ListUsers(ctx context.Context, email string, page store.Page) (model.UserList, error) {
	page = page.Normalize()

	users, err := s.store.ListUsers(ctx, normalizeEmail(email), page)
	if err != nil {
		return model.UserList{}, err
	}

	out := make([]model.User, 0, len(users))
	for _, u := range users {
		out = append(out, toUserView(u))
	}
	return model.UserList{
		Users: out,
		NextCursor: nextCursor(users, page.Limit, func(u store.UserRecord) store.Cursor {
			return store.Cursor{Time: u.CreatedAt, ID: u.ID}
		}),
	}, nil
}

// GetUser is the composite read: the Postgres row plus the live Redis state
// (locked, sessions revoked), which otherwise takes four hand-typed key lookups
// to answer.
func (s *Service) GetUser(ctx context.Context, userID string) (model.User, error) {
	u, err := s.mustUser(ctx, userID)
	if err != nil {
		return model.User{}, err
	}

	view := toUserView(u)

	locked, err := s.accounts.LockState(ctx, u.Email)
	if err != nil {
		return model.User{}, err
	}
	view.Locked = &locked

	if revokedAt, err := s.accounts.SessionsRevokedAt(ctx, u.ID); err != nil {
		return model.User{}, err
	} else if !revokedAt.IsZero() {
		view.SessionsRevokedAt = &revokedAt
	}

	return view, nil
}

// UpdateUser applies a status and/or role change. Both revoke the target's
// sessions: a suspension that leaves a live token working for another hour is
// decoration.
func (s *Service) UpdateUser(ctx context.Context, c Caller, userID string, req model.UpdateUserRequest) (model.User, error) {
	if req.Status == nil && req.Role == nil {
		return model.User{}, ErrBadInput
	}

	u, err := s.mustUser(ctx, userID)
	if err != nil {
		return model.User{}, err
	}
	if u.ID == c.UserID {
		// Not a security boundary — the last-admin guard is. This just stops
		// an admin locking themselves out by accident.
		return model.User{}, ErrSelfTarget
	}

	// Build the whole change first, so a request that touches both fields is
	// one transaction rather than two — half a PATCH plus an error is a state
	// nobody asked for and the caller cannot reason about.
	var (
		upd    store.UserUpdate
		events []store.AuditEvent
	)
	if req.Status != nil {
		if !store.ValidStatus(*req.Status) {
			return model.User{}, ErrBadInput
		}
		upd.Status = req.Status
		ev := c.event("user."+statusAction(*req.Status), userTarget(u))
		ev.Metadata = map[string]any{"from": u.Status, "to": *req.Status}
		events = append(events, ev)
	}
	if req.Role != nil {
		if !store.ValidRole(*req.Role) {
			return model.User{}, ErrBadInput
		}
		upd.Role = req.Role
		ev := c.event("user.role_change", userTarget(u))
		ev.Metadata = map[string]any{"from": u.Role, "to": *req.Role}
		events = append(events, ev)
	}

	if err := s.revokeThen(ctx, u.ID, func() error {
		return s.store.UpdateUser(ctx, u.ID, upd, events)
	}); err != nil {
		return model.User{}, translate(err)
	}

	if upd.Status != nil {
		u.Status = *upd.Status
	}
	if upd.Role != nil {
		u.Role = *upd.Role
	}
	return toUserView(u), nil
}

func (s *Service) DeleteUser(ctx context.Context, c Caller, userID string, req model.DeleteUserRequest) error {
	u, err := s.mustUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.ID == c.UserID {
		return ErrSelfTarget
	}
	if err := confirm(normalizeEmail(req.Email), u.Email); err != nil {
		return err
	}

	// Revoke first: nothing re-checks that a token's subject still exists, so a
	// deleted row whose sessions survived would leave a working session behind.
	return translate(s.revokeThen(ctx, u.ID, func() error {
		return s.store.DeleteUser(ctx, u.ID, c.event("user.delete", userTarget(u)))
	}))
}

// revokeThen invalidates a user's sessions and only then applies the change.
//
// The ordering is deliberate and is the opposite of the intuitive one. Session
// revocation lives in Redis and the change lives in Postgres, so they cannot
// share a transaction; one of them has to go first, and whichever fails leaves
// the other applied. Revoking first makes the failure mode "logged out for a
// change that did not happen" — recoverable, and safe. Mutating first makes it
// "suspended, deleted or demoted with live tokens still working", which is
// precisely the guarantee these endpoints exist to provide.
//
// Revocation is idempotent, so the wasted bump costs nothing but a re-login.
func (s *Service) revokeThen(ctx context.Context, userID string, apply func() error) error {
	if err := s.accounts.RevokeSessions(ctx, userID); err != nil {
		return err
	}
	return apply()
}

// --- helpers ---

func toUserView(u store.UserRecord) model.User {
	return model.User{
		ID:        u.ID,
		Email:     u.Email,
		Role:      u.Role,
		Status:    u.Status,
		CreatedAt: u.CreatedAt,
	}
}

func statusAction(status string) string {
	if status == store.StatusSuspended {
		return "suspend"
	}
	return "unsuspend"
}
