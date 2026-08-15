package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strconv"
	"sync"
	"time"
)

// MemoryStore is the in-process implementation used by tests and local runs.
// It mirrors the Postgres surface, including the audit log, so service-level
// tests exercise the same code paths production does.
//
// One property it cannot reproduce: guardLastAdmin's correctness rests on
// SELECT ... FOR UPDATE. The mutex below serializes everything, so this store
// will pass a concurrent-demotion test that Postgres might not. Treat that case
// as unproven here (docs/ADMIN_API_PLAN.md §10.4).
type MemoryStore struct {
	mu               sync.RWMutex
	users            map[string]*UserRecord // id -> user
	emails           map[string]string      // email -> id
	clients          map[string]*Client     // id -> client
	allowedRedirects map[string]bool
	audit            []AuditRecord
	seq              int64
	clock            time.Time
}

func NewMemoryStore(allowedRedirects ...string) *MemoryStore {
	allowed := make(map[string]bool, len(allowedRedirects))
	for _, uri := range allowedRedirects {
		allowed[uri] = true
	}
	return &MemoryStore{
		users:            map[string]*UserRecord{},
		emails:           map[string]string{},
		clients:          map[string]*Client{},
		allowedRedirects: allowed,
		clock:            time.Now().UTC(),
	}
}

// next hands out a strictly increasing timestamp so keyset pagination has a
// total order, exactly as (created_at, id) does in Postgres.
func (s *MemoryStore) next() time.Time {
	s.seq++
	return s.clock.Add(time.Duration(s.seq) * time.Millisecond)
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read does not fail in practice
	return hex.EncodeToString(b)
}

// --- users ---

func (s *MemoryStore) CreateUser(ctx context.Context, email, hashedPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.emails[email]; exists {
		return ErrDuplicate
	}
	id := newID()
	s.users[id] = &UserRecord{
		ID:           id,
		Email:        email,
		PasswordHash: hashedPassword,
		Role:         RoleUser,
		Status:       StatusActive,
		CreatedAt:    s.next(),
	}
	s.emails[email] = id
	return nil
}

func (s *MemoryStore) GetUser(ctx context.Context, email string) (UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.emails[email]
	if !ok {
		return UserRecord{}, ErrNotFound
	}
	return *s.users[id], nil
}

func (s *MemoryStore) GetUserByID(ctx context.Context, userID string) (UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[userID]
	if !ok {
		return UserRecord{}, ErrNotFound
	}
	return *u, nil
}

func (s *MemoryStore) SetUserPassword(ctx context.Context, userID, hashedPassword string, ev AuditEvent) error {
	return s.mutate(ev, func() error {
		u, ok := s.users[userID]
		if !ok {
			return ErrNotFound
		}
		u.PasswordHash = hashedPassword
		return nil
	})
}

func (s *MemoryStore) ListUsers(ctx context.Context, email string, page Page) ([]UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]UserRecord, 0, len(s.users))
	for _, u := range s.users {
		if email != "" && u.Email != email {
			continue
		}
		all = append(all, *u)
	}
	return paginate(all, page, func(u UserRecord) Cursor {
		return Cursor{Time: u.CreatedAt, ID: u.ID}
	}), nil
}

// ListPrivilegedUsers returns every support/admin account, unpaginated.
func (s *MemoryStore) ListPrivilegedUsers(ctx context.Context) ([]UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]UserRecord, 0, 4)
	for _, u := range s.users {
		if IsPrivileged(u.Role) {
			out = append(out, *u)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Email < out[j].Email
	})
	return out, nil
}

// UpdateUser applies both changes together, mirroring the single Postgres
// transaction: a partially-applied update is not a state the caller can observe.
func (s *MemoryStore) UpdateUser(ctx context.Context, userID string, upd UserUpdate, evs []AuditEvent) error {
	if upd.IsZero() {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[userID]
	if !ok {
		return ErrNotFound
	}
	if upd.RemovesAdmin() && s.isLastAdmin(userID) {
		return ErrLastAdmin
	}

	if upd.Status != nil {
		u.Status = *upd.Status
	}
	if upd.Role != nil {
		u.Role = *upd.Role
	}
	for _, ev := range evs {
		s.appendAudit(ev)
	}
	return nil
}

func (s *MemoryStore) SetUserRole(ctx context.Context, userID, role string, ev AuditEvent) error {
	return s.UpdateUser(ctx, userID, UserUpdate{Role: &role}, []AuditEvent{ev})
}

func (s *MemoryStore) SetUserStatus(ctx context.Context, userID, status string, ev AuditEvent) error {
	return s.UpdateUser(ctx, userID, UserUpdate{Status: &status}, []AuditEvent{ev})
}

func (s *MemoryStore) DeleteUser(ctx context.Context, userID string, ev AuditEvent) error {
	return s.mutate(ev, func() error {
		u, ok := s.users[userID]
		if !ok {
			return ErrNotFound
		}
		if s.isLastAdmin(userID) {
			return ErrLastAdmin
		}
		delete(s.emails, u.Email)
		delete(s.users, userID)
		return nil
	})
}

func (s *MemoryStore) CountAdmins(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.countAdmins(), nil
}

func (s *MemoryStore) countAdmins() int {
	n := 0
	for _, u := range s.users {
		if u.Role == RoleAdmin && u.Status == StatusActive {
			n++
		}
	}
	return n
}

func (s *MemoryStore) isLastAdmin(userID string) bool {
	u, ok := s.users[userID]
	if !ok || u.Role != RoleAdmin || u.Status != StatusActive {
		return false
	}
	return s.countAdmins() == 1
}

// --- clients ---

func (s *MemoryStore) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Empty allowlist and no registered clients means accept all, for local
	// dev and for the tests that predate client management.
	if len(s.allowedRedirects) == 0 && len(s.clients) == 0 {
		return nil
	}
	if s.allowedRedirects[redirectURI] {
		return nil
	}
	for _, c := range s.clients {
		if c.RedirectURI == redirectURI && !c.Disabled() {
			return nil
		}
	}
	return ErrNotFound
}

func (s *MemoryStore) ListClients(ctx context.Context, page Page) ([]Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]Client, 0, len(s.clients))
	for _, c := range s.clients {
		all = append(all, *c)
	}
	return paginate(all, page, func(c Client) Cursor {
		return Cursor{Time: c.CreatedAt, ID: c.ID}
	}), nil
}

func (s *MemoryStore) GetClient(ctx context.Context, id string) (Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c, ok := s.clients[id]
	if !ok {
		return Client{}, ErrNotFound
	}
	return *c, nil
}

func (s *MemoryStore) CreateClient(ctx context.Context, name, redirectURI string, ev AuditEvent) (Client, error) {
	var created Client
	err := s.mutatePtr(&ev, func() error {
		for _, c := range s.clients {
			if c.RedirectURI == redirectURI && !c.Disabled() {
				return ErrDuplicate
			}
		}
		c := &Client{ID: newID(), Name: name, RedirectURI: redirectURI, CreatedAt: s.next()}
		s.clients[c.ID] = c
		created = *c
		// The audit record can only name the client once it exists.
		ev.TargetID = c.ID
		return nil
	})
	return created, err
}

func (s *MemoryStore) RenameClient(ctx context.Context, id, name string, ev AuditEvent) error {
	return s.mutate(ev, func() error {
		c, ok := s.clients[id]
		if !ok {
			return ErrNotFound
		}
		c.Name = name
		return nil
	})
}

func (s *MemoryStore) SetClientDisabled(ctx context.Context, id string, disabled bool, ev AuditEvent) error {
	return s.mutate(ev, func() error {
		c, ok := s.clients[id]
		if !ok {
			return ErrNotFound
		}
		if !disabled {
			c.DisabledAt = nil
			return nil
		}
		at := s.next()
		c.DisabledAt = &at
		return nil
	})
}

func (s *MemoryStore) DeleteClient(ctx context.Context, id string, ev AuditEvent) error {
	return s.mutate(ev, func() error {
		if _, ok := s.clients[id]; !ok {
			return ErrNotFound
		}
		delete(s.clients, id)
		return nil
	})
}

// --- audit ---

func (s *MemoryStore) InsertAudit(ctx context.Context, ev AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendAudit(ev)
	return nil
}

func (s *MemoryStore) ListAudit(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	matched := make([]AuditRecord, 0, len(s.audit))
	for _, r := range s.audit {
		switch {
		case f.ActorID != "" && r.ActorID != f.ActorID:
		case f.TargetID != "" && r.TargetID != f.TargetID:
		case f.Action != "" && r.Action != f.Action:
		case !f.From.IsZero() && r.CreatedAt.Before(f.From):
		case !f.To.IsZero() && r.CreatedAt.After(f.To):
		default:
			matched = append(matched, r)
		}
	}
	return paginate(matched, f.Page, func(r AuditRecord) Cursor {
		return Cursor{Time: r.CreatedAt, ID: strconv.FormatInt(r.ID, 10)}
	}), nil
}

// SeedRole sets a role without recording an audit event.
//
// Test-only, and the reason it exists: building a fixture is not an
// administrative action, so it must not appear in the log those tests then
// assert on. Going through SetUserRole for setup makes every audit count
// off-by-however-many-users-the-fixture-created.
func (s *MemoryStore) SeedRole(userID, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[userID]; ok {
		u.Role = role
	}
}

// AuditEvents exposes the raw log for assertions. Test-only.
func (s *MemoryStore) AuditEvents() []AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]AuditRecord(nil), s.audit...)
}

func (s *MemoryStore) appendAudit(ev AuditEvent) {
	s.audit = append(s.audit, AuditRecord{
		ID:           int64(len(s.audit) + 1),
		ActorID:      ev.ActorID,
		ActorEmail:   ev.ActorEmail,
		ActorRole:    ev.ActorRole,
		Action:       ev.Action,
		TargetType:   ev.TargetType,
		TargetID:     ev.TargetID,
		TargetLabel:  ev.TargetLabel,
		Result:       ev.Result,
		Metadata:     ev.Metadata,
		RemoteAddr:   ev.RemoteAddr,
		ForwardedFor: ev.ForwardedFor,
		UserAgent:    ev.UserAgent,
		CreatedAt:    s.next(),
	})
}

// mutate mirrors the Postgres transaction: the change and its audit row are
// applied together, or the change is rolled back by never having happened.
func (s *MemoryStore) mutate(ev AuditEvent, fn func() error) error {
	return s.mutatePtr(&ev, fn)
}

// mutatePtr is mutate for writes whose audit record can only be completed after
// the change — a created row's id, in practice.
func (s *MemoryStore) mutatePtr(ev *AuditEvent, fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := fn(); err != nil {
		return err
	}
	s.appendAudit(*ev)
	return nil
}

// paginate applies "newest first" ordering plus the keyset cursor, so the
// memory store's paging semantics match the SQL.
func paginate[T any](all []T, page Page, key func(T) Cursor) []T {
	page = page.Normalize()

	sort.Slice(all, func(i, j int) bool {
		a, b := key(all[i]), key(all[j])
		if !a.Time.Equal(b.Time) {
			return a.Time.After(b.Time)
		}
		return a.ID > b.ID
	})

	out := make([]T, 0, page.Limit)
	for _, item := range all {
		if !page.Cursor.IsZero() {
			k := key(item)
			after := k.Time.After(page.Cursor.Time) ||
				(k.Time.Equal(page.Cursor.Time) && k.ID >= page.Cursor.ID)
			if after {
				continue
			}
		}
		if len(out) == page.Limit {
			break
		}
		out = append(out, item)
	}
	return out
}
