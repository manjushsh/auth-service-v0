package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// uniqueViolation is Postgres' SQLSTATE for a unique-constraint breach.
const uniqueViolation = "23505"

const userColumns = `id, email, password_hash, role, status, created_at`

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows so the scan helpers
// below work for single reads and list queries alike.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(s rowScanner) (UserRecord, error) {
	var u UserRecord
	err := s.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt)
	return u, err
}

func scanClient(s rowScanner) (Client, error) {
	var c Client
	err := s.Scan(&c.ID, &c.Name, &c.RedirectURI, &c.DisabledAt, &c.CreatedAt)
	return c, err
}

// collect runs a list query and scans every row with the given scanner.
//
// The result is always non-nil, so an empty page marshals as `[]` rather than
// `null`. A nil slice here would make the JSON depend on which store answered —
// the in-memory one already returns empty slices — and hand clients a value
// they cannot iterate.
func collect[T any](ctx context.Context, db *sql.DB, query string, args []any, scan func(rowScanner) (T, error)) ([]T, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []T{}
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// withTx runs fn inside a transaction, rolling back on any error or panic.
//
// It is the mechanism behind the plan's central audit rule: a mutation and its
// audit row land together or not at all, so there is no such thing as an
// unaudited change to users or clients.
func (s *PostgresStore) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// mutate is the shape every audited write takes: do the work, then record it,
// on one transaction. Written once so no handler can accidentally skip half.
//
// The event is passed by pointer so fn can fill in fields that only exist after
// the write — a created row's id, most importantly. Capturing the event by
// value would leave `client.create` records with a null target, and those are
// exactly the rows an incident review looks for first.
func (s *PostgresStore) mutate(ctx context.Context, ev *AuditEvent, fn func(tx *sql.Tx) error) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return insertAuditTx(ctx, tx, ev)
	})
}

// --- users: public auth plane ---

func (s *PostgresStore) CreateUser(ctx context.Context, email, hashedPassword string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2)`,
		email, hashedPassword,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == uniqueViolation {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

func (s *PostgresStore) GetUser(ctx context.Context, email string) (UserRecord, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = $1`, email))
	if errors.Is(err, sql.ErrNoRows) {
		return UserRecord{}, ErrNotFound
	}
	return u, err
}

func (s *PostgresStore) GetUserByID(ctx context.Context, userID string) (UserRecord, error) {
	if !looksLikeUUID(userID) {
		// Postgres rejects a malformed UUID with a type error rather than an
		// empty result; short-circuit so callers get ErrNotFound as they expect.
		return UserRecord{}, ErrNotFound
	}
	u, err := scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return UserRecord{}, ErrNotFound
	}
	return u, err
}

func (s *PostgresStore) SetUserPassword(ctx context.Context, userID, hashedPassword string, ev AuditEvent) error {
	return s.mutate(ctx, &ev, func(tx *sql.Tx) error {
		return execExpectingRow(ctx, tx,
			`UPDATE users SET password_hash = $1 WHERE id = $2`, hashedPassword, userID)
	})
}

func (s *PostgresStore) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM clients WHERE redirect_uri = $1 AND disabled_at IS NULL`,
		redirectURI,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// --- users: admin plane ---

// ListUsers returns one keyset page, newest first. email, when set, is an exact
// (already normalized) match.
func (s *PostgresStore) ListUsers(ctx context.Context, email string, page Page) ([]UserRecord, error) {
	page = page.Normalize()

	var f filter
	f.eq("email", email)
	f.keyset("created_at, id", page.Cursor, page.Cursor.ID)

	q := `SELECT ` + userColumns + ` FROM users` + f.where() +
		orderAndLimit("created_at DESC, id DESC", page.Limit)
	return collect(ctx, s.db, q, f.args, scanUser)
}

// ListPrivilegedUsers returns every support/admin account, ordered for display.
//
// It is a separate query rather than a filter over ListUsers because callers
// need *all* of them, not a page: adminctl paging through users and filtering
// in memory would silently miss an admin created before the newest page, which
// on a break-glass tool is the worst possible way to be wrong. The partial
// index users_role_idx exists for exactly this predicate.
func (s *PostgresStore) ListPrivilegedUsers(ctx context.Context) ([]UserRecord, error) {
	var f filter
	f.notEq("role", RoleUser)

	q := `SELECT ` + userColumns + ` FROM users` + f.where() + ` ORDER BY role, email`
	return collect(ctx, s.db, q, f.args, scanUser)
}

// UpdateUser applies a status and/or role change as one transaction, recording
// one audit row per distinct change.
func (s *PostgresStore) UpdateUser(ctx context.Context, userID string, upd UserUpdate, evs []AuditEvent) error {
	if upd.IsZero() {
		return nil
	}

	return s.withTx(ctx, func(tx *sql.Tx) error {
		if upd.RemovesAdmin() {
			if err := guardLastAdmin(ctx, tx, userID); err != nil {
				return err
			}
		}

		var (
			assignments []string
			args        []any
		)
		if upd.Status != nil {
			args = append(args, *upd.Status)
			assignments = append(assignments, fmt.Sprintf("status = $%d", len(args)))
		}
		if upd.Role != nil {
			args = append(args, *upd.Role)
			assignments = append(assignments, fmt.Sprintf("role = $%d", len(args)))
		}
		args = append(args, userID)

		q := fmt.Sprintf(`UPDATE users SET %s WHERE id = $%d`, strings.Join(assignments, ", "), len(args))
		if err := execExpectingRow(ctx, tx, q, args...); err != nil {
			return err
		}

		for i := range evs {
			if err := insertAuditTx(ctx, tx, &evs[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetUserRole and SetUserStatus are single-change conveniences over UpdateUser,
// so the last-admin guard and the audit rule have one implementation.
func (s *PostgresStore) SetUserRole(ctx context.Context, userID, role string, ev AuditEvent) error {
	return s.UpdateUser(ctx, userID, UserUpdate{Role: &role}, []AuditEvent{ev})
}

func (s *PostgresStore) SetUserStatus(ctx context.Context, userID, status string, ev AuditEvent) error {
	return s.UpdateUser(ctx, userID, UserUpdate{Status: &status}, []AuditEvent{ev})
}

func (s *PostgresStore) DeleteUser(ctx context.Context, userID string, ev AuditEvent) error {
	return s.mutate(ctx, &ev, func(tx *sql.Tx) error {
		if err := guardLastAdmin(ctx, tx, userID); err != nil {
			return err
		}
		return execExpectingRow(ctx, tx, `DELETE FROM users WHERE id = $1`, userID)
	})
}

// guardLastAdmin locks every admin row and refuses if userID is the only one
// left. Taking the row locks first is what makes two concurrent demotions
// serialize instead of both seeing "there are 2 admins" and both proceeding.
func guardLastAdmin(ctx context.Context, tx *sql.Tx, userID string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM users WHERE role = $1 AND status = $2 FOR UPDATE`,
		RoleAdmin, StatusActive)
	if err != nil {
		return err
	}
	defer rows.Close()

	admins := make([]string, 0, 2)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		admins = append(admins, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if len(admins) == 1 && admins[0] == userID {
		return ErrLastAdmin
	}
	return nil
}

// --- clients ---

const clientColumns = `id, name, redirect_uri, disabled_at, created_at`

func (s *PostgresStore) ListClients(ctx context.Context, page Page) ([]Client, error) {
	page = page.Normalize()

	var f filter
	f.keyset("created_at, id", page.Cursor, page.Cursor.ID)

	q := `SELECT ` + clientColumns + ` FROM clients` + f.where() +
		orderAndLimit("created_at DESC, id DESC", page.Limit)
	return collect(ctx, s.db, q, f.args, scanClient)
}

func (s *PostgresStore) GetClient(ctx context.Context, id string) (Client, error) {
	if !looksLikeUUID(id) {
		return Client{}, ErrNotFound
	}
	c, err := scanClient(s.db.QueryRowContext(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	return c, err
}

func (s *PostgresStore) CreateClient(ctx context.Context, name, redirectURI string, ev AuditEvent) (Client, error) {
	var c Client
	err := s.mutate(ctx, &ev, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`INSERT INTO clients (name, redirect_uri) VALUES ($1, $2) RETURNING `+clientColumns,
			name, redirectURI)
		created, err := scanClient(row)
		if err != nil {
			var pqErr *pq.Error
			if errors.As(err, &pqErr) && pqErr.Code == uniqueViolation {
				return ErrDuplicate
			}
			return err
		}
		c = created
		// The row exists now, so the audit record can name it. Without this the
		// creation event has a null target and never matches a target filter.
		ev.TargetID = created.ID
		return nil
	})
	return c, err
}

func (s *PostgresStore) RenameClient(ctx context.Context, id, name string, ev AuditEvent) error {
	return s.mutate(ctx, &ev, func(tx *sql.Tx) error {
		return execExpectingRow(ctx, tx, `UPDATE clients SET name = $1 WHERE id = $2`, name, id)
	})
}

// SetClientDisabled is the soft delete. Re-enabling is supported so an
// accidental disable during an incident is one call to undo.
func (s *PostgresStore) SetClientDisabled(ctx context.Context, id string, disabled bool, ev AuditEvent) error {
	return s.mutate(ctx, &ev, func(tx *sql.Tx) error {
		// NOW() rather than a Go timestamp: one clock, the database's, shared
		// with created_at so the two are always comparable.
		q := `UPDATE clients SET disabled_at = NULL WHERE id = $1`
		if disabled {
			q = `UPDATE clients SET disabled_at = NOW() WHERE id = $1`
		}
		return execExpectingRow(ctx, tx, q, id)
	})
}

func (s *PostgresStore) DeleteClient(ctx context.Context, id string, ev AuditEvent) error {
	return s.mutate(ctx, &ev, func(tx *sql.Tx) error {
		return execExpectingRow(ctx, tx, `DELETE FROM clients WHERE id = $1`, id)
	})
}

// --- helpers ---

// execExpectingRow turns "matched nothing" into ErrNotFound, so an update
// against a stale id fails loudly instead of reporting success.
func execExpectingRow(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == uniqueViolation {
			return ErrDuplicate
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// looksLikeUUID is a cheap shape check. Postgres raises a type error rather
// than returning zero rows for a malformed UUID, which would surface to the
// caller as a 500 where a 404 is correct.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
