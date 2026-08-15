package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lib/pq"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) CreateUser(ctx context.Context, email, hashedPassword string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2)`,
		email, hashedPassword,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

func (s *PostgresStore) GetUser(ctx context.Context, email string) (UserRecord, error) {
	var u UserRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return UserRecord{}, ErrNotFound
	}
	return u, err
}

func (s *PostgresStore) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM clients WHERE redirect_uri = $1`,
		redirectURI,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
