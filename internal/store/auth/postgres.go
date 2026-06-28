package auth

import (
	"database/sql"
	"errors"

	"github.com/lib/pq"

	model "github.com/manjushsh/auth-service/internal/model/auth"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) CreateUser(email, hashedPassword string) error {
	_, err := s.db.Exec(
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

func (s *PostgresStore) GetUser(email string) (model.UserRecord, error) {
	var u model.UserRecord
	err := s.db.QueryRow(
		`SELECT id, password_hash FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return model.UserRecord{}, ErrNotFound
	}
	return u, err
}
