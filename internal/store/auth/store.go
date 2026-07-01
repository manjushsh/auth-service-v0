package auth

import "errors"

var (
	ErrDuplicate = errors.New("user already exists")
	ErrNotFound  = errors.New("user not found")
)

type UserRecord struct {
	ID           string
	PasswordHash string
}

type Store interface {
	CreateUser(email, hashedPassword string) error
	GetUser(email string) (UserRecord, error)
	ValidateRedirectURI(redirectURI string) error
}
