package auth

import (
	"context"
	"errors"
)

var (
	ErrDuplicate = errors.New("user already exists")
	ErrNotFound  = errors.New("user not found")
)

type UserRecord struct {
	ID           string
	PasswordHash string
}

type Store interface {
	CreateUser(ctx context.Context, email, hashedPassword string) error
	GetUser(ctx context.Context, email string) (UserRecord, error)
	ValidateRedirectURI(ctx context.Context, redirectURI string) error
}
