package auth

import (
	"errors"

	model "github.com/manjushsh/auth-service/internal/model/auth"
)

var (
	ErrDuplicate = errors.New("user already exists")
	ErrNotFound  = errors.New("user not found")
)

type Store interface {
	CreateUser(email, hashedPassword string) error
	GetUser(email string) (model.UserRecord, error)
}
