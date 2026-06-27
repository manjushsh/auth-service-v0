package basic

import "errors"

var (
	ErrDuplicate = errors.New("user already exists")
	ErrNotFound  = errors.New("user not found")
)

type Store interface {
	CreateUser(email, hashedPassword string) error
	GetHashedPassword(email string) (string, error)
}
