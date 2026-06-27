package basic

import (
	"errors"

	"golang.org/x/crypto/bcrypt"

	model "github.com/manjushsh/auth-service/internal/model/basic"
	store "github.com/manjushsh/auth-service/internal/store/basic"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrBadRequest         = errors.New("bad request")
)

type Service struct {
	store store.Store
}

func New(s store.Store) *Service {
	return &Service{store: s}
}

func (s *Service) Register(req model.RegisterRequest) error {
	if req.Email == "" || req.Password == "" {
		return ErrBadRequest
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if err := s.store.CreateUser(req.Email, string(hashed)); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return ErrBadRequest
		}
		return err
	}
	return nil
}

func (s *Service) Login(req model.LoginRequest) error {
	if req.Email == "" || req.Password == "" {
		return ErrBadRequest
	}

	hashed, err := s.store.GetHashedPassword(req.Email)
	if err != nil {
		return ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(req.Password)); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}
