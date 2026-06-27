package basic

import (
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/manjushsh/auth-service/internal/model/basic"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrBadRequest         = errors.New("Bad Request")
)

type Service struct {
	mu    sync.RWMutex
	users map[string]string // email -> hashedPassword
}

func New() *Service {
	return &Service{users: make(map[string]string)}
}

func (s *Service) Register(req basic.RegisterRequest) error {
	if req.Email == "" || req.Password == "" {
		return ErrBadRequest
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[req.Email]; exists {
		return ErrBadRequest
	}

	s.users[req.Email] = string(hashed)
	return nil
}

func (s *Service) Login(req basic.LoginRequest) error {
	if req.Email == "" || req.Password == "" {
		return ErrBadRequest
	}

	s.mu.RLock()
	hashed, ok := s.users[req.Email]
	s.mu.RUnlock()

	if !ok {
		return ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(req.Password)); err != nil {
		return ErrInvalidCredentials
	}

	return nil
}
