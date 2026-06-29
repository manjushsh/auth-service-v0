package auth

import (
	"sync"

	model "github.com/manjushsh/auth-service/internal/model/auth"
)

type MemoryStore struct {
	mu    sync.RWMutex
	users map[string]string // email -> hashedPassword
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: make(map[string]string)}
}

func (s *MemoryStore) CreateUser(email, hashedPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[email]; exists {
		return ErrDuplicate
	}
	s.users[email] = hashedPassword
	return nil
}

func (s *MemoryStore) GetUser(email string) (model.UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hashed, ok := s.users[email]
	if !ok {
		return model.UserRecord{}, ErrNotFound
	}
	// Memory store has no UUIDs so use email as the identifier.
	return model.UserRecord{ID: email, PasswordHash: hashed}, nil
}
