package basic

import "sync"

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

func (s *MemoryStore) GetHashedPassword(email string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hashed, ok := s.users[email]
	if !ok {
		return "", ErrNotFound
	}
	return hashed, nil
}
