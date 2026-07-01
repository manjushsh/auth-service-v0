package auth

import "sync"

type MemoryStore struct {
	mu               sync.RWMutex
	users            map[string]string // email -> hashedPassword
	allowedRedirects map[string]bool
}

func NewMemoryStore(allowedRedirects ...string) *MemoryStore {
	allowed := make(map[string]bool, len(allowedRedirects))
	for _, uri := range allowedRedirects {
		allowed[uri] = true
	}
	return &MemoryStore{
		users:            make(map[string]string),
		allowedRedirects: allowed,
	}
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

func (s *MemoryStore) GetUser(email string) (UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hashed, ok := s.users[email]
	if !ok {
		return UserRecord{}, ErrNotFound
	}
	// Memory store has no UUIDs so use email as the identifier.
	return UserRecord{ID: email, PasswordHash: hashed}, nil
}

func (s *MemoryStore) ValidateRedirectURI(redirectURI string) error {
	// Empty allowlist means accept all, for local dev/testing.
	if len(s.allowedRedirects) == 0 || s.allowedRedirects[redirectURI] {
		return nil
	}
	return ErrNotFound
}
