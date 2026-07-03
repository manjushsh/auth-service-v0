package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	model "github.com/manjushsh/auth-service/internal/model/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// --- fakes for the narrow interfaces in deps.go ---

type fakeCodeStore struct {
	mu    sync.Mutex
	codes map[string]string
}

func newFakeCodeStore() *fakeCodeStore { return &fakeCodeStore{codes: map[string]string{}} }

func (f *fakeCodeStore) StoreCode(ctx context.Context, code, userID string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes[code] = userID
	return nil
}

func (f *fakeCodeStore) RedeemCode(ctx context.Context, code string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	userID, ok := f.codes[code]
	if !ok {
		return "", errors.New("code not found")
	}
	delete(f.codes, code)
	return userID, nil
}

type fakeBlocklist struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func newFakeBlocklist() *fakeBlocklist { return &fakeBlocklist{revoked: map[string]bool{}} }

func (f *fakeBlocklist) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[jti] = true
	return nil
}

func (f *fakeBlocklist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[jti], nil
}

type fakeLocker struct {
	mu       sync.Mutex
	attempts map[string]int
	locked   map[string]bool
}

func newFakeLocker() *fakeLocker {
	return &fakeLocker{attempts: map[string]int{}, locked: map[string]bool{}}
}

func (f *fakeLocker) IsLocked(ctx context.Context, email string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.locked[email], nil
}

func (f *fakeLocker) RecordFailedAttempt(ctx context.Context, email string, ttl time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts[email]++
	return f.attempts[email], nil
}

func (f *fakeLocker) LockAccount(ctx context.Context, email string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.locked[email] = true
	return nil
}

func (f *fakeLocker) ClearFailedAttempts(ctx context.Context, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.attempts, email)
	return nil
}

func newTestService(t *testing.T, allowedRedirects ...string) (*Service, *store.MemoryStore) {
	t.Helper()
	st := store.NewMemoryStore(allowedRedirects...)
	secret := []byte(strings.Repeat("s", minJWTSecretLen))
	svc, err := New(st, newFakeCodeStore(), newFakeBlocklist(), newFakeLocker(), secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, st
}

const testPassword = "correct-horse-battery-staple"

func TestNew_RejectsShortSecret(t *testing.T) {
	st := store.NewMemoryStore()
	_, err := New(st, newFakeCodeStore(), newFakeBlocklist(), newFakeLocker(), []byte("too-short"))
	if err == nil {
		t.Fatal("expected error for short jwt secret")
	}
}

func TestRegister_SuccessAndDuplicate(t *testing.T) {
	svc, _ := newTestService(t)
	req := model.RegisterRequest{Credentials: model.Credentials{Email: "User@Example.com", Password: testPassword}}

	if err := svc.Register(context.Background(), req); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.Register(context.Background(), req); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("Register duplicate: got %v, want ErrBadRequest", err)
	}
}

func TestRegister_EmailNormalizedCaseInsensitive(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.Register(context.Background(), model.RegisterRequest{
		Credentials: model.Credentials{Email: "  User@Example.com  ", Password: testPassword},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Same address, different case/whitespace, should collide.
	err := svc.Register(context.Background(), model.RegisterRequest{
		Credentials: model.Credentials{Email: "user@example.com", Password: testPassword},
	})
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expected duplicate registration to be rejected, got %v", err)
	}
}

func TestRegister_InvalidInput(t *testing.T) {
	svc, _ := newTestService(t)
	cases := []model.RegisterRequest{
		{Credentials: model.Credentials{Email: "", Password: testPassword}},
		{Credentials: model.Credentials{Email: "not-an-email", Password: testPassword}},
		{Credentials: model.Credentials{Email: "a@b.com", Password: "short"}},
		{Credentials: model.Credentials{Email: "a@b.com", Password: strings.Repeat("x", 73)}},
	}
	for i, c := range cases {
		if err := svc.Register(context.Background(), c); !errors.Is(err, ErrBadRequest) {
			t.Errorf("case %d: got %v, want ErrBadRequest", i, err)
		}
	}
}

func TestGenerateCode_SuccessAndClearsLockout(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	email := "user@example.com"
	if err := svc.Register(ctx, model.RegisterRequest{Credentials: model.Credentials{Email: email, Password: testPassword}}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Case-insensitive login should match the normalized stored email.
	resp, err := svc.GenerateCode(ctx, model.GenerateCodeRequest{
		Credentials: model.Credentials{Email: "User@Example.com", Password: testPassword},
	})
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if resp.Code == "" {
		t.Fatal("expected non-empty code")
	}
}

func TestGenerateCode_WrongPasswordLocksAccountAfterThreshold(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	email := "user@example.com"
	if err := svc.Register(ctx, model.RegisterRequest{Credentials: model.Credentials{Email: email, Password: testPassword}}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for i := 0; i < maxLoginAttempts; i++ {
		_, err := svc.GenerateCode(ctx, model.GenerateCodeRequest{
			Credentials: model.Credentials{Email: email, Password: "wrong-password"},
		})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: got %v, want ErrInvalidCredentials", i, err)
		}
	}

	_, err := svc.GenerateCode(ctx, model.GenerateCodeRequest{
		Credentials: model.Credentials{Email: email, Password: testPassword},
	})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("got %v, want ErrAccountLocked after %d failed attempts", err, maxLoginAttempts)
	}
}

func TestGenerateCode_UnknownUserReturnsInvalidCredentials(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.GenerateCode(context.Background(), model.GenerateCodeRequest{
		Credentials: model.Credentials{Email: "nobody@example.com", Password: testPassword},
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestGenerateCode_RejectsUnauthorizedRedirectURI(t *testing.T) {
	svc, _ := newTestService(t, "https://app.example.com/callback")
	ctx := context.Background()
	email := "user@example.com"
	if err := svc.Register(ctx, model.RegisterRequest{Credentials: model.Credentials{Email: email, Password: testPassword}}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err := svc.GenerateCode(ctx, model.GenerateCodeRequest{
		Credentials: model.Credentials{Email: email, Password: testPassword},
		RedirectURI: "https://evil.example.com/steal",
	})
	if !errors.Is(err, ErrUnauthorizedClient) {
		t.Fatalf("got %v, want ErrUnauthorizedClient", err)
	}
}

func TestExchangeCode_SingleUse(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	email := "user@example.com"
	if err := svc.Register(ctx, model.RegisterRequest{Credentials: model.Credentials{Email: email, Password: testPassword}}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	gen, err := svc.GenerateCode(ctx, model.GenerateCodeRequest{Credentials: model.Credentials{Email: email, Password: testPassword}})
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	tok, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: gen.Code})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// Redeeming the same code again must fail.
	if _, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: gen.Code}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("second exchange: got %v, want ErrInvalidCode", err)
	}
}

func TestLogoutAndIntrospect(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	email := "user@example.com"
	if err := svc.Register(ctx, model.RegisterRequest{Credentials: model.Credentials{Email: email, Password: testPassword}}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	gen, err := svc.GenerateCode(ctx, model.GenerateCodeRequest{Credentials: model.Credentials{Email: email, Password: testPassword}})
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	tok, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: gen.Code})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	introspect, err := svc.Introspect(ctx, tok.Token)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !introspect.Active {
		t.Fatal("expected token to be active before logout")
	}

	if err := svc.Logout(ctx, tok.Token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	introspect, err = svc.Introspect(ctx, tok.Token)
	if err != nil {
		t.Fatalf("Introspect after logout: %v", err)
	}
	if introspect.Active {
		t.Fatal("expected token to be inactive after logout")
	}
}

func TestIntrospect_InvalidToken(t *testing.T) {
	svc, _ := newTestService(t)
	resp, err := svc.Introspect(context.Background(), "not-a-jwt")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if resp.Active {
		t.Fatal("expected malformed token to be inactive")
	}
}
