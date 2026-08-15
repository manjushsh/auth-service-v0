package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	model "github.com/manjushsh/auth-service/internal/model/auth"
	"github.com/manjushsh/auth-service/internal/secret"
	store "github.com/manjushsh/auth-service/internal/store/auth"
	"github.com/manjushsh/auth-service/internal/store/memory"
	"github.com/manjushsh/auth-service/internal/token"
)

// testDeps is the wiring every test shares, exposed so individual tests can
// reach into a collaborator without rebuilding the graph.
//
// Note there are no hand-rolled fakes: memory.Store mirrors the Redis
// implementation method for method, so these tests exercise the same paths
// production takes rather than a simplification of them.
type testDeps struct {
	store    *store.MemoryStore
	volatile *memory.Store
	tokens   *token.Manager
	clock    *testClock
	service  *Service
}

// testClock drives every time source in the graph — the service, the token
// manager and the volatile store — from one place. Session revocation is
// second-granular, so tests that need to cross a second boundary advance this
// rather than sleeping.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	return &testClock{at: time.Now().UTC().Truncate(time.Second)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func testSecret() []byte { return []byte(strings.Repeat("s", token.MinSecretLen)) }

func newTestDeps(t *testing.T, allowedRedirects ...string) *testDeps {
	t.Helper()

	st := store.NewMemoryStore(allowedRedirects...)
	vol := memory.New()
	clock := newTestClock()
	vol.SetClock(clock.Now)

	tokens, err := token.NewManager(testSecret(), secret.NewToken, clock.Now)
	if err != nil {
		t.Fatalf("token.NewManager: %v", err)
	}

	deps := newDeps(st, vol, tokens)
	deps.Now = clock.Now

	// MinCost keeps the bcrypt-heavy tests fast.
	svc, err := New(deps, Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &testDeps{store: st, volatile: vol, tokens: tokens, clock: clock, service: svc}
}

// newDeps builds a fully-wired dependency set, so tests that need to drop one
// collaborator start from something valid.
func newDeps(st *store.MemoryStore, vol *memory.Store, tokens *token.Manager) Deps {
	return Deps{
		Store:     st,
		Codes:     vol,
		Blocklist: vol,
		Locker:    vol,
		Epochs:    vol,
		Resets:    vol,
		Audit:     st,
		Tokens:    tokens,
	}
}

func newTestService(t *testing.T, allowedRedirects ...string) (*Service, *store.MemoryStore) {
	t.Helper()
	d := newTestDeps(t, allowedRedirects...)
	return d.service, d.store
}

const testPassword = "correct-horse-battery-staple"

// registerUser creates an account and returns its stored record.
func registerUser(t *testing.T, svc *Service, st *store.MemoryStore, email string) store.UserRecord {
	t.Helper()
	err := svc.Register(context.Background(), model.RegisterRequest{
		Credentials: model.Credentials{Email: email, Password: testPassword},
	})
	if err != nil {
		t.Fatalf("Register(%s): %v", email, err)
	}
	u, err := st.GetUser(context.Background(), email)
	if err != nil {
		t.Fatalf("GetUser(%s): %v", email, err)
	}
	return u
}

func TestNewManager_RejectsShortSecret(t *testing.T) {
	if _, err := token.NewManager([]byte("too-short"), secret.NewToken, time.Now); err == nil {
		t.Fatal("expected error for short jwt secret")
	}
}

// A nil dependency reaching production is a silent security bypass, so the
// constructor must refuse rather than build a half-wired service.
func TestNew_RejectsNilDependency(t *testing.T) {
	tokens, err := token.NewManager(testSecret(), secret.NewToken, time.Now)
	if err != nil {
		t.Fatalf("token.NewManager: %v", err)
	}
	full := newDeps(store.NewMemoryStore(), memory.New(), tokens)

	cases := map[string]func(*Deps){
		"Store":     func(d *Deps) { d.Store = nil },
		"Codes":     func(d *Deps) { d.Codes = nil },
		"Blocklist": func(d *Deps) { d.Blocklist = nil },
		"Locker":    func(d *Deps) { d.Locker = nil },
		"Epochs":    func(d *Deps) { d.Epochs = nil },
		"Resets":    func(d *Deps) { d.Resets = nil },
		"Audit":     func(d *Deps) { d.Audit = nil },
		"Tokens":    func(d *Deps) { d.Tokens = nil },
	}
	for name, drop := range cases {
		t.Run(name, func(t *testing.T) {
			d := full
			drop(&d)
			if _, err := New(d, Config{BcryptCost: bcrypt.MinCost}); err == nil {
				t.Fatalf("expected New to reject a nil %s", name)
			}
		})
	}
}

func TestNew_RejectsOutOfRangeBcryptCost(t *testing.T) {
	tokens, err := token.NewManager(testSecret(), secret.NewToken, time.Now)
	if err != nil {
		t.Fatalf("token.NewManager: %v", err)
	}
	deps := newDeps(store.NewMemoryStore(), memory.New(), tokens)
	if _, err := New(deps, Config{BcryptCost: bcrypt.MaxCost + 1}); err == nil {
		t.Fatal("expected error for out-of-range bcrypt cost")
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

	for i := 0; i < DefaultMaxLoginAttempts; i++ {
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
		t.Fatalf("got %v, want ErrAccountLocked after %d failed attempts", err, DefaultMaxLoginAttempts)
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

func TestExchangeCode_BoundToRedirectURI(t *testing.T) {
	const redirect = "https://app.example.com/callback"
	svc, _ := newTestService(t, redirect)
	ctx := context.Background()
	email := "user@example.com"
	if err := svc.Register(ctx, model.RegisterRequest{Credentials: model.Credentials{Email: email, Password: testPassword}}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	newCode := func() string {
		t.Helper()
		gen, err := svc.GenerateCode(ctx, model.GenerateCodeRequest{
			Credentials: model.Credentials{Email: email, Password: testPassword},
			RedirectURI: redirect,
		})
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		return gen.Code
	}

	// Missing redirect_uri at exchange must fail.
	if _, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: newCode()}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("exchange without redirect_uri: got %v, want ErrInvalidCode", err)
	}

	// Wrong redirect_uri at exchange must fail.
	if _, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{
		Code:        newCode(),
		RedirectURI: "https://evil.example.com/steal",
	}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("exchange with wrong redirect_uri: got %v, want ErrInvalidCode", err)
	}

	// A failed exchange must burn the code.
	code := newCode()
	if _, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: code}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("mismatched exchange: got %v, want ErrInvalidCode", err)
	}
	if _, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: code, RedirectURI: redirect}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("retry after failed exchange: got %v, want ErrInvalidCode (code burned)", err)
	}

	// Matching redirect_uri succeeds.
	tok, err := svc.ExchangeCode(ctx, model.ExchangeTokenRequest{Code: newCode(), RedirectURI: redirect})
	if err != nil {
		t.Fatalf("exchange with matching redirect_uri: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("expected non-empty token")
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
