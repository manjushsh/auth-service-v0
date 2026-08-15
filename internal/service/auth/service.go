package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	model "github.com/manjushsh/auth-service/internal/model/auth"
	"github.com/manjushsh/auth-service/internal/secret"
	store "github.com/manjushsh/auth-service/internal/store/auth"
	"github.com/manjushsh/auth-service/internal/token"
)

const (
	minPasswordLen = 8
	// bcrypt silently truncates/errors past 72 bytes; reject before hashing.
	maxPasswordLen = 72
)

// Defaults for the tunables in Config; a zero Config gets all of these.
const (
	DefaultCodeTTL          = 60 * time.Second
	DefaultTokenTTL         = time.Hour
	DefaultMaxLoginAttempts = 5
	DefaultLockoutDuration  = 15 * time.Minute
	DefaultBcryptCost       = bcrypt.DefaultCost
	DefaultPasswordResetTTL = 15 * time.Minute
)

// Config holds the tunable knobs of the service. Zero values fall back to
// the Default* constants, so Config{} is a valid production configuration.
type Config struct {
	CodeTTL          time.Duration // lifetime of a one-time login code
	TokenTTL         time.Duration // lifetime of an issued JWT
	MaxLoginAttempts int           // failed logins before the account locks
	LockoutDuration  time.Duration // how long a locked account stays locked
	BcryptCost       int           // bcrypt cost used when hashing passwords
	PasswordResetTTL time.Duration // lifetime of an admin-issued reset token
}

func (c Config) withDefaults() Config {
	if c.CodeTTL <= 0 {
		c.CodeTTL = DefaultCodeTTL
	}
	if c.TokenTTL <= 0 {
		c.TokenTTL = DefaultTokenTTL
	}
	if c.MaxLoginAttempts <= 0 {
		c.MaxLoginAttempts = DefaultMaxLoginAttempts
	}
	if c.LockoutDuration <= 0 {
		c.LockoutDuration = DefaultLockoutDuration
	}
	if c.BcryptCost <= 0 {
		c.BcryptCost = DefaultBcryptCost
	}
	if c.PasswordResetTTL <= 0 {
		c.PasswordResetTTL = DefaultPasswordResetTTL
	}
	return c
}

// epochTTL is how long a session-revocation watermark needs to outlive the
// tokens it invalidates. Once every token predating a bump has expired on its
// own, the watermark carries no information — so a generous multiple of the
// token lifetime is both correct and self-cleaning.
func (c Config) epochTTL() time.Duration { return 2 * c.TokenTTL }

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrBadRequest         = errors.New("bad request")
	ErrInvalidCode        = errors.New("invalid or expired code")
	ErrInvalidToken       = errors.New("invalid token")
	ErrUnauthorizedClient = errors.New("unauthorized redirect URI")
	ErrAccountLocked      = errors.New("account locked due to too many failed attempts")
	ErrInvalidResetToken  = errors.New("invalid or expired reset token")
)

// Deps are the service's collaborators.
//
// This is a struct rather than a positional argument list because several of
// these are interfaces the compiler cannot tell apart at a call site:
// transposing two of them would produce a program that builds cleanly and
// fails at runtime in a security-critical path.
type Deps struct {
	Store     store.Store
	Codes     codeStore
	Blocklist blocklist
	Locker    locker
	Epochs    epochStore
	Resets    resetStore
	Audit     auditStore
	Tokens    *token.Manager
	Now       func() time.Time // nil -> time.Now
}

type Service struct {
	store     store.Store
	codes     codeStore
	blocklist blocklist
	locker    locker
	epochs    epochStore
	resets    resetStore
	audit     auditStore
	tokens    *token.Manager
	verifier  *token.Verifier
	cfg       Config
	now       func() time.Time
	// dummyHash is compared against on unknown-user login attempts so that the
	// GenerateCode response time doesn't reveal whether an email is registered.
	// It is hashed at cfg.BcryptCost so both paths cost the same.
	dummyHash []byte
}

func New(d Deps, cfg Config) (*Service, error) {
	// A nil dependency here is a silent security bypass in production, and this
	// constructor is the only place that can catch it cheaply.
	for name, dep := range map[string]any{
		"Store": d.Store, "Codes": d.Codes, "Blocklist": d.Blocklist,
		"Locker": d.Locker, "Epochs": d.Epochs, "Resets": d.Resets,
		"Audit": d.Audit,
	} {
		if dep == nil {
			return nil, fmt.Errorf("auth service: %s dependency is required", name)
		}
	}
	// Checked separately because it is a concrete pointer: a nil *token.Manager
	// boxed into `any` is not == nil, so the loop above cannot see it.
	if d.Tokens == nil {
		return nil, errors.New("auth service: Tokens dependency is required")
	}

	cfg = cfg.withDefaults()
	if cfg.BcryptCost < bcrypt.MinCost || cfg.BcryptCost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}
	dummyHash, err := bcrypt.GenerateFromPassword([]byte("not-a-real-password-used-for-timing-safety"), cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("generate dummy hash: %w", err)
	}

	now := d.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		store:     d.Store,
		codes:     d.Codes,
		blocklist: d.Blocklist,
		locker:    d.Locker,
		epochs:    d.Epochs,
		resets:    d.Resets,
		audit:     d.Audit,
		tokens:    d.Tokens,
		verifier: &token.Verifier{
			Manager:   d.Tokens,
			Blocklist: d.Blocklist,
			Epochs:    d.Epochs,
		},
		cfg:       cfg,
		now:       now,
		dummyHash: dummyHash,
	}, nil
}

// normalizeEmail trims whitespace and lowercases so that the same address
// can't be registered/locked-out under multiple case variants.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateCredentials(email, password string) error {
	if email == "" || password == "" {
		return ErrBadRequest
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return ErrBadRequest
	}
	return validatePassword(password)
}

func validatePassword(password string) error {
	if len(password) < minPasswordLen || len(password) > maxPasswordLen {
		return ErrBadRequest
	}
	return nil
}

func (s *Service) Register(ctx context.Context, req model.RegisterRequest) error {
	email := normalizeEmail(req.Email)
	if err := validateCredentials(email, req.Password); err != nil {
		return err
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.cfg.BcryptCost)
	if err != nil {
		return err
	}

	if err := s.store.CreateUser(ctx, email, string(hashed)); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return ErrBadRequest
		}
		return err
	}
	return nil
}

// VerifyPassword performs the lockout check, the bcrypt comparison and the
// failure accounting as a single unit.
//
// Every password check in the service routes through here — never a bare
// bcrypt.CompareHashAndPassword — so no endpoint can become an unthrottled
// password-guessing oracle that bypasses MAX_LOGIN_ATTEMPTS. The admin plane's
// login depends on this method for exactly that reason.
func (s *Service) VerifyPassword(ctx context.Context, email, password string) (store.UserRecord, error) {
	email = normalizeEmail(email)
	if email == "" || password == "" {
		return store.UserRecord{}, ErrBadRequest
	}

	locked, err := s.locker.IsLocked(ctx, store.LockScopePassword, email)
	if err != nil {
		return store.UserRecord{}, err
	}
	if locked {
		return store.UserRecord{}, ErrAccountLocked
	}

	u, err := s.store.GetUser(ctx, email)
	if err != nil {
		// Compare against a dummy hash so lookup-miss and bad-password paths
		// take a similar amount of time (timing-based user enumeration).
		bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		s.recordFailedAttempt(ctx, email)
		return store.UserRecord{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		s.recordFailedAttempt(ctx, email)
		return store.UserRecord{}, ErrInvalidCredentials
	}

	// The suspension check sits *after* the bcrypt comparison on purpose:
	// checking earlier would skip the hash and make suspended accounts
	// detectable by response time, defeating the dummy-hash work above. The
	// error is deliberately indistinguishable from a wrong password.
	if u.Suspended() {
		return store.UserRecord{}, ErrInvalidCredentials
	}

	// Successful login, clear any previous failed attempts.
	if err := s.locker.ClearFailedAttempts(ctx, store.LockScopePassword, email); err != nil {
		slog.Error("clear failed attempts", "email", email, "error", err)
	}
	return u, nil
}

func (s *Service) GenerateCode(ctx context.Context, req model.GenerateCodeRequest) (model.GenerateCodeResponse, error) {
	if req.RedirectURI != "" {
		if err := s.ValidateRedirectURI(ctx, req.RedirectURI); err != nil {
			return model.GenerateCodeResponse{}, err
		}
	}

	u, err := s.VerifyPassword(ctx, req.Email, req.Password)
	if err != nil {
		return model.GenerateCodeResponse{}, err
	}

	code, err := secret.NewToken()
	if err != nil {
		return model.GenerateCodeResponse{}, err
	}

	// Bind the code to the redirect_uri it was issued for so it can only be
	// exchanged by the client that received it, and stamp it with the issue
	// time so ExchangeCode can compare against a session revocation.
	if err := s.codes.StoreCode(ctx, code, u.ID, req.RedirectURI, s.now(), s.cfg.CodeTTL); err != nil {
		return model.GenerateCodeResponse{}, err
	}

	resp := model.GenerateCodeResponse{Code: code}
	if req.RedirectURI != "" {
		parsed, err := url.Parse(req.RedirectURI)
		if err == nil {
			q := parsed.Query()
			q.Set("code", code)
			parsed.RawQuery = q.Encode()
			resp.RedirectURL = parsed.String()
		}
	}
	return resp, nil
}

func (s *Service) ExchangeCode(ctx context.Context, req model.ExchangeTokenRequest) (model.ExchangeTokenResponse, error) {
	if req.Code == "" {
		return model.ExchangeTokenResponse{}, ErrBadRequest
	}

	userID, redirectURI, issuedAt, err := s.codes.RedeemCode(ctx, req.Code)
	if err != nil {
		return model.ExchangeTokenResponse{}, ErrInvalidCode
	}

	// The code is bound to the redirect_uri it was issued for; a stolen code
	// can't be exchanged without also knowing it. RedeemCode has already
	// consumed the code, so a mismatched attempt burns it (OAuth requires
	// invalidating a code on a failed exchange).
	if redirectURI != req.RedirectURI {
		return model.ExchangeTokenResponse{}, ErrInvalidCode
	}

	// Re-validate the client at redemption, so disabling a client takes effect
	// within CODE_TTL rather than only for logins that start afterwards.
	if redirectURI != "" {
		if err := s.ValidateRedirectURI(ctx, redirectURI); err != nil {
			return model.ExchangeTokenResponse{}, ErrInvalidCode
		}
	}

	// A code minted before a session revocation must not redeem into a fresh
	// token — otherwise "revoke all sessions" has a hole one CODE_TTL wide,
	// because the new token's iat would be *after* the epoch.
	epoch, err := s.epochs.Epoch(ctx, userID)
	if err != nil {
		return model.ExchangeTokenResponse{}, err
	}
	// Truncated to the epoch's own one-second granularity before comparing, and
	// compared with <=, for the same reason Introspect does: a code minted in
	// the same second as the revocation must not survive it.
	if !epoch.IsZero() && !issuedAt.Truncate(time.Second).After(epoch) {
		return model.ExchangeTokenResponse{}, ErrInvalidCode
	}

	minted, err := s.tokens.Mint(token.Grant{
		Subject:  userID,
		Audience: token.AudienceUser,
		TTL:      s.cfg.TokenTTL,
	})
	if err != nil {
		return model.ExchangeTokenResponse{}, err
	}

	return model.ExchangeTokenResponse{
		Token:     minted.Raw,
		ExpiresIn: int(s.cfg.TokenTTL.Seconds()),
	}, nil
}

func (s *Service) Logout(ctx context.Context, tokenString string) error {
	// Parsed without the liveness checks on purpose: a token that is already
	// dead should still log out cleanly rather than return an error the caller
	// cannot act on.
	claims, err := s.tokens.Parse(tokenString, token.AudienceUser)
	if err != nil {
		return ErrInvalidToken
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return nil // already expired, nothing to revoke
	}
	return s.blocklist.Revoke(ctx, claims.ID, ttl)
}

func (s *Service) Introspect(ctx context.Context, tokenString string) (model.IntrospectResponse, error) {
	claims, err := s.verifier.Verify(ctx, tokenString, token.AudienceUser)
	switch {
	case errors.Is(err, token.ErrInvalidToken), errors.Is(err, token.ErrTokenInactive):
		return model.IntrospectResponse{Active: false}, nil
	case err != nil:
		// An infrastructure failure is not evidence of an inactive token, and
		// must not be reported as one.
		return model.IntrospectResponse{}, err
	}

	return model.IntrospectResponse{
		Active:    true,
		Subject:   claims.Subject,
		ExpiresAt: claims.ExpiresAt.Unix(),
	}, nil
}

func (s *Service) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	if err := s.store.ValidateRedirectURI(ctx, redirectURI); err != nil {
		return ErrUnauthorizedClient
	}
	return nil
}

// RevokeSessions invalidates every token already issued to a user.
//
// This is the only mechanism that can express "revoke everything for user X":
// the blocklist is keyed by jti and nothing indexes which jtis belong to whom.
// Suspension, deletion, role changes and password resets all route through it.
func (s *Service) RevokeSessions(ctx context.Context, userID string) error {
	return s.epochs.BumpEpoch(ctx, userID, s.cfg.epochTTL())
}

// SessionsRevokedAt reports when a user's sessions were last revoked; a zero
// time means never.
func (s *Service) SessionsRevokedAt(ctx context.Context, userID string) (time.Time, error) {
	return s.epochs.Epoch(ctx, userID)
}

// LockState reports whether an account is currently locked out in any scope.
func (s *Service) LockState(ctx context.Context, email string) (bool, error) {
	email = normalizeEmail(email)
	for _, scope := range store.LockScopes {
		locked, err := s.locker.IsLocked(ctx, scope, email)
		if err != nil {
			return false, err
		}
		if locked {
			return true, nil
		}
	}
	return false, nil
}

// Unlock clears the lockout state for an account across the given scopes.
// Passing no scopes clears all of them.
func (s *Service) Unlock(ctx context.Context, email string, scopes ...string) error {
	if len(scopes) == 0 {
		scopes = store.LockScopes
	}
	for _, scope := range scopes {
		if err := s.locker.Unlock(ctx, scope, normalizeEmail(email)); err != nil {
			return err
		}
	}
	return nil
}

// recordFailedAttempt increments the failure counter and locks the account on threshold.
func (s *Service) recordFailedAttempt(ctx context.Context, email string) {
	attempts, err := s.locker.RecordFailedAttempt(ctx, store.LockScopePassword, email, s.cfg.LockoutDuration)
	if err != nil {
		slog.Error("record failed attempt", "email", email, "error", err)
		return
	}
	if attempts >= s.cfg.MaxLoginAttempts {
		if err := s.locker.LockAccount(ctx, store.LockScopePassword, email, s.cfg.LockoutDuration); err != nil {
			slog.Error("lock account", "email", email, "error", err)
		}
	}
}
