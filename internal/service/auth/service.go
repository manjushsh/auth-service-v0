package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	model "github.com/manjushsh/auth-service/internal/model/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

const (
	codeTTL          = 60 * time.Second
	tokenTTL         = time.Hour
	maxLoginAttempts = 5
	lockoutDuration  = 15 * time.Minute
	minPasswordLen   = 8
	// bcrypt silently truncates/errors past 72 bytes; reject before hashing.
	maxPasswordLen = 72
	tokenIssuer    = "auth-service"
)

// dummyHash is compared against on unknown-user login attempts so that the
// GenerateCode response time doesn't reveal whether an email is registered.
var dummyHash = mustHash("not-a-real-password-used-for-timing-safety")

func mustHash(pw string) []byte {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return h
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrBadRequest         = errors.New("bad request")
	ErrInvalidCode        = errors.New("invalid or expired code")
	ErrInvalidToken       = errors.New("invalid token")
	ErrUnauthorizedClient = errors.New("unauthorized redirect URI")
	ErrAccountLocked      = errors.New("account locked due to too many failed attempts")
)

type Service struct {
	store     store.Store
	codeStore codeStore
	blocklist blocklist
	locker    locker
	jwtSecret []byte
}

// minJWTSecretLen is enforced so a trivially short secret can't be brute-forced.
const minJWTSecretLen = 32

func New(s store.Store, cs codeStore, bl blocklist, lk locker, jwtSecret []byte) (*Service, error) {
	if len(jwtSecret) < minJWTSecretLen {
		return nil, fmt.Errorf("jwt secret must be at least %d bytes", minJWTSecretLen)
	}
	return &Service{store: s, codeStore: cs, blocklist: bl, locker: lk, jwtSecret: jwtSecret}, nil
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

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
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

func (s *Service) GenerateCode(ctx context.Context, req model.GenerateCodeRequest) (model.GenerateCodeResponse, error) {
	email := normalizeEmail(req.Email)
	if email == "" || req.Password == "" {
		return model.GenerateCodeResponse{}, ErrBadRequest
	}

	if req.RedirectURI != "" {
		if err := s.ValidateRedirectURI(ctx, req.RedirectURI); err != nil {
			return model.GenerateCodeResponse{}, err
		}
	}

	locked, err := s.locker.IsLocked(ctx, email)
	if err != nil {
		return model.GenerateCodeResponse{}, err
	}
	if locked {
		return model.GenerateCodeResponse{}, ErrAccountLocked
	}

	u, err := s.store.GetUser(ctx, email)
	if err != nil {
		// Compare against a dummy hash so lookup-miss and bad-password paths
		// take a similar amount of time (timing-based user enumeration).
		bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		s.recordFailedAttempt(ctx, email)
		return model.GenerateCodeResponse{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		s.recordFailedAttempt(ctx, email)
		return model.GenerateCodeResponse{}, ErrInvalidCredentials
	}

	// Successful login, clear any previous failed attempts.
	if err := s.locker.ClearFailedAttempts(ctx, email); err != nil {
		log.Printf("auth: clear failed attempts for %s: %v", email, err)
	}

	code, err := randomString()
	if err != nil {
		return model.GenerateCodeResponse{}, err
	}

	if err := s.codeStore.StoreCode(ctx, code, u.ID, codeTTL); err != nil {
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

	userID, err := s.codeStore.RedeemCode(ctx, req.Code)
	if err != nil {
		return model.ExchangeTokenResponse{}, ErrInvalidCode
	}

	jti, err := randomString()
	if err != nil {
		return model.ExchangeTokenResponse{}, err
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		ID:        jti,
		Subject:   userID,
		Issuer:    tokenIssuer,
		Audience:  jwt.ClaimStrings{tokenIssuer},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return model.ExchangeTokenResponse{}, fmt.Errorf("sign token: %w", err)
	}

	return model.ExchangeTokenResponse{
		Token:     signed,
		ExpiresIn: int(tokenTTL.Seconds()),
	}, nil
}

func (s *Service) Logout(ctx context.Context, tokenString string) error {
	claims, err := s.parseToken(tokenString)
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
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return model.IntrospectResponse{Active: false}, nil
	}

	revoked, err := s.blocklist.IsRevoked(ctx, claims.ID)
	if err != nil {
		return model.IntrospectResponse{}, err
	}
	if revoked {
		return model.IntrospectResponse{Active: false}, nil
	}

	return model.IntrospectResponse{
		Active:    true,
		Subject:   claims.Subject,
		ExpiresAt: claims.ExpiresAt.Unix(),
	}, nil
}

func (s *Service) parseToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	},
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithAudience(tokenIssuer),
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || claims.ID == "" {
		return nil, errors.New("missing jti claim")
	}
	return claims, nil
}

func (s *Service) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	if err := s.store.ValidateRedirectURI(ctx, redirectURI); err != nil {
		return ErrUnauthorizedClient
	}
	return nil
}

// recordFailedAttempt increments the failure counter and locks the account on threshold.
func (s *Service) recordFailedAttempt(ctx context.Context, email string) {
	attempts, err := s.locker.RecordFailedAttempt(ctx, email, lockoutDuration)
	if err != nil {
		log.Printf("auth: record failed attempt for %s: %v", email, err)
		return
	}
	if attempts >= maxLoginAttempts {
		if err := s.locker.LockAccount(ctx, email, lockoutDuration); err != nil {
			log.Printf("auth: lock account %s: %v", email, err)
		}
	}
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
