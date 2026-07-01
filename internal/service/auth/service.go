package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
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
)

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

func New(s store.Store, cs codeStore, bl blocklist, lk locker, jwtSecret []byte) *Service {
	return &Service{store: s, codeStore: cs, blocklist: bl, locker: lk, jwtSecret: jwtSecret}
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

func (s *Service) GenerateCode(ctx context.Context, req model.GenerateCodeRequest) (model.GenerateCodeResponse, error) {
	if req.Email == "" || req.Password == "" {
		return model.GenerateCodeResponse{}, ErrBadRequest
	}

	locked, err := s.locker.IsLocked(ctx, req.Email)
	if err != nil {
		return model.GenerateCodeResponse{}, err
	}
	if locked {
		return model.GenerateCodeResponse{}, ErrAccountLocked
	}

	u, err := s.store.GetUser(req.Email)
	if err != nil {
		s.recordFailedAttempt(ctx, req.Email)
		return model.GenerateCodeResponse{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		s.recordFailedAttempt(ctx, req.Email)
		return model.GenerateCodeResponse{}, ErrInvalidCredentials
	}

	// Successful login — clear any previous failed attempts.
	s.locker.ClearFailedAttempts(ctx, req.Email)

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
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || claims.ID == "" {
		return nil, errors.New("missing jti claim")
	}
	return claims, nil
}

func (s *Service) ValidateRedirectURI(redirectURI string) error {
	if err := s.store.ValidateRedirectURI(redirectURI); err != nil {
		return ErrUnauthorizedClient
	}
	return nil
}

// recordFailedAttempt increments the failure counter and locks the account on threshold.
func (s *Service) recordFailedAttempt(ctx context.Context, email string) {
	attempts, err := s.locker.RecordFailedAttempt(ctx, email)
	if err != nil {
		return
	}
	if attempts >= maxLoginAttempts {
		s.locker.LockAccount(ctx, email, lockoutDuration)
	}
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
