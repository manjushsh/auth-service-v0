// Package token owns JWT minting and parsing for every plane of the service.
//
// It exists so the *audience split* is structural rather than conventional:
// user tokens and admin tokens are signed with the same secret but are minted
// and parsed under different audiences, and Parse will not accept a token
// issued for a different one. See docs/ADMIN_API_PLAN.md §3.2 for why that
// matters — user JWTs are handed to third-party relying applications by design,
// so an admin's ordinary token must never open the admin plane.
package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// Issuer is the single `iss` value for every token this service mints.
	Issuer = "auth-service"

	// AudienceUser is carried by tokens issued through the authorization-code
	// flow — the ones relying applications receive.
	AudienceUser = "auth-service"
	// AudienceAdmin is carried only by tokens minted by the admin login
	// endpoint, which has no redirect flow and no third party in it.
	AudienceAdmin = "auth-service-admin"

	// MinSecretLen is enforced so a trivially short secret can't be brute-forced.
	MinSecretLen = 32
)

var ErrInvalidToken = errors.New("invalid token")

// Claims is the full claim set. RegisteredClaims covers exp/iss/aud/jti/iat/sub;
// the extras are ours.
type Claims struct {
	jwt.RegisteredClaims
	// Role is present on admin tokens only, and is advisory — authorization
	// re-reads the role from the database on every request so a demotion takes
	// effect immediately rather than at token expiry.
	Role string `json:"role,omitempty"`
	// AMR records which authentication factors were used (RFC 8176). Reserved
	// for the MFA plan; nil today.
	AMR []string `json:"amr,omitempty"`
}

// Grant describes a token to mint.
type Grant struct {
	Subject  string
	Audience string
	TTL      time.Duration
	Role     string
	AMR      []string
}

// Minted is the result of Mint. ID and the timestamps are returned because
// callers need them for revocation bookkeeping without re-parsing.
type Minted struct {
	Raw       string
	ID        string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Manager mints and parses tokens. It performs no I/O; see Verifier for the
// checks that need Redis.
type Manager struct {
	secret []byte
	newID  func() (string, error)
	now    func() time.Time
}

// NewManager validates the signing secret once, at startup, so no caller has to.
func NewManager(secret []byte, newID func() (string, error), now func() time.Time) (*Manager, error) {
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("jwt secret must be at least %d bytes", MinSecretLen)
	}
	if newID == nil {
		return nil, errors.New("token: newID is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{secret: secret, newID: newID, now: now}, nil
}

func (m *Manager) Mint(g Grant) (Minted, error) {
	if g.Subject == "" || g.Audience == "" || g.TTL <= 0 {
		return Minted{}, errors.New("token: subject, audience and a positive ttl are required")
	}

	jti, err := m.newID()
	if err != nil {
		return Minted{}, fmt.Errorf("generate jti: %w", err)
	}

	now := m.now()
	expires := now.Add(g.TTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   g.Subject,
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{g.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
		Role: g.Role,
		AMR:  g.AMR,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return Minted{}, fmt.Errorf("sign token: %w", err)
	}
	return Minted{Raw: signed, ID: jti, IssuedAt: now, ExpiresAt: expires}, nil
}

// Parse verifies signature, expiry, issuer and — crucially — that the token was
// minted for the given audience. A user token presented to the admin plane
// fails here, and vice versa.
func (m *Manager) Parse(raw, audience string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(raw, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	},
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(audience),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || claims.ID == "" || claims.Subject == "" {
		return nil, fmt.Errorf("%w: missing jti or sub claim", ErrInvalidToken)
	}
	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("%w: missing iat claim", ErrInvalidToken)
	}
	return claims, nil
}
