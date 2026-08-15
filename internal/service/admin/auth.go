package admin

import (
	"context"
	"errors"
	"log/slog"
	"time"

	model "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
	"github.com/manjushsh/auth-service/internal/token"
)

// Login exchanges admin credentials for an admin-audience token.
//
// There is no authorization code and no redirect_uri in this flow: the token is
// handed straight back to the caller and never passes through a relying
// application, which is what keeps admin authority out of third-party hands.
func (s *Service) Login(ctx context.Context, req model.LoginRequest, meta store.RequestMeta) (model.LoginResponse, error) {
	// VerifyPassword owns the lockout check, the bcrypt comparison, the
	// suspension check and the failure accounting. Calling it — rather than
	// comparing a hash here — is what stops this endpoint becoming an
	// unthrottled password oracle that routes around MAX_LOGIN_ATTEMPTS.
	u, err := s.accounts.VerifyPassword(ctx, req.Email, req.Password)
	if err != nil {
		s.recordLoginFailure(ctx, req.Email, meta, err)
		return model.LoginResponse{}, err
	}

	if !store.IsPrivileged(u.Role) {
		s.recordLoginFailure(ctx, req.Email, meta, ErrUnauthenticated)
		return model.LoginResponse{}, ErrUnauthenticated
	}

	minted, err := s.tokens.Mint(token.Grant{
		Subject:  u.ID,
		Audience: token.AudienceAdmin,
		TTL:      s.cfg.TokenTTL,
		Role:     u.Role,
	})
	if err != nil {
		return model.LoginResponse{}, err
	}

	caller := Caller{UserID: u.ID, Email: u.Email, Role: u.Role, Meta: meta}
	if err := s.record(ctx, caller.event("admin.login.ok", userTarget(u))); err != nil {
		return model.LoginResponse{}, err
	}

	return model.LoginResponse{
		Token:     minted.Raw,
		ExpiresIn: int(s.cfg.TokenTTL.Seconds()),
		Role:      u.Role,
	}, nil
}

// recordLoginFailure reports a rejected admin login.
//
// It always logs, but only writes a durable audit row when the address belongs
// to an account that may actually use this plane. The split matters in both
// directions: `POST /admin/auth/login` is unauthenticated, so recording every
// attempt would let anyone who can reach the port fill the audit table with
// rows about accounts that do not exist — while a repeated failure against a
// *real* admin is one of the most important things the log can hold.
//
// Either way it is best-effort: a failed login must still return its
// authentication error to the caller even if the recording fails. Successful
// privileged actions are the ones that fail closed.
func (s *Service) recordLoginFailure(ctx context.Context, email string, meta store.RequestMeta, cause error) {
	slog.Warn("admin login failed",
		"email", email, "remote_addr", meta.RemoteAddr, "reason", cause.Error())

	u, err := s.store.GetUser(ctx, normalizeEmail(email))
	if err != nil || !store.IsPrivileged(u.Role) {
		return // unknown or unprivileged address: logged, not recorded
	}

	ev := store.AuditEvent{
		ActorID:     u.ID,
		ActorEmail:  u.Email,
		ActorRole:   u.Role,
		Action:      "admin.login.failed",
		TargetType:  store.TargetUser,
		TargetID:    u.ID,
		TargetLabel: u.Email,
		Result:      store.AuditDenied,
		Metadata:    map[string]any{"reason": cause.Error()},
		RequestMeta: meta,
	}
	if err := s.store.InsertAudit(ctx, ev); err != nil {
		slog.Error("record admin login failure", "error", err)
	}
}

func (s *Service) Logout(ctx context.Context, raw string) error {
	claims, err := s.tokens.Parse(raw, token.AudienceAdmin)
	if err != nil {
		return ErrUnauthenticated
	}
	// Only the token's *remaining* lifetime needs blocklisting; past that it
	// stops verifying on its own.
	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining <= 0 {
		return nil
	}
	return s.blocklist.Revoke(ctx, claims.ID, remaining)
}

// Authenticate resolves a bearer token to a Caller, or fails.
//
// Note what it does *not* do: it never calls the public plane's Introspect,
// which reports an invalid token as a successful call returning Active:false —
// a shape that makes the obvious `if err != nil` handler fail open. Every
// outcome here that is not a valid, live, privileged, active account is an
// error.
//
// The role is read from the database rather than taken from the token's claim,
// so demoting a compromised admin takes effect on their next request instead of
// at token expiry.
func (s *Service) Authenticate(ctx context.Context, raw string, meta store.RequestMeta) (Caller, error) {
	if raw == "" {
		return Caller{}, rejected(meta, "", "no bearer token")
	}

	claims, err := s.verifier.Verify(ctx, raw, token.AudienceAdmin)
	switch {
	case errors.Is(err, token.ErrInvalidToken):
		// Covers a forged signature, an expired token and — the case worth
		// watching for — a valid *user-audience* token being tried here.
		return Caller{}, rejected(meta, "", "token rejected: "+err.Error())
	case errors.Is(err, token.ErrTokenInactive):
		return Caller{}, rejected(meta, "", "token revoked or superseded")
	case err != nil:
		return Caller{}, err // infrastructure failure: fail closed, but as a 500
	}

	u, err := s.store.GetUserByID(ctx, claims.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return Caller{}, rejected(meta, claims.Subject, "subject no longer exists")
	}
	if err != nil {
		return Caller{}, err
	}

	if u.Suspended() {
		return Caller{}, rejected(meta, u.ID, "account suspended")
	}
	if !store.IsPrivileged(u.Role) {
		return Caller{}, rejected(meta, u.ID, "role is no longer privileged")
	}

	return Caller{UserID: u.ID, Email: u.Email, Role: u.Role, Meta: meta}, nil
}

// rejected logs a failed authentication and returns the single error every
// caller sees.
//
// These go to the structured log rather than the audit table on purpose: the
// caller is by definition unauthenticated, so there is no actor to attribute a
// row to, and anyone able to reach the port could otherwise write to the audit
// table at will. Denials by an *authenticated* caller — the role checks in
// Authorize — are attributable and do get recorded.
func rejected(meta store.RequestMeta, subject, reason string) error {
	slog.Warn("admin authentication rejected",
		"reason", reason, "subject", subject,
		"remote_addr", meta.RemoteAddr, "user_agent", meta.UserAgent)
	return ErrUnauthenticated
}

// Authorize checks a caller against a route's required role.
//
// A denial here is attributable — the caller proved who they are and then asked
// for something above their role — so it is recorded durably, unlike the
// authentication failures above.
//
// If that recording fails the caller gets a 500 rather than a 403. The request
// is refused either way; surfacing the audit failure is the deliberate choice,
// consistent with the rule that an unaudited privileged interaction is worse
// than a failed one.
func (s *Service) Authorize(ctx context.Context, c Caller, want string) error {
	if store.RoleSatisfies(c.Role, want) {
		return nil
	}
	if err := s.Deny(ctx, c, "authz.denied", "requires role "+want); err != nil {
		return err
	}
	return ErrForbidden
}

func (s *Service) WhoAmI(c Caller) model.WhoAmIResponse {
	return model.WhoAmIResponse{UserID: c.UserID, Email: c.Email, Role: c.Role}
}
