package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/manjushsh/auth-service/internal/httpx"
	model "github.com/manjushsh/auth-service/internal/model/auth"
	svc "github.com/manjushsh/auth-service/internal/service/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

type service interface {
	Register(ctx context.Context, req model.RegisterRequest) error
	GenerateCode(ctx context.Context, req model.GenerateCodeRequest) (model.GenerateCodeResponse, error)
	ExchangeCode(ctx context.Context, req model.ExchangeTokenRequest) (model.ExchangeTokenResponse, error)
	Logout(ctx context.Context, tokenString string) error
	Introspect(ctx context.Context, tokenString string) (model.IntrospectResponse, error)
	RedeemPasswordReset(ctx context.Context, req model.PasswordResetRequest, meta store.RequestMeta) error
}

type Handler struct {
	svc service
}

func New(s service) *Handler {
	return &Handler{svc: s}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.svc.Register(r.Context(), req); err != nil {
		if errors.Is(err, svc.ErrBadRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, model.RegisterResponse{Status: "created", Email: req.Email})
}

func (h *Handler) GenerateCode(w http.ResponseWriter, r *http.Request) {
	var req model.GenerateCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := h.svc.GenerateCode(r.Context(), req)
	if err != nil {
		if errors.Is(err, svc.ErrBadRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, svc.ErrInvalidCredentials) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, svc.ErrAccountLocked) {
			http.Error(w, "account locked, try again later", http.StatusTooManyRequests)
			return
		}
		if errors.Is(err, svc.ErrUnauthorizedClient) {
			http.Error(w, "unauthorized redirect_uri", http.StatusBadRequest)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) ExchangeToken(w http.ResponseWriter, r *http.Request) {
	var req model.ExchangeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := h.svc.ExchangeCode(r.Context(), req)
	if err != nil {
		if errors.Is(err, svc.ErrBadRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, svc.ErrInvalidCode) {
			http.Error(w, "invalid or expired code", http.StatusUnauthorized)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing or malformed authorization header", http.StatusBadRequest)
		return
	}

	if err := h.svc.Logout(r.Context(), token); err != nil {
		if errors.Is(err, svc.ErrInvalidToken) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing or malformed authorization header", http.StatusBadRequest)
		return
	}

	resp, err := h.svc.Introspect(r.Context(), token)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// RedeemPasswordReset completes an admin-issued password reset. It is
// unauthenticated: the single-use token is the credential.
func (h *Handler) RedeemPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req model.PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	meta := store.RequestMeta{
		RemoteAddr:   httpx.RemoteIP(r),
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		UserAgent:    r.Header.Get("User-Agent"),
	}
	if err := h.svc.RedeemPasswordReset(r.Context(), req, meta); err != nil {
		switch {
		case errors.Is(err, svc.ErrInvalidResetToken):
			http.Error(w, "invalid or expired reset token", http.StatusUnauthorized)
		case errors.Is(err, svc.ErrBadRequest):
			http.Error(w, "password does not meet requirements", http.StatusBadRequest)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func extractBearerToken(r *http.Request) string { return httpx.BearerToken(r) }

func writeJSON(w http.ResponseWriter, status int, v any) { httpx.WriteJSON(w, status, v) }
