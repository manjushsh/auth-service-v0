package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	model "github.com/manjushsh/auth-service/internal/model/auth"
	svc "github.com/manjushsh/auth-service/internal/service/auth"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// fakeService lets each test stub exactly the call it exercises.
type fakeService struct {
	registerErr      error
	generateCodeErr  error
	generateCode     model.GenerateCodeResponse
	exchangeErr      error
	exchange         model.ExchangeTokenResponse
	logoutErr        error
	introspect       model.IntrospectResponse
	introspectErr    error
	passwordResetErr error
}

func (f *fakeService) Register(ctx context.Context, req model.RegisterRequest) error {
	return f.registerErr
}

func (f *fakeService) GenerateCode(ctx context.Context, req model.GenerateCodeRequest) (model.GenerateCodeResponse, error) {
	return f.generateCode, f.generateCodeErr
}

func (f *fakeService) ExchangeCode(ctx context.Context, req model.ExchangeTokenRequest) (model.ExchangeTokenResponse, error) {
	return f.exchange, f.exchangeErr
}

func (f *fakeService) Logout(ctx context.Context, tokenString string) error {
	return f.logoutErr
}

func (f *fakeService) Introspect(ctx context.Context, tokenString string) (model.IntrospectResponse, error) {
	return f.introspect, f.introspectErr
}

func (f *fakeService) RedeemPasswordReset(ctx context.Context, req model.PasswordResetRequest, meta store.RequestMeta) error {
	return f.passwordResetErr
}

func TestGenerateCode_ErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantHTTP int
	}{
		{"bad request", svc.ErrBadRequest, http.StatusBadRequest},
		{"invalid credentials", svc.ErrInvalidCredentials, http.StatusUnauthorized},
		{"account locked", svc.ErrAccountLocked, http.StatusTooManyRequests},
		{"unauthorized redirect", svc.ErrUnauthorizedClient, http.StatusBadRequest},
		{"unknown error", errors.New("boom"), http.StatusInternalServerError},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := New(&fakeService{generateCodeErr: c.err})
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"a@b.com","password":"pw"}`))
			rec := httptest.NewRecorder()

			h.GenerateCode(rec, req)

			if rec.Code != c.wantHTTP {
				t.Errorf("got status %d, want %d", rec.Code, c.wantHTTP)
			}
		})
	}
}

func TestRegister_MalformedBody(t *testing.T) {
	h := New(&fakeService{})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLogout_MissingBearerToken(t *testing.T) {
	h := New(&fakeService{})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLogout_InvalidToken(t *testing.T) {
	h := New(&fakeService{logoutErr: svc.ErrInvalidToken})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestIntrospect_Success(t *testing.T) {
	h := New(&fakeService{introspect: model.IntrospectResponse{Active: true, Subject: "user-1"}})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/introspect", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	rec := httptest.NewRecorder()

	h.Introspect(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"active":true`) {
		t.Errorf("unexpected body: %s", rec.Body.String())
	}
}
