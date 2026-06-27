package basic

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/manjushsh/auth-service/internal/model/basic"
	svc "github.com/manjushsh/auth-service/internal/service/basic"
)

type Handler struct {
	svc *svc.Service
}

func New(s *svc.Service) *Handler {
	return &Handler{svc: s}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	creds, err := parseCredentials(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.svc.Register(basic.RegisterRequest{Credentials: creds}); err != nil {
		if errors.Is(err, svc.ErrBadRequest) {
			// I am returning Bad Request instead of StatusConflict just to not expose registered emails
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, svc.ErrBadRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(basic.RegisterResponse{Status: "created", Email: creds.Email})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	creds, err := parseCredentials(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.svc.Login(basic.LoginRequest{Credentials: creds}); err != nil {
		if errors.Is(err, svc.ErrBadRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(basic.LoginResponse{Status: "logged in"})
}

// parseCredentials decodes email/password from JSON body or form data.
func parseCredentials(r *http.Request) (basic.Credentials, error) {
	var creds basic.Credentials

	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		err := json.NewDecoder(r.Body).Decode(&creds)
		return creds, err
	}

	if err := r.ParseForm(); err != nil {
		return creds, err
	}
	creds.Email = r.FormValue("email")
	creds.Password = r.FormValue("password")
	return creds, nil
}
