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
	email, password, err := parseCredentials(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := basic.RegisterRequest{Email: email, Password: password}
	if err := h.svc.Register(req); err != nil {
		if errors.Is(err, svc.ErrUserExists) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(basic.RegisterResponse{Status: "created", Email: email})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	email, password, err := parseCredentials(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := basic.LoginRequest{Email: email, Password: password}
	if err := h.svc.Login(req); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(basic.LoginResponse{Status: "logged in"})
}

// parseCredentials reads email and password from either a JSON body or form data.
func parseCredentials(r *http.Request) (email, password string, err error) {
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "application/json") {
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
			return
		}
		return body.Email, body.Password, nil
	}

	if err = r.ParseForm(); err != nil {
		return
	}
	return r.FormValue("email"), r.FormValue("password"), nil
}
