package ui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"

	model "github.com/manjushsh/auth-service/internal/model/auth"
	svc "github.com/manjushsh/auth-service/internal/service/auth"
)

//go:embed templates/login.html
var loginHTML string

//go:embed templates/register.html
var registerHTML string

//go:embed static
var StaticFS embed.FS

var (
	loginTmpl    = template.Must(template.New("login").Parse(loginHTML))
	registerTmpl = template.Must(template.New("register").Parse(registerHTML))
)

type pageData struct {
	RedirectURI string
	CSRFToken   string
	Error       string
}

type service interface {
	ValidateRedirectURI(redirectURI string) error
	GenerateCode(ctx context.Context, req model.GenerateCodeRequest) (model.GenerateCodeResponse, error)
	Register(req model.RegisterRequest) error
}

type Handler struct {
	svc service
}

func New(s service) *Handler {
	return &Handler{svc: s}
}

func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")

	if err := h.svc.ValidateRedirectURI(redirectURI); err != nil {
		http.Error(w, "invalid or missing redirect_uri", http.StatusBadRequest)
		return
	}

	token, err := newCSRFToken(w)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	renderHTML(w, loginTmpl, pageData{RedirectURI: redirectURI, CSRFToken: token})
}

func (h *Handler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if !validCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if err := h.svc.ValidateRedirectURI(redirectURI); err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	resp, err := h.svc.GenerateCode(r.Context(), model.GenerateCodeRequest{
		Credentials: model.Credentials{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		},
		RedirectURI: redirectURI,
	})
	if err != nil {
		token, _ := newCSRFToken(w)
		msg := "invalid credentials"
		if errors.Is(err, svc.ErrBadRequest) {
			msg = "email and password are required"
		}
		renderHTML(w, loginTmpl, pageData{RedirectURI: redirectURI, CSRFToken: token, Error: msg})
		return
	}

	http.Redirect(w, r, resp.RedirectURL, http.StatusFound)
}

func (h *Handler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")

	if err := h.svc.ValidateRedirectURI(redirectURI); err != nil {
		http.Error(w, "invalid or missing redirect_uri", http.StatusBadRequest)
		return
	}

	token, err := newCSRFToken(w)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	renderHTML(w, registerTmpl, pageData{RedirectURI: redirectURI, CSRFToken: token})
}

func (h *Handler) RegisterSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if !validCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if err := h.svc.ValidateRedirectURI(redirectURI); err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	err := h.svc.Register(model.RegisterRequest{
		Credentials: model.Credentials{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		},
	})
	if err != nil {
		token, _ := newCSRFToken(w)
		msg := "registration failed"
		if errors.Is(err, svc.ErrBadRequest) {
			msg = "email already registered or invalid input"
		}
		renderHTML(w, registerTmpl, pageData{RedirectURI: redirectURI, CSRFToken: token, Error: msg})
		return
	}

	loginURL := "/login?" + url.Values{"redirect_uri": {redirectURI}}.Encode()
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func newCSRFToken(w http.ResponseWriter) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
	return token, nil
}

func validCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return false
	}
	return r.FormValue("csrf_token") == cookie.Value && cookie.Value != ""
}

func renderHTML(w http.ResponseWriter, tmpl *template.Template, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("renderHTML: template error: %v", err)
	}
}
