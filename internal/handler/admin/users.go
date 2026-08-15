package admin

import (
	"net/http"

	"github.com/manjushsh/auth-service/internal/httpx"
	model "github.com/manjushsh/auth-service/internal/model/admin"
)

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	page, ok := parsePage(w, r)
	if !ok {
		return
	}

	resp, err := h.svc.ListUsers(r.Context(), r.URL.Query().Get("email"), page)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	resp, err := h.svc.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	req, ok := requireBody[model.UpdateUserRequest](w, r)
	if !ok {
		return
	}

	resp, err := h.svc.UpdateUser(r.Context(), callerFrom(r.Context()), r.PathValue("id"), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	// The body must echo the target's email; deletion is irreversible and a
	// mistyped id would otherwise hit the wrong account.
	req, ok := requireBody[model.DeleteUserRequest](w, r)
	if !ok {
		return
	}

	if err := h.svc.DeleteUser(r.Context(), callerFrom(r.Context()), r.PathValue("id"), req); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Unlock(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[model.UnlockRequest](w, r)
	if !ok {
		return
	}

	if err := h.svc.Unlock(r.Context(), callerFrom(r.Context()), r.PathValue("id"), req); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.RevokeSessions(r.Context(), callerFrom(r.Context()), r.PathValue("id")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) IssuePasswordReset(w http.ResponseWriter, r *http.Request) {
	resp, err := h.svc.IssuePasswordReset(r.Context(), callerFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	// The response carries a live credential; SecurityHeaders sets no-store
	// across the service so no intermediary may keep it.
	httpx.WriteJSON(w, http.StatusCreated, resp)
}
