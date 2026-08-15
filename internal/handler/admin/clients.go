package admin

import (
	"net/http"

	"github.com/manjushsh/auth-service/internal/httpx"
	model "github.com/manjushsh/auth-service/internal/model/admin"
)

func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	page, ok := parsePage(w, r)
	if !ok {
		return
	}

	resp, err := h.svc.ListClients(r.Context(), page)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetClient(w http.ResponseWriter, r *http.Request) {
	resp, err := h.svc.GetClient(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	req, ok := requireBody[model.CreateClientRequest](w, r)
	if !ok {
		return
	}

	resp, err := h.svc.CreateClient(r.Context(), callerFrom(r.Context()), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// UpdateClient renames a client. A redirect_uri change is refused with an
// explanation rather than ignored: it is the client's identity everywhere else
// in the system, so rotating it means create-new, migrate, disable-old.
func (h *Handler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	req, ok := requireBody[model.UpdateClientRequest](w, r)
	if !ok {
		return
	}
	if req.RedirectURI != nil {
		httpx.WriteError(w, http.StatusBadRequest, "immutable_field",
			"redirect_uri cannot be changed in place: create a new client, migrate the application, then disable this one")
		return
	}

	resp, err := h.svc.UpdateClient(r.Context(), callerFrom(r.Context()), r.PathValue("id"), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) DisableClient(w http.ResponseWriter, r *http.Request) {
	h.setClientDisabled(w, r, true)
}

func (h *Handler) EnableClient(w http.ResponseWriter, r *http.Request) {
	h.setClientDisabled(w, r, false)
}

func (h *Handler) setClientDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	resp, err := h.svc.SetClientDisabled(r.Context(), callerFrom(r.Context()), r.PathValue("id"), disabled)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	req, ok := requireBody[model.DeleteClientRequest](w, r)
	if !ok {
		return
	}

	if err := h.svc.DeleteClient(r.Context(), callerFrom(r.Context()), r.PathValue("id"), req); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
