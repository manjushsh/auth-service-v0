package admin

import (
	"net/http"

	"github.com/manjushsh/auth-service/internal/httpx"
	model "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	req, ok := requireBody[model.LoginRequest](w, r)
	if !ok {
		return
	}

	resp, err := h.svc.Login(r.Context(), req, metaFrom(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Logout(r.Context(), httpx.BearerToken(r)); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) WhoAmI(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.svc.WhoAmI(callerFrom(r.Context())))
}

// Health reports the real state of the process's dependencies, unlike the
// public /health, which returns a constant and would report healthy through a
// total database outage.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	healthy, components := h.svc.Health(r.Context())

	status, code := "ok", http.StatusOK
	if !healthy {
		status, code = "degraded", http.StatusServiceUnavailable
	}
	httpx.WriteJSON(w, code, model.HealthResponse{Status: status, Components: components})
}

func (h *Handler) ListAudit(w http.ResponseWriter, r *http.Request) {
	page, ok := parsePage(w, r)
	if !ok {
		return
	}
	from, ok := parseTime(w, r, "from")
	if !ok {
		return
	}
	to, ok := parseTime(w, r, "to")
	if !ok {
		return
	}

	q := r.URL.Query()
	resp, err := h.svc.ListAudit(r.Context(), store.AuditFilter{
		ActorID:  q.Get("actor"),
		TargetID: q.Get("target"),
		Action:   q.Get("action"),
		From:     from,
		To:       to,
		Page:     page,
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
