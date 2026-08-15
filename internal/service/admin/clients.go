package admin

import (
	"context"
	"net/url"
	"strings"

	model "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// Client management replaces the raw `INSERT INTO clients` the README
// documents — the one workflow that currently requires production database
// write access just to onboard a relying application.

func (s *Service) ListClients(ctx context.Context, page store.Page) (model.ClientList, error) {
	page = page.Normalize()

	clients, err := s.store.ListClients(ctx, page)
	if err != nil {
		return model.ClientList{}, err
	}

	out := make([]model.Client, 0, len(clients))
	for _, c := range clients {
		out = append(out, toClientView(c))
	}
	return model.ClientList{
		Clients: out,
		NextCursor: nextCursor(clients, page.Limit, func(c store.Client) store.Cursor {
			return store.Cursor{Time: c.CreatedAt, ID: c.ID}
		}),
	}, nil
}

func (s *Service) GetClient(ctx context.Context, id string) (model.Client, error) {
	c, err := s.mustClient(ctx, id)
	if err != nil {
		return model.Client{}, err
	}
	return toClientView(c), nil
}

func (s *Service) CreateClient(ctx context.Context, caller Caller, req model.CreateClientRequest) (model.Client, error) {
	name := strings.TrimSpace(req.Name)
	redirectURI := strings.TrimSpace(req.RedirectURI)
	if name == "" {
		return model.Client{}, ErrBadInput
	}
	if err := validateRedirectURI(redirectURI); err != nil {
		return model.Client{}, err
	}

	// The audit target is built from the request because the row does not
	// exist yet; the store fills in nothing else that matters here.
	ev := caller.event("client.create", target{
		Type:  store.TargetClient,
		Label: redirectURI,
	})
	created, err := s.store.CreateClient(ctx, name, redirectURI, ev)
	if err != nil {
		return model.Client{}, translate(err)
	}
	return toClientView(created), nil
}

// UpdateClient renames a client. It cannot change redirect_uri: that string is
// the client's identity everywhere else — codes are bound to it and the
// exchange compares it verbatim — so editing it mid-flight would silently break
// every code in the air.
func (s *Service) UpdateClient(ctx context.Context, caller Caller, id string, req model.UpdateClientRequest) (model.Client, error) {
	if req.RedirectURI != nil {
		return model.Client{}, ErrBadInput
	}
	if req.Name == nil || strings.TrimSpace(*req.Name) == "" {
		return model.Client{}, ErrBadInput
	}

	c, err := s.mustClient(ctx, id)
	if err != nil {
		return model.Client{}, err
	}

	name := strings.TrimSpace(*req.Name)
	ev := caller.event("client.update", clientTarget(c))
	ev.Metadata = map[string]any{"from": c.Name, "to": name}
	if err := s.store.RenameClient(ctx, c.ID, name, ev); err != nil {
		return model.Client{}, translate(err)
	}
	c.Name = name
	return toClientView(c), nil
}

// SetClientDisabled is the soft delete.
//
// Disabling stops new logins immediately and stops in-flight codes redeeming
// within CODE_TTL, because ExchangeCode re-validates the client. Tokens already
// issued through it stay valid until they expire — revoking those needs a
// per-client token index, which does not exist.
func (s *Service) SetClientDisabled(ctx context.Context, caller Caller, id string, disabled bool) (model.Client, error) {
	c, err := s.mustClient(ctx, id)
	if err != nil {
		return model.Client{}, err
	}

	action := "client.enable"
	if disabled {
		action = "client.disable"
	}
	if err := s.store.SetClientDisabled(ctx, c.ID, disabled, caller.event(action, clientTarget(c))); err != nil {
		return model.Client{}, translate(err)
	}
	return s.GetClient(ctx, c.ID)
}

func (s *Service) DeleteClient(ctx context.Context, caller Caller, id string, req model.DeleteClientRequest) error {
	c, err := s.mustClient(ctx, id)
	if err != nil {
		return err
	}
	if err := confirm(strings.TrimSpace(req.RedirectURI), c.RedirectURI); err != nil {
		return err
	}
	return translate(s.store.DeleteClient(ctx, c.ID, caller.event("client.delete", clientTarget(c))))
}

func toClientView(c store.Client) model.Client {
	return model.Client{
		ID:          c.ID,
		Name:        c.Name,
		RedirectURI: c.RedirectURI,
		Disabled:    c.Disabled(),
		DisabledAt:  c.DisabledAt,
		CreatedAt:   c.CreatedAt,
	}
}

// validateRedirectURI rejects the shapes that could never work as a callback,
// so a typo fails at creation rather than at a user's first login.
func validateRedirectURI(raw string) error {
	if raw == "" {
		return ErrBadInput
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return ErrBadInput
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ErrBadInput
	}
	// A fragment is never sent to the server and a code cannot be appended
	// meaningfully to one.
	if u.Fragment != "" {
		return ErrBadInput
	}
	return nil
}
