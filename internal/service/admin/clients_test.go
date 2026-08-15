package admin

import (
	"context"
	"errors"
	"testing"

	model "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

const testRedirect = "https://app.example.com/callback"

func createClient(t *testing.T, h *harness, caller Caller, name, uri string) model.Client {
	t.Helper()
	c, err := h.admin.CreateClient(context.Background(), caller,
		model.CreateClientRequest{Name: name, RedirectURI: uri})
	if err != nil {
		t.Fatalf("CreateClient(%s): %v", uri, err)
	}
	return c
}

func TestCreateClient_RegistersARedirectURIAndAudits(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	ctx := context.Background()

	c := createClient(t, h, admin, "my-app", testRedirect)
	if c.ID == "" || c.Disabled {
		t.Fatalf("unexpected client: %+v", c)
	}
	if h.countAudit("client.create") != 1 {
		t.Fatalf("expected one create record, got %v", h.auditActions())
	}

	// This is the whole point of the endpoint: the URI now passes validation
	// without anyone running INSERT by hand.
	if err := h.auth.ValidateRedirectURI(ctx, testRedirect); err != nil {
		t.Fatalf("ValidateRedirectURI after create: %v", err)
	}
}

func TestCreateClient_RejectsDuplicatesAndMalformedURIs(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	ctx := context.Background()
	createClient(t, h, admin, "my-app", testRedirect)

	_, err := h.admin.CreateClient(ctx, admin, model.CreateClientRequest{Name: "copy", RedirectURI: testRedirect})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate redirect_uri: got %v, want ErrConflict", err)
	}

	// A typo should fail at creation, not at some user's first login.
	bad := []string{"", "not-a-url", "/relative/only", "ftp://app.example.com/cb", "https://app.example.com/cb#frag"}
	for _, uri := range bad {
		_, err := h.admin.CreateClient(ctx, admin, model.CreateClientRequest{Name: "x", RedirectURI: uri})
		if !errors.Is(err, ErrBadInput) {
			t.Errorf("CreateClient(%q): got %v, want ErrBadInput", uri, err)
		}
	}
	if _, err := h.admin.CreateClient(ctx, admin, model.CreateClientRequest{Name: "  ", RedirectURI: "https://ok.example.com/cb"}); !errors.Is(err, ErrBadInput) {
		t.Fatalf("blank name: got %v, want ErrBadInput", err)
	}
}

// redirect_uri is the client's identity everywhere else in the system — codes
// are bound to the literal string — so changing it in place would silently
// break every code in flight.
func TestUpdateClient_RenamesOnly(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	ctx := context.Background()
	c := createClient(t, h, admin, "my-app", testRedirect)

	updated, err := h.admin.UpdateClient(ctx, admin, c.ID, model.UpdateClientRequest{Name: ptr("renamed")})
	if err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if updated.Name != "renamed" || updated.RedirectURI != testRedirect {
		t.Fatalf("unexpected client after rename: %+v", updated)
	}

	_, err = h.admin.UpdateClient(ctx, admin, c.ID, model.UpdateClientRequest{
		Name: ptr("x"), RedirectURI: ptr("https://elsewhere.example.com/cb"),
	})
	if !errors.Is(err, ErrBadInput) {
		t.Fatalf("redirect_uri change: got %v, want ErrBadInput", err)
	}
}

func TestDisableClient_StopsLoginsAndFreesTheURI(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	ctx := context.Background()
	c := createClient(t, h, admin, "my-app", testRedirect)

	if _, err := h.admin.SetClientDisabled(ctx, admin, c.ID, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := h.auth.ValidateRedirectURI(ctx, testRedirect); err == nil {
		t.Fatal("a disabled client must not validate")
	}

	// Uniqueness applies to live rows only, so the URI can be re-registered —
	// which is how a rotation completes.
	replacement := createClient(t, h, admin, "my-app-v2", testRedirect)
	if replacement.ID == c.ID {
		t.Fatal("expected a distinct replacement client")
	}
	if err := h.auth.ValidateRedirectURI(ctx, testRedirect); err != nil {
		t.Fatalf("ValidateRedirectURI after re-registration: %v", err)
	}

	// And disabling is reversible.
	if _, err := h.admin.SetClientDisabled(ctx, admin, replacement.ID, false); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
}

func TestDeleteClient_RequiresMatchingRedirectURI(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	ctx := context.Background()
	c := createClient(t, h, admin, "my-app", testRedirect)

	err := h.admin.DeleteClient(ctx, admin, c.ID, model.DeleteClientRequest{RedirectURI: "https://wrong.example.com/cb"})
	if !errors.Is(err, ErrConfirmationMismatch) {
		t.Fatalf("wrong confirmation: got %v, want ErrConfirmationMismatch", err)
	}
	if _, err := h.admin.GetClient(ctx, c.ID); err != nil {
		t.Fatalf("client must survive a refused delete: %v", err)
	}

	if err := h.admin.DeleteClient(ctx, admin, c.ID, model.DeleteClientRequest{RedirectURI: testRedirect}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := h.admin.GetClient(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
}

// Pagination is keyset, so a page boundary must neither skip nor duplicate.
func TestListClients_PaginatesWithoutGapsOrDuplicates(t *testing.T) {
	h := newHarness(t)
	admin, _ := h.admins()
	ctx := context.Background()

	const total = 5
	for i := range total {
		createClient(t, h, admin, "app", "https://app.example.com/cb/"+string(rune('a'+i)))
	}

	seen := map[string]bool{}
	page := store.Page{Limit: 2}
	for range total + 1 {
		resp, err := h.admin.ListClients(ctx, page)
		if err != nil {
			t.Fatalf("ListClients: %v", err)
		}
		for _, c := range resp.Clients {
			if seen[c.ID] {
				t.Fatalf("client %s returned on two pages", c.ID)
			}
			seen[c.ID] = true
		}
		if resp.NextCursor == "" {
			break
		}
		cursor, err := store.DecodeCursor(resp.NextCursor)
		if err != nil {
			t.Fatalf("DecodeCursor: %v", err)
		}
		page.Cursor = cursor
	}
	if len(seen) != total {
		t.Fatalf("saw %d clients across all pages, want %d", len(seen), total)
	}
}

// Every mutation must leave exactly one record: no unaudited privileged change,
// and no double-counting either.
func TestEveryMutationWritesExactlyOneAuditRecord(t *testing.T) {
	h := newHarness(t)
	admin, support := h.admins()
	victim := h.user("victim@example.com", store.RoleUser)
	ctx := context.Background()

	before := len(h.store.AuditEvents())

	c := createClient(t, h, admin, "my-app", testRedirect)
	mutations := []struct {
		name string
		run  func() error
	}{
		{"client.update", func() error {
			_, err := h.admin.UpdateClient(ctx, admin, c.ID, model.UpdateClientRequest{Name: ptr("renamed")})
			return err
		}},
		{"client.disable", func() error {
			_, err := h.admin.SetClientDisabled(ctx, admin, c.ID, true)
			return err
		}},
		{"user.unlock", func() error {
			return h.admin.Unlock(ctx, support, victim.ID, model.UnlockRequest{})
		}},
		{"user.revoke_sessions", func() error {
			return h.admin.RevokeSessions(ctx, support, victim.ID)
		}},
		{"user.suspend", func() error {
			_, err := h.admin.UpdateUser(ctx, admin, victim.ID, model.UpdateUserRequest{Status: ptr(store.StatusSuspended)})
			return err
		}},
		{"user.password_reset.issued", func() error {
			_, err := h.admin.IssuePasswordReset(ctx, admin, victim.ID)
			return err
		}},
		{"user.delete", func() error {
			return h.admin.DeleteUser(ctx, admin, victim.ID, model.DeleteUserRequest{Email: victim.Email})
		}},
	}

	// One for the create above, plus one per mutation.
	want := before + 1 + len(mutations)
	for _, m := range mutations {
		if err := m.run(); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if h.countAudit(m.name) != 1 {
			t.Errorf("%s: got %d audit records, want exactly 1", m.name, h.countAudit(m.name))
		}
	}
	if got := len(h.store.AuditEvents()); got != want {
		t.Fatalf("total audit records = %d, want %d (actions: %v)", got, want, h.auditActions())
	}
}
