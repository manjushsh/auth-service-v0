// Command adminctl grants and revokes admin roles directly against the
// database.
//
// It exists to solve the bootstrap problem — promoting the first admin requires
// an admin — without weakening anything: granting admin already requires
// database access, which is precisely the privilege being granted. It is
// explicit, one-shot, and visible in shell history and database logs.
//
// The alternative, an ADMIN_BOOTSTRAP_EMAIL environment variable applied at
// startup, is deliberately not implemented. It would turn "can edit config"
// into "can grant myself admin, silently, at the next restart" — a strictly
// larger group than "can write to the database" — and being re-applied on every
// boot means demoting a compromised admin would be undone by the next deploy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"github.com/manjushsh/auth-service/db"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

const timeout = 15 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "adminctl:", err)
		os.Exit(1)
	}
}

func usage() string {
	return strings.TrimSpace(`
usage: adminctl <command> [args]

  list                     show every account with a privileged role
  promote <email> <role>   grant "support" or "admin"
  demote  <email>          return an account to the ordinary "user" role

Requires DATABASE_URL. Granting admin requires database access by design.`)
}

func run() error {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		return errors.New(usage())
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is not set")
	}
	database, err := db.Open(dsn)
	if err != nil {
		return err
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	st := store.NewPostgresStore(database)

	switch args[0] {
	case "list":
		return list(ctx, st)
	case "promote":
		if len(args) != 3 {
			return errors.New(usage())
		}
		return setRole(ctx, st, args[1], args[2])
	case "demote":
		if len(args) != 2 {
			return errors.New(usage())
		}
		return setRole(ctx, st, args[1], store.RoleUser)
	default:
		return errors.New(usage())
	}
}

func list(ctx context.Context, st *store.PostgresStore) error {
	// A dedicated query, not a page of users filtered in memory: this is the
	// break-glass tool, and "no privileged accounts" must mean there are none
	// rather than none in the newest page.
	users, err := st.ListPrivilegedUsers(ctx)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		fmt.Println("no privileged accounts; promote one with: adminctl promote <email> admin")
		return nil
	}
	for _, u := range users {
		fmt.Printf("%s\t%-8s\t%-9s\t%s\n", u.ID, u.Role, u.Status, u.Email)
	}
	return nil
}

func setRole(ctx context.Context, st *store.PostgresStore, email, role string) error {
	if !store.ValidRole(role) {
		return fmt.Errorf("unknown role %q (want user, support or admin)", role)
	}

	email = strings.ToLower(strings.TrimSpace(email))
	u, err := st.GetUser(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no account for %s — register it first, then promote", email)
	}
	if err != nil {
		return err
	}
	if u.Role == role {
		fmt.Printf("%s is already %s\n", email, role)
		return nil
	}

	ev := store.AuditEvent{
		ActorEmail:  "adminctl",
		ActorRole:   "cli",
		Action:      "user.role_change",
		TargetType:  store.TargetUser,
		TargetID:    u.ID,
		TargetLabel: u.Email,
		Result:      store.AuditOK,
		Metadata:    map[string]any{"from": u.Role, "to": role, "via": "adminctl"},
	}
	if err := st.SetUserRole(ctx, u.ID, role, ev); err != nil {
		if errors.Is(err, store.ErrLastAdmin) {
			return fmt.Errorf("%s is the last remaining admin; promote another account first", email)
		}
		return err
	}

	fmt.Printf("%s: %s -> %s\n", email, u.Role, role)
	if store.IsPrivileged(role) {
		fmt.Println("reminder: admin accounts have no second factor yet. Use a generated, " +
			"long password stored in a password manager, and keep ADMIN_BIND_ADDR on loopback.")
	}
	return nil
}
