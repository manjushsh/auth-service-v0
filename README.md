# auth-service

A Go HTTP service implementing authentication strategies. Currently supports Basic Auth with a PostgreSQL store. You can use APIs or Inbuilt login with `redirect_uri` if you have created a app in auth service for callback.
You need to extract one time code and get JWT with API call in your service.

### TODO
1. Multi-factor authentication — see [docs/MFA_PLAN.md](docs/MFA_PLAN.md)
2. Fine-grained authorization (the admin plane ships two roles; a permission model is still open)


See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a detailed architecture reference (request/data flow diagrams, Redis key space, full config reference, security posture, extension points), and [docs/ADMIN_API_PLAN.md](docs/ADMIN_API_PLAN.md) for the design behind the admin plane.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | **Liveness** — a constant; it touches no dependency, so it stays 200 through a database outage. For **readiness**, use `/admin/health` on the admin listener, which pings Postgres and Redis |
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Verify credentials, get a one-time code (alias of `/api/auth/code`) |
| POST | `/api/auth/code` | Same as `/api/auth/login` |
| POST | `/api/auth/token` | Exchange a one-time code for a JWT (must send the same `redirect_uri` the code was issued with, if any) |
| POST | `/api/auth/logout` | Revoke a JWT (`Authorization: Bearer <token>`) |
| POST | `/api/auth/introspect` | Check whether a JWT is active (`Authorization: Bearer <token>`) |
| POST | `/api/auth/password-reset` | Redeem an admin-issued reset token: `{reset_token, new_password}` |
| GET/POST | `/login` | Hosted login page/form (`redirect_uri` must belong to a registered client) |
| GET/POST | `/register` | Hosted registration page/form |

All `POST` routes above are rate limited per IP; `/api/auth/token`, `/logout` and `/introspect` allow more requests/minute than the credential-guessing routes.

## Admin API

A **separate listener**, off by default and bound to loopback (`ADMIN_API_ENABLED`,
`ADMIN_BIND_ADDR`, `ADMIN_PORT`). JSON and bearer-token only — never cookies.

Admin tokens carry a different JWT audience (`auth-service-admin`) than user tokens and are
minted only by `POST /admin/auth/login`. This matters: user JWTs are handed to third-party
relying applications by design, so an ordinary token must never open this plane.

| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/admin/auth/login` | — | `{email, password}` → admin token. Shares the account lockout |
| POST | `/admin/auth/logout` | support | Revoke the current admin token |
| GET | `/admin/auth/whoami` | support | Current actor and role |
| GET | `/admin/health` | — | Readiness: pings Postgres and Redis, 503 when either is down. Also answers on `/health` for probes that expect the bare path |
| GET | `/admin/clients` | support | List registered clients (keyset paginated) |
| POST | `/admin/clients` | admin | `{name, redirect_uri}` — replaces the manual `INSERT` |
| GET | `/admin/clients/{id}` | support | One client |
| PATCH | `/admin/clients/{id}` | admin | `{name}` only — see the rotation note below |
| POST | `/admin/clients/{id}/disable` | admin | Soft delete; stops new logins immediately |
| POST | `/admin/clients/{id}/enable` | admin | Undo a disable |
| DELETE | `/admin/clients/{id}` | admin | Hard delete; body must echo `{redirect_uri}` |
| GET | `/admin/users?email=` | support | Search by exact email (keyset paginated) |
| GET | `/admin/users/{id}` | support | Account plus live lockout / session-revocation state |
| POST | `/admin/users/{id}/unlock` | support | Release a lockout. `{scope}` optional, idempotent |
| POST | `/admin/users/{id}/revoke-sessions` | support | Invalidate every token issued to the user |
| PATCH | `/admin/users/{id}` | admin | `{status}` and/or `{role}`; both revoke sessions |
| DELETE | `/admin/users/{id}` | admin | Hard delete; body must echo `{email}` |
| POST | `/admin/users/{id}/password-reset` | admin | Mint a single-use reset token to hand over out of band |
| GET | `/admin/audit` | admin | Append-only log; filter by `actor`, `target`, `action`, `from`, `to` |

Errors are structured: `{"error": {"code": "...", "message": "..."}}`.

**Roles.** `support` covers the high-volume recovery tasks (unlock, revoke sessions);
`admin` adds client management, user lifecycle and password reset. The split is deliberate —
password reset is the action that hands over a path into an account, so the role most people
hold cannot take one over on its own.

**Rotating a `redirect_uri`** is create-new → migrate the application → disable the old
client. It is not editable in place: authorization codes are bound to the literal string, so
changing it mid-flight would break every code in the air.

### Bootstrapping the first admin

Granting admin requires database access — which is exactly the privilege being granted — so
it is a one-shot CLI rather than an environment variable that would re-apply on every boot:

```bash
go run ./cmd/adminctl promote you@example.com admin
go run ./cmd/adminctl list
go run ./cmd/adminctl demote someone@example.com
```

Register the account through `/api/auth/register` first. Admin accounts have **no second
factor yet** (see [docs/MFA_PLAN.md](docs/MFA_PLAN.md)), so use a generated, long password
and keep `ADMIN_BIND_ADDR` on loopback.

Under Docker, run it inside the app container — `adminctl` needs the database, which is only
reachable from there. It is built into the `prod` image; in `dev`, `go run` it:

```bash
docker compose exec app go run ./cmd/adminctl promote you@example.com admin   # dev
docker compose exec app adminctl promote you@example.com admin                # prod
```

**A container's loopback is its own**, so the `ADMIN_BIND_ADDR=127.0.0.1` default would make
the admin plane unreachable even from the host. `docker-compose.yml` therefore binds it
container-wide and publishes the port to the **host's** loopback only
(`127.0.0.1:8081:8081`) — the same boundary, expressed one layer out. Set
`ADMIN_API_ENABLED=true` in `.env` to switch it on.

```bash
# Then, from somewhere that can reach the admin port:
TOKEN=$(curl -s -X POST localhost:8081/admin/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"..."}' | jq -r .token)

curl -X POST localhost:8081/admin/clients -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-app","redirect_uri":"https://app.example.com/callback"}'
```

### Flow

1. `POST /api/auth/register` — create a user.
2. `POST /api/auth/login` (or `/code`) with `email`/`password` (+ optional `redirect_uri` belonging to a registered client) — returns a short-lived one-time `code`.
3. `POST /api/auth/token` with that `code` (and the same `redirect_uri` if one was used in step 2 — codes are bound to the redirect URI they were issued for, and a mismatched exchange invalidates the code) — returns a JWT (`expires_in` seconds).
4. Use the JWT as a bearer token; `POST /api/auth/introspect` to validate it, `POST /api/auth/logout` to revoke it early.

## Local dev

```bash
cp .env.example .env
docker compose up --build -d
docker compose logs -f app
```

**Use `--build`.** Without it, Compose reuses whatever image is already tagged
`auth-service-v0-app`, ignoring `build.target`. If that image was ever built from the `prod`
stage, the container starts with the prod command while the dev bind mount covers `/app` —
which surfaces as the fairly opaque `exec: "./server": stat ./server: no such file or
directory`. The prod stage now installs its binaries to `/usr/local/bin` so the two can no
longer collide, but a stale image is still a stale image.

If want to run server on host, while still using Docker for the database and Redis, set `SERVER_PORT` to a port on your host machine and `INSECURE_COOKIES` to `true`.
then still start docker with services and then run

```bash
go run ./cmd/server/
```

This uses the `dev` build target (`docker-compose.yml`'s `app.build.target`), which runs Air — it watches for `.go` file changes and rebuilds automatically inside the container via the bind-mounted source.

Air is configured to **poll** (`.air.docker.toml`) rather than rely on filesystem events:
inotify notifications do not cross a Docker Desktop bind mount on Windows or macOS, so
without polling Air reports that it is watching and then never rebuilds — edits look ignored
until you restart the container.

`INSECURE_COOKIES=true` in `.env.example` disables the `Secure` flag on the CSRF cookie so the hosted login/register pages work over plain HTTP locally. Leave it unset/`false` in any environment served over HTTPS.

`JWT_SECRET` must be at least 32 bytes — the service refuses to start otherwise.

## Prod

Set `app.build.target: prod` in `docker-compose.yml` (or build the `prod` stage directly), set `INSECURE_COOKIES=false` (or unset), then:

```bash
docker compose up --build -d
```
## Note
Clients (the allow-list of redirect URIs) are managed through the [Admin API](#admin-api).
The raw SQL below still works if the admin plane is disabled:
```bash
INSERT INTO clients (name, redirect_uri) VALUES ('my-app', 'https://app.example.com/callback');
```

## Cleanup

```bash
# stop containers
docker compose down

# stop containers and delete volumes (wipes DB)
docker compose down -v
```

## Migrations

Migrations run automatically on server start. Files live in `db/migrations/` and follow the `golang-migrate` naming convention:

```
001_create_users.up.sql
001_create_users.down.sql
```

## Tests

```bash
go test ./...
```
