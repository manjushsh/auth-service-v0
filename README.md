# auth-service

A Go HTTP service implementing authentication strategies. Currently supports Basic Auth with a PostgreSQL store. You can use APIs or Inbuilt login with `redirect_uri` if you have created a app in auth service for callback.
You need to extract one time code and get JWT with API call in your service.

### TODO
1. Role (Authorization) 
2. Can't think any other feature as of now.. will add later


## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Verify credentials, get a one-time code (alias of `/api/auth/code`) |
| POST | `/api/auth/code` | Same as `/api/auth/login` |
| POST | `/api/auth/token` | Exchange a one-time code for a JWT |
| POST | `/api/auth/logout` | Revoke a JWT (`Authorization: Bearer <token>`) |
| POST | `/api/auth/introspect` | Check whether a JWT is active (`Authorization: Bearer <token>`) |
| GET/POST | `/login` | Hosted login page/form (`redirect_uri` must belong to a registered client) |
| GET/POST | `/register` | Hosted registration page/form |

All `POST` routes above are rate limited per IP; `/api/auth/token`, `/logout` and `/introspect` allow more requests/minute than the credential-guessing routes.

### Flow

1. `POST /api/auth/register` — create a user.
2. `POST /api/auth/login` (or `/code`) with `email`/`password` (+ optional `redirect_uri` belonging to a registered client) — returns a short-lived one-time `code`.
3. `POST /api/auth/token` with that `code` — returns a JWT (`expires_in` seconds).
4. Use the JWT as a bearer token; `POST /api/auth/introspect` to validate it, `POST /api/auth/logout` to revoke it early.

## Local dev

```bash
cp .env.example .env
docker compose up --build -d
docker compose logs -f app
```

This uses the `dev` build target (`docker-compose.yml`'s `app.build.target`), which runs Air — it watches for `.go` file changes and rebuilds automatically inside the container via the bind-mounted source.

`INSECURE_COOKIES=true` in `.env.example` disables the `Secure` flag on the CSRF cookie so the hosted login/register pages work over plain HTTP locally. Leave it unset/`false` in any environment served over HTTPS.

`JWT_SECRET` must be at least 32 bytes — the service refuses to start otherwise.

## Prod

Set `app.build.target: prod` in `docker-compose.yml` (or build the `prod` stage directly), set `INSECURE_COOKIES=false` (or unset), then:

```bash
docker compose up --build -d
```
## Note
Add client entry which is allowed to use auth service
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
