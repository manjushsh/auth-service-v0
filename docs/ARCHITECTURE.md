# auth-service — Architecture & Reference

A standalone Go authentication service implementing an OAuth-style authorization-code flow: email/password login produces a short-lived one-time code, which is exchanged for a JWT. It's meant to be run once and shared across multiple applications ("clients"), each identified by an allow-listed `redirect_uri`.

This document describes how the service is built, how data flows through it, and how to operate it. For a quick start and the plain endpoint table, see the top-level [README.md](../README.md). For a prioritized list of known gaps and suggested improvements, see [IMPROVEMENTS.md](../IMPROVEMENTS.md).

---

## 1. High-level design

```
                    ┌──────────────────────────────────────────┐
                    │                 main.go                  │
                    │  load config → connect DB/Redis → serve  │
                    └───────────────────┬────────────────────--┘
                                        │
                                routes.go (newHandler)
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        │                               │                               │
  middleware chain              internal/handler/auth          internal/handler/ui
  (Security, MaxBytes,           (JSON API)                    (HTML forms + CSRF)
   Logger, RateLimit)                    │                               │
                                        └───────────────┬───────────────┘
                                                        │
                                        internal/service/auth.Service
                                        (business logic, all validation,
                                        JWT signing, lockout policy)
                                                        │
                        ┌───────────────────────────────┼───────────────────────────────┐
                        │                               │                               │
                internal/store/auth              internal/store/redis            golang-jwt
                (Postgres: users, clients)   (codes, blocklist, lockout,          (HS256 signing)
                                                rate-limit counters)
```

**Layering rule:** handlers depend on a narrow `service` interface (defined in the handler package, satisfied by `*Service`); the service depends on narrow `store`/`codeStore`/`blocklist`/`locker` interfaces (defined in `internal/service/auth/deps.go`). Nothing above the service package imports Postgres or Redis directly — swapping either store means writing a new adapter, not touching business logic. This is also why `internal/store/auth/memory.go` (an in-memory `Store`) and the `fake*` types in `service_test.go` exist: they let the service and handler layers be unit-tested with no real database or Redis.

## 2. Directory layout

```
cmd/server/            Composition root: config loading, dependency wiring, HTTP server lifecycle
  main.go                Connects to Postgres/Redis, runs migrations, starts/stops the server
  config.go              Reads and validates environment variables into a config struct
  routes.go              Builds the http.ServeMux, wires middleware and handlers

db/
  db.go                  sql.DB setup (pool tuning, ping) + embedded-migration runner
  migrations/             golang-migrate SQL files (embedded into the binary via go:embed)

internal/
  model/auth/            Wire types (request/response JSON structs) shared by handler + service
  service/auth/          Business logic: registration, login, code issuance/exchange, JWT, lockout
    service.go             Service implementation
    deps.go                 Narrow interfaces the service depends on (codeStore, blocklist, locker)
  store/auth/            User/client persistence
    store.go                Store interface + shared errors (ErrDuplicate, ErrNotFound)
    postgres.go             Postgres implementation (lib/pq)
    memory.go               In-memory implementation, used only by tests
  store/redis/            Redis-backed implementations of codeStore, blocklist, locker, rate limiter
    store.go                Shared client wrapper, key helpers, atomic INCR+EXPIRE Lua script
    code.go                 One-time login codes (GETDEL for single-use redemption)
    blocklist.go            Revoked-JWT set (by jti)
    locker.go               Failed-login counters + account lock flag
    ratelimit.go             Fixed-window request counter
  handler/auth/           JSON API handlers (thin: decode → call service → map errors → encode)
  handler/ui/             Server-rendered login/register pages (HTML templates + CSRF)
  middleware/             Cross-cutting HTTP concerns: security headers, body size limit, logging,
                          per-IP rate limiting

docs/                   This document
IMPROVEMENTS.md         Open findings and recommended enhancements (security, reliability, roadmap)
```

## 3. Request lifecycle

Every request passes through the middleware chain in this order (outermost first, from `routes.go`):

1. **`SecurityHeaders`** — sets `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy` on every response.
2. **`MaxBytes`** — wraps the request body in `http.MaxBytesReader` capped at 1 MiB, so an oversized body is rejected before it's read.
3. **`Logger`** — records method, path, response status, and duration for every request.
4. **`RateLimit`** (per-route) — a fixed-window counter keyed by `path:ip`; applied individually to each mutating route with two tiers (see §6).

Then the route's handler runs. API handlers (`internal/handler/auth`) decode JSON, call the service, and map service errors to HTTP status codes via `errors.Is`. UI handlers (`internal/handler/ui`) parse form data, validate a CSRF cookie/field pair, call the same service methods, and render an HTML template (success → redirect; failure → re-render the form with an error message and a fresh CSRF token).

## 4. Core flow: authorization code → JWT

This is the central flow the service exists to implement.

```
Client app                 auth-service                        Redis / Postgres
    │                           │                                     │
    │  GET /login?redirect_uri= │                                     │
    ├──────────────────────────>│  ValidateRedirectURI(uri)          │
    │                           ├────────────────────────────────────>│ SELECT ... FROM clients
    │  <html + csrf cookie>     │<────────────────────────────────────┤
    │<──────────────────────────┤                                     │
    │                           │                                     │
    │  POST /login (form)       │                                     │
    │  email, password,         │  GenerateCode(...)                 │
    │  redirect_uri, csrf_token │   1. locker.IsLocked?              │
    ├──────────────────────────>│   2. store.GetUser + bcrypt compare│
    │                           │   3. locker.ClearFailedAttempts    │
    │                           │   4. codeStore.StoreCode(code,     │
    │                           │      userID, redirectURI, 60s TTL) │
    │                           ├────────────────────────────────────>│ SET auth:code:<code> {...} EX 60
    │  302 → redirect_uri?code=  │                                     │
    │<──────────────────────────┤                                     │
    │                           │                                     │
    │  POST /api/auth/token     │                                     │
    │  {code, redirect_uri}     │  ExchangeCode(...)                 │
    ├──────────────────────────>│   1. codeStore.RedeemCode(code)    │
    │                           │      (GETDEL — atomic, single-use) │
    │                           ├────────────────────────────────────>│ GETDEL auth:code:<code>
    │                           │   2. compare redirectURI == req    │
    │                           │      (mismatch → burn code, 401)   │
    │                           │   3. sign JWT (HS256, 1h TTL)      │
    │  {token, expires_in}      │                                     │
    │<──────────────────────────┤                                     │
```

Key properties:

- **Single-use codes.** `RedeemCode` uses Redis `GETDEL`, an atomic read-and-delete — there's no window where two concurrent exchanges could both succeed.
- **Redirect-URI binding.** The code is stored as a JSON payload (`{user_id, redirect_uri}`), and `ExchangeCode` requires the same `redirect_uri` used at login. A mismatched attempt still consumes the code (per OAuth semantics for a failed exchange), and returns the same generic `ErrInvalidCode` an expired/unknown code would, so it doesn't leak *why* it failed. See [IMPROVEMENTS.md §1.3](../IMPROVEMENTS.md) for what's still open here (client secrets, PKCE).
- **Timing-safe login.** If the email isn't found, the service still runs a bcrypt comparison against a precomputed dummy hash before returning `ErrInvalidCredentials`, so the response time for "no such user" and "wrong password" are similar — this defeats the simplest user-enumeration timing attack.
- **JWTs are stateless but revocable.** A JWT carries a random `jti` (JWT ID) claim. `POST /api/auth/logout` doesn't delete anything server-side about the session — it adds the `jti` to a Redis blocklist with a TTL equal to the token's remaining lifetime. `POST /api/auth/introspect` checks both signature/expiry *and* blocklist membership.

## 5. Account lockout & abuse protection

Two independent protections layer on top of each other:

| Mechanism | Scope | Storage key | Behavior |
|---|---|---|---|
| Per-IP rate limit | `path + client IP` | `auth:ratelimit:<path>:<ip>` | Fixed-window counter; 429 + `Retry-After` when exceeded. Two tiers: tighter for credential-guessing routes, looser for token/logout/introspect. Fails **open** on Redis errors (logged) — availability is prioritized over the limit itself. |
| Account lockout | `normalized email` | `auth:lockout:attempts:<email>`, `auth:lockout:locked:<email>` | After `MAX_LOGIN_ATTEMPTS` consecutive bad passwords, the account is locked for `LOCKOUT_DURATION`. A successful login clears the counter. Locking is keyed by email only — see [IMPROVEMENTS.md §1.2](../IMPROVEMENTS.md) for the known abuse case (an attacker can lock out a victim they don't control). |

Both counters use the same atomic Lua script (`incrWithExpire` in `internal/store/redis/store.go`): `INCR` the key, and only on the *first* increment (count == 1) set its `EXPIRE`. Doing this in one round trip avoids a crash-between-INCR-and-EXPIRE leaving an unbounded, un-expiring counter.

## 6. Configuration reference

All configuration is environment variables, loaded and validated once at startup in `cmd/server/config.go`. Invalid values (wrong type, non-positive, etc.) are a **startup failure**, not a silent fallback — this is deliberate so a typo can't quietly weaken a security setting in production.

### Required

| Variable | Description |
|---|---|
| `DATABASE_URL` | Postgres DSN, e.g. `postgres://user:pass@host:5432/db?sslmode=disable` |
| `JWT_SECRET` | HMAC signing secret for JWTs. Must be **≥ 32 bytes** or the service refuses to start. |

### Optional — infrastructure

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `SERVER_PORT` | `8080` | HTTP listen port |
| `INSECURE_COOKIES` | `false` | Set `true` only for local plain-HTTP dev — disables the `Secure` flag on the CSRF cookie |

### Optional — tuning

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_PER_MIN` | `10` | Requests/min/IP for `/register`, `/login`, `/code` (and their UI form equivalents) |
| `RATE_LIMIT_TOKEN_PER_MIN` | `30` | Requests/min/IP for `/token`, `/logout`, `/introspect` |
| `CODE_TTL` | `60s` | Lifetime of a one-time login code (Go duration syntax: `90s`, `15m`, `1h`) |
| `TOKEN_TTL` | `1h` | Lifetime of an issued JWT |
| `MAX_LOGIN_ATTEMPTS` | `5` | Consecutive failed logins before lockout |
| `LOCKOUT_DURATION` | `15m` | How long a locked account stays locked |
| `BCRYPT_COST` | `10` | bcrypt cost factor (valid range 4–31); higher is slower but stronger |

These map onto `authService.Config` (`internal/service/auth/service.go`) — a zero-value `Config{}` resolves to the same defaults, so the constructor is safe to call directly in tests without wiring env vars.

## 7. Data model

### Postgres

| Table | Columns | Notes |
|---|---|---|
| `users` | `id UUID PK`, `email TEXT UNIQUE NOT NULL`, `password_hash TEXT NOT NULL`, `created_at` | Email is stored normalized (trimmed + lowercased) by the service layer before insert/lookup. |
| `clients` | `id UUID PK`, `name TEXT`, `redirect_uri TEXT UNIQUE NOT NULL`, `created_at` | The allow-list of redirect URIs permitted to use hosted login. Populated manually (see README "Note" section) — there is no admin API yet. |

Migrations live in `db/migrations/`, are embedded into the binary via `go:embed`, and run automatically on every server start (`db.RunMigrations`, using `golang-migrate`). Migration `002` originally added a `sessions` table; migration `004` drops it again — the service turned out to be fully stateless (JWT + Redis), so nothing ever read or wrote it. It's kept as a migration pair rather than squashed, to preserve history for anyone who deployed between 002 and 004.

### Redis key space

| Key pattern | Written by | Purpose | TTL |
|---|---|---|---|
| `auth:code:<code>` | `codeStore.StoreCode` | One-time login code → `{user_id, redirect_uri}` JSON | `CODE_TTL` (default 60s) |
| `auth:blocklist:<jti>` | `blocklist.Revoke` | Revoked JWT IDs | remaining token lifetime at revocation time |
| `auth:lockout:attempts:<email>` | `locker.RecordFailedAttempt` | Failed-login counter | `LOCKOUT_DURATION` |
| `auth:lockout:locked:<email>` | `locker.LockAccount` | Lock flag (existence = locked) | `LOCKOUT_DURATION` |
| `auth:ratelimit:<path>:<ip>` | middleware `RateLimit` | Fixed-window request counter | rate-limit window (1 minute) |

Redis holds no data that needs to survive a flush — everything in it is either short-lived or reconstructible (a wiped blocklist just means already-issued tokens become valid again until they naturally expire; a wiped lockout counter just resets attempt counts). Postgres is the only store requiring backup/durability.

## 8. API surface

See the [README](../README.md#api) for the endpoint table and step-by-step flow. Request/response JSON shapes are defined in `internal/model/auth/user.go`:

- `RegisterRequest` / `RegisterResponse`
- `GenerateCodeRequest` / `GenerateCodeResponse` (used by both `/api/auth/login` and `/api/auth/code` — they're aliases of the same handler)
- `ExchangeTokenRequest` (now includes `redirect_uri`, must match what the code was issued with) / `ExchangeTokenResponse`
- `IntrospectResponse`

Error responses are plain text (`http.Error`) with a status code; there is no structured error body format yet.

## 9. Security posture summary

Implemented:
- bcrypt password hashing (configurable cost)
- Timing-safe login (dummy-hash comparison on user-not-found)
- Single-use, short-TTL, redirect-URI-bound authorization codes
- JWT with mandatory `exp`, `iss`, `aud`, `jti` claims; explicit HMAC algorithm check (no `alg: none` confusion)
- Server-side JWT revocation via blocklist (logout)
- Account lockout after repeated failed logins
- Per-IP, per-route rate limiting
- CSRF double-submit cookie protection on the hosted HTML forms
- Baseline security response headers + CSP
- Request body size cap (1 MiB)
- Minimum JWT secret length enforced at startup

Known gaps and their tracking items — see [IMPROVEMENTS.md](../IMPROVEMENTS.md) for full detail:
- `X-Forwarded-For` is trusted unconditionally by the rate limiter, which is spoofable when the service is reachable directly (§1.1)
- Lockout is keyed by email only, making it possible to lock out a victim's own account (§1.2)
- Token exchange has no client authentication or PKCE beyond the redirect-URI binding (§1.3, partially addressed)
- Rate limiter and lockout both fail open on Redis errors (§1.4)
- `/api/auth/introspect` is unauthenticated (§1.7)
- No JWT secret rotation support (§1.8)

## 10. Testing

```bash
go test ./...          # unit tests
go test -race ./...    # with the race detector (recommended before merging concurrency-sensitive changes)
```

Coverage by package:
- `internal/service/auth` — the bulk of the business-logic tests, using fakes for `codeStore`/`blocklist`/`locker` (`service_test.go`) and the real in-memory `Store`.
- `internal/handler/auth` — HTTP status-code mapping from service errors, malformed-body handling.
- `internal/middleware` — rate-limit allow/block/fail-open behavior.

Not yet covered (see [IMPROVEMENTS.md §4](../IMPROVEMENTS.md)): the UI handler package, the Redis store implementations against a real/fake Redis, the Postgres store, and an end-to-end flow test wiring `routes.go` itself.

## 11. Local development & deployment

Local dev and Docker Compose usage are documented in the [README](../README.md#local-dev). Summary of the moving parts:

- `docker-compose.yml` runs three services: `postgres` (with a healthcheck), `redis` (with a healthcheck), and `app` — built from the `dev` target of the multi-stage `Dockerfile`, which runs [Air](https://github.com/air-verse/air) for live reload against the bind-mounted source (`.air.docker.toml`).
- The `prod` Dockerfile target is a separate multi-stage build: `builder` (compiles a static `CGO_ENABLED=0` binary) → `prod` (copies just the binary onto `alpine:3.23`). See [IMPROVEMENTS.md §2.6](../IMPROVEMENTS.md) for hardening suggestions (non-root user, healthcheck, distroless base).
- The server does a graceful shutdown on `SIGINT`/`SIGTERM`: it stops accepting new connections and gives in-flight requests up to 15 seconds to finish (`main.go`).
- Startup order: connect to Postgres → run migrations → connect to Redis → build the handler → start listening. Any failure at any step is fatal (`log.Fatal`), so the process won't come up half-configured.

## 12. Extending the service

Some pointers for common changes, based on how the layering is structured:

- **New API endpoint:** add a method to `internal/service/auth.Service` (and the narrow `service` interface in whichever handler package needs it), then wire a handler method + route in `routes.go`.
- **New persistence need:** if it's relational (needs joins, constraints, uniqueness across restarts) it belongs in `internal/store/auth` + a migration; if it's ephemeral/keyed-lookup (TTL'd, counter-like) it belongs in `internal/store/redis`. Either way, define the interface in `internal/service/auth/deps.go` (or `store.go`) first, so the service package stays decoupled from the concrete backend — and so it stays testable with a fake.
- **New config knob:** add a field to `authService.Config` (or `config` in `cmd/server` for non-service settings) with a `Default*` constant, wire it through `loadConfig`, and document it in the tables in §6 above and in `.env.example`.
- **Roadmap features** (roles/authorization, refresh tokens, password reset, a client-management API, PKCE) are tracked in [IMPROVEMENTS.md §5](../IMPROVEMENTS.md).
