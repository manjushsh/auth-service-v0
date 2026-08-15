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
                                wire.go (newHandler)
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
  main.go                Connects to Postgres/Redis, runs migrations, starts/stops both servers
  config.go              Reads and validates environment variables into a config struct
  wire.go                Builds the service graph and both handler chains. Registers no
                         routes itself: each handler package declares its own.
cmd/adminctl/          One-shot CLI to promote/demote admin roles (bootstrap, break-glass)

db/
  db.go                  sql.DB setup (pool tuning, ping) + embedded-migration runner
  migrations/             golang-migrate SQL files (embedded into the binary via go:embed)

internal/
  token/                 JWT minting and parsing; owns the user/admin audience split
    token.go                Manager: Mint/Parse (pure, no I/O)
    verifier.go             Verifier: adds blocklist + session-epoch liveness checks
  secret/                Random token generation and at-rest hashing
  httpx/                 Shared HTTP helpers: JSON encode/decode, error bodies, bearer, client IP
  model/auth/            Wire types for the public plane
  model/admin/           Wire types for the admin plane
  service/auth/          Credential and session mechanics: registration, login, codes, JWT,
                         lockout, session revocation, password reset
    service.go             Service implementation (Deps struct constructor)
    password_reset.go       Reset token issuance + redemption
    deps.go                 Narrow interfaces the service depends on
  service/admin/         Administrative operations, orchestrating service/auth and the store
    service.go             Caller, audit plumbing, health, shared helpers
    auth.go                 Admin login, Authenticate, Authorize
    users.go                Account *lifecycle* (admin tier): list, read, role, status, delete
    recovery.go             Account *recovery* (support tier): unlock, revoke sessions,
                            password reset — and, later, MFA reset
    clients.go / audit.go
  store/auth/            User/client/audit persistence
    store.go                Domain types, roles, statuses, pagination, shared errors
    postgres.go             Postgres implementation (lib/pq); audited mutations run in one tx
    audit_postgres.go       Audit insert (tx-aware) + keyset query
    memory.go               In-memory implementation, mirroring the same surface
  store/redis/           Redis-backed volatile state
    store.go                Shared client wrapper, key helpers, atomic INCR+EXPIRE Lua script
    code.go                 One-time login codes (GETDEL for single-use redemption)
    blocklist.go            Revoked-JWT set (by jti)
    locker.go               Scoped failed-login counters, lock flag, Unlock
    epoch.go                Per-user session-revocation watermark
    pwreset.go              Single-use password-reset tokens (stored hashed)
    ratelimit.go            Fixed-window request counter
  store/memory/          In-process mirror of store/redis: the test double for every service
                         package, and a Redis-free mode for local runs
  handler/auth/          JSON API handlers for the public plane
    routes.go               Route table: path → rate-limit tier → handler
  handler/admin/         JSON API handlers for the admin plane
    handler.go              requireRole gate, error mapping, request helpers
    routes.go               Route table: path → required role → handler
  handler/ui/            Server-rendered login/register pages (HTML templates + CSRF)
    routes.go               Route table for the hosted pages and static assets
  middleware/            Cross-cutting HTTP concerns: security headers, body size limit, logging,
                         per-IP rate limiting (two tiers: fail-open public, fail-closed admin)

docs/                   This document, MFA_PLAN.md, ADMIN_API_PLAN.md
```

## 3. Request lifecycle

Every request passes through the middleware chain in this order (outermost first, from `wire.go`):

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
| Account lockout | `normalized email` | `auth:lockout:<scope>:attempts:<email>`, `auth:lockout:<scope>:locked:<email>` | After `MAX_LOGIN_ATTEMPTS` consecutive bad passwords, the account is locked for `LOCKOUT_DURATION`. A successful login clears the counter. Locking is keyed by email only — see [IMPROVEMENTS.md §1.2](../IMPROVEMENTS.md) for the known abuse case (an attacker can lock out a victim they don't control). The admin API can release a lock early (`POST /admin/users/{id}/unlock`), which is the mitigation that makes that abuse case tolerable. |
| Session revocation | `user id` | `auth:user:epoch:<user_id>` | A watermark: every token issued at or before it stops introspecting as active. The only mechanism that can express "revoke everything for user X" — the blocklist is per-`jti` and nothing indexes a user's `jti`s. Bumped by admin revoke-sessions, suspension, role change, deletion and password reset. |

`<scope>` exists so independent failure budgets can share one implementation. Only `pwd` is in
use today; the MFA plan adds an `otp` scope whose counter a successful password login must not
clear, or an attacker who already has the password would get an unbounded OTP-guessing budget.

The epoch is compared as `iat <= epoch`, not `<`: JWT `iat` has one-second granularity, so a
token minted in the same second as a revocation would survive a strict comparison. `ExchangeCode`
applies the same rule to the authorization code's issue time, otherwise a code already in flight
would redeem into a fresh token whose `iat` is *after* the epoch — a revocation hole one
`CODE_TTL` wide.

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

### Optional — admin plane

| Variable | Default | Description |
|---|---|---|
| `ADMIN_API_ENABLED` | `false` | Master switch; the admin listener does not start unless `true` |
| `ADMIN_BIND_ADDR` | `127.0.0.1` | Interface for the admin listener. `0.0.0.0` should be a deliberate, reviewed change |
| `ADMIN_PORT` | `8081` | Admin listener port |
| `ADMIN_TOKEN_TTL` | `15m` | Admin JWT lifetime — deliberately much shorter than `TOKEN_TTL` |
| `ADMIN_RATE_LIMIT_PER_MIN` | `60` | Per real peer IP, per route. Fails **closed** |
| `ADMIN_PWRESET_TTL` | `15m` | Lifetime of an admin-issued password reset token |

A kill switch is correct here and would be wrong for a security control: the failure mode of
`ADMIN_API_ENABLED=false` is "an operator has to use psql", not "a protection stopped applying".
Defaulting it off means an environment that never opted in has no admin plane to attack.

Booleans are parsed with `strconv.ParseBool` and a malformed value is a startup error. A bare
`== "true"` comparison would read `ADMIN_API_ENABLED=TRUE` as *false*; that direction happens to
fail safe here, but the pattern must not spread to a flag where it would fail open.

These map onto `authService.Config` and `adminService.Config` — a zero-value `Config{}` resolves to the same defaults, so both constructors are safe to call directly in tests without wiring env vars.

## 7. Data model

### Postgres

| Table | Columns | Notes |
|---|---|---|
| `users` | `id UUID PK`, `email TEXT UNIQUE NOT NULL`, `password_hash TEXT NOT NULL`, `role`, `status`, `created_at` | Email is stored normalized (trimmed + lowercased) by the service layer before insert/lookup. `role ∈ {user, support, admin}` and `status ∈ {active, suspended}`, both `CHECK`-constrained and defaulted so migration 005 is a no-op for existing rows. Indexed for the three access patterns that exist: unique on `email` (exact lookup), a **partial** index on `role <> 'user'` (privileged accounts are rare, so the index stays tiny), and a composite `(created_at DESC, id DESC)` for keyset pagination — without which every page of `GET /admin/users` was a full scan plus a sort. |
| `clients` | `id UUID PK`, `name TEXT`, `redirect_uri TEXT NOT NULL`, `disabled_at`, `created_at` | The allow-list of redirect URIs permitted to use hosted login, managed through the [Admin API](../README.md#admin-api). Uniqueness is a **partial** index over live rows (`WHERE disabled_at IS NULL`), so a disabled URI can be re-registered — which is how a client rotation completes. |
| `admin_audit_log` | `id BIGSERIAL PK`, `actor_*`, `action`, `target_*`, `result`, `metadata JSONB`, `remote_addr INET`, `forwarded_for`, `user_agent`, `created_at` | Append-only record of every privileged action, including denials. `actor_id` is `ON DELETE SET NULL`, not `CASCADE` — every other FK here cascades, but deleting an admin must not erase the record of what they did; `actor_email`/`actor_role` are snapshots for the same reason. `BIGSERIAL` rather than a UUID because this table is read in time order and paginated. |

Mutations to `users` and `clients` go through store methods that **take an audit event** and write
it on the same transaction. The signature is the enforcement: there is no way to change either
table without supplying the record of who did it, and a failed audit write rolls the change back.
The event is passed by pointer so a write can complete its own record — a created row's id, in
particular, which does not exist until the INSERT returns.

Two rules govern what reaches the table at all:

- **Attributable actions only.** Failed authentication, and failed logins against addresses that
  are unknown or unprivileged, go to the structured log instead. `/admin/auth/login` is
  unauthenticated, so recording every attempt would let anyone able to reach the port write
  unbounded rows about accounts that do not exist. A failed login against a real privileged
  account *is* attributable, and is recorded.
- **Session revocation precedes the change it accompanies.** Revocation lives in Redis and the
  change in Postgres, so they cannot share a transaction and one must go first. Revoking first
  makes a partial failure mean "logged out for a change that did not happen"; the other order
  means "suspended, deleted or demoted with live tokens still working", which is the guarantee
  those endpoints exist to provide. Revocation is idempotent, so the wasted bump costs a re-login.

Migrations live in `db/migrations/`, are embedded into the binary via `go:embed`, and run automatically on every server start (`db.RunMigrations`, using `golang-migrate`). Migration `002` originally added a `sessions` table; migration `004` drops it again — the service turned out to be fully stateless (JWT + Redis), so nothing ever read or wrote it. It's kept as a migration pair rather than squashed, to preserve history for anyone who deployed between 002 and 004.

### Redis key space

| Key pattern | Written by | Purpose | TTL |
|---|---|---|---|
| `auth:code:<code>` | `codeStore.StoreCode` | One-time login code → `{user_id, redirect_uri, issued_at}` JSON | `CODE_TTL` (default 60s) |
| `auth:blocklist:<jti>` | `blocklist.Revoke` | Revoked JWT IDs | remaining token lifetime at revocation time |
| `auth:lockout:<scope>:attempts:<email>` | `locker.RecordFailedAttempt` | Failed-login counter | `LOCKOUT_DURATION` |
| `auth:lockout:<scope>:locked:<email>` | `locker.LockAccount` | Lock flag (existence = locked) | `LOCKOUT_DURATION` |
| `auth:user:epoch:<user_id>` | `BumpEpoch` | Session-revocation watermark (unix seconds) | `2 × TOKEN_TTL` |
| `auth:pwreset:<sha256(token)>` | `StoreResetToken` | Admin-issued reset token → user id | `ADMIN_PWRESET_TTL` (15m) |
| `auth:ratelimit:<path>:<ip>` | middleware `RateLimit` | Fixed-window request counter | rate-limit window (1 minute) |

Reset tokens are keyed by hash, never by the token itself, so a dump of Redis is not a set of
usable account takeovers. A fast hash is correct rather than bcrypt: the tokens are 256 bits of
`crypto/rand`, so there is nothing to brute-force and a slow KDF buys nothing.

The epoch is the one key here without a natural TTL; giving it `2 × TOKEN_TTL` keeps the
invariant below true, because once every token predating a bump has expired the watermark
carries no information.

Redis holds no data that needs to survive a flush — everything in it is either short-lived or reconstructible (a wiped blocklist just means already-issued tokens become valid again until they naturally expire; a wiped lockout counter just resets attempt counts). Postgres is the only store requiring backup/durability.

## 8. API surface

See the [README](../README.md#api) for the endpoint table and step-by-step flow. Request/response JSON shapes are defined in `internal/model/auth/user.go`:

- `RegisterRequest` / `RegisterResponse`
- `GenerateCodeRequest` / `GenerateCodeResponse` (used by both `/api/auth/login` and `/api/auth/code` — they're aliases of the same handler)
- `ExchangeTokenRequest` (now includes `redirect_uri`, must match what the code was issued with) / `ExchangeTokenResponse`
- `IntrospectResponse`
- `PasswordResetRequest`

Public-plane error responses are plain text (`http.Error`) with a status code.

The admin plane is a **separate listener** with its own handler chain, its own wire types in
`internal/model/admin`, and structured errors: `{"error": {"code": "...", "message": "..."}}`.
That inconsistency is deliberate — the admin API is machine-consumed, and retrofitting the
public plane would be a separate breaking change. Its endpoint table is in the
[README](../README.md#admin-api); the design reasoning is in [ADMIN_API_PLAN.md](ADMIN_API_PLAN.md).

Admin responses never carry a password hash: `model/admin.User` is a distinct type from
`store.UserRecord` precisely so the hash has no field to be marshalled into.

## 9. Security posture summary

Implemented:
- bcrypt password hashing (configurable cost)
- Timing-safe login (dummy-hash comparison on user-not-found; the suspension check sits *after* the comparison so suspended accounts aren't detectable by response time)
- Single-use, short-TTL, redirect-URI-bound authorization codes, re-validated against the client allow-list at redemption
- JWT with mandatory `exp`, `iss`, `aud`, `jti` claims; explicit HMAC algorithm check (no `alg: none` confusion)
- **Audience split**: admin tokens carry `auth-service-admin` and are minted only by admin login, so a user JWT handed to a relying application can never open the admin plane
- Server-side JWT revocation via blocklist (logout) and per-user session revocation via epoch
- Account lockout after repeated failed logins, releasable early by an authenticated admin
- Every password check — including admin login — routes through one lockout-aware helper, so no endpoint becomes an unthrottled password oracle
- Per-IP, per-route rate limiting; the admin tier ignores proxy headers and fails closed
- Admin plane on a separate listener, off by default, bound to loopback
- Two-role authorization, re-read from the database on every request rather than trusted from the token
- Last-admin and self-target guards, enforced inside the transaction
- Confirmation echo on irreversible operations (delete user / delete client)
- Durable, append-only audit log; a failed audit write fails the mutation
- CSRF double-submit cookie protection on the hosted HTML forms; the admin plane is bearer-only so it has no ambient credential to ride
- Baseline security response headers + CSP + `Cache-Control: no-store` on everything but `/static/`
- Request body size cap (1 MiB public, 64 KiB admin)
- Minimum JWT secret length enforced at startup; nil dependencies rejected by both service constructors

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
- `internal/service/auth` — the bulk of the business-logic tests. There are no hand-rolled fakes: `store/memory` mirrors the Redis implementation method for method, so these exercise the same paths production takes. An injectable clock drives the service, the token manager and the volatile store together, which is what makes the second-granular `iat <= epoch` boundary testable without sleeping.
- `internal/service/admin` — admin operations against the *real* auth service, since the interaction between the two is the thing worth testing. Covers the last-admin and self-target guards, confirmation echoes, client lifecycle, keyset pagination, and an assertion that every mutation leaves exactly one audit record.
- `internal/handler/admin` — the authorization table (below) plus end-to-end HTTP flows for the client lifecycle and support operations.
- `internal/handler/auth` — HTTP status-code mapping from service errors, malformed-body handling.
- `internal/middleware` — rate-limit allow/block/fail-open behavior.

**The authorization test is driven from the route table itself**, not a hand-maintained list.
Every non-public route is asserted to reject an anonymous caller, a garbage token, a
wrongly-signed token and — the one that matters most — a valid *user-audience* token for the
same admin. A second test asserts that only login and health are public. Between them, an
endpoint added without a role gate fails the suite instead of shipping open.

Not yet covered (see [IMPROVEMENTS.md §4](../IMPROVEMENTS.md)): the UI handler package, the Redis store implementations against a real/fake Redis, and the Postgres store. Note in particular that the last-admin guard's correctness rests on `SELECT ... FOR UPDATE`; the in-memory store serializes everything behind a mutex, so a concurrent-demotion test passes there and proves nothing about Postgres.

## 11. Local development & deployment

Local dev and Docker Compose usage are documented in the [README](../README.md#local-dev). Summary of the moving parts:

- `docker-compose.yml` runs three services: `postgres` (with a healthcheck), `redis` (with a healthcheck), and `app` — built from the `dev` target of the multi-stage `Dockerfile`, which runs [Air](https://github.com/air-verse/air) for live reload against the bind-mounted source (`.air.docker.toml`).
- The `prod` Dockerfile target is a separate multi-stage build: `builder` (compiles a static `CGO_ENABLED=0` binary) → `prod` (copies just the binary onto `alpine:3.23`). See [IMPROVEMENTS.md §2.6](../IMPROVEMENTS.md) for hardening suggestions (non-root user, healthcheck, distroless base).
- The server does a graceful shutdown on `SIGINT`/`SIGTERM`: it stops accepting new connections and gives in-flight requests up to 15 seconds to finish (`main.go`).
- Startup order: connect to Postgres → run migrations → connect to Redis → build the handler → start listening. Any failure at any step is fatal (`log.Fatal`), so the process won't come up half-configured.

## 12. Extending the service

Some pointers for common changes, based on how the layering is structured:

- **New public API endpoint:** add a method to `internal/service/auth.Service` (and the narrow `service` interface in whichever handler package needs it), a handler method, then a row in that handler package's `Routes()`. The row is where the **rate-limit tier** is declared, and `TestRoutes_RateLimitTiers` fails until the new route is listed there too — so a credential endpoint cannot quietly land on the loose tier.
- **New admin endpoint:** add the operation to `internal/service/admin`, a handler in `internal/handler/admin`, and a row in `Routes()` — the row is where the required role is declared, and the authorization test reads that table, so an endpoint cannot be added without choosing one. Mutations take a `store.AuditEvent`; Postgres ones get it written on the same transaction, Redis-backed ones call `s.record` and must propagate its error.
- **New persistence need:** if it's relational (needs joins, constraints, uniqueness across restarts) it belongs in `internal/store/auth` + a migration; if it's ephemeral/keyed-lookup (TTL'd, counter-like) it belongs in `internal/store/redis`. Either way, define the interface in `internal/service/auth/deps.go` (or `store.go`) first, so the service package stays decoupled from the concrete backend — and so it stays testable with a fake.
- **New config knob:** add a field to `authService.Config` (or `config` in `cmd/server` for non-service settings) with a `Default*` constant, wire it through `loadConfig`, and document it in the tables in §6 above and in `.env.example`.
- **Roadmap features** (roles/authorization, refresh tokens, password reset, a client-management API, PKCE) are tracked in [IMPROVEMENTS.md §5](../IMPROVEMENTS.md).
