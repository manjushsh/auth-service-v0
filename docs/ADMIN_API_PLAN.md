# Admin API — Basic Surface & Implementation Plan

Status: **implemented** — A0a through A5 are built, tested and documented. This document is
now the design rationale behind the code rather than a proposal; §13 remains forward-looking.
Scope owner: `internal/service/admin`, `internal/handler/admin`, `cmd/server`, `cmd/adminctl`
Related: [ARCHITECTURE.md](ARCHITECTURE.md), [../README.md](../README.md), [MFA_PLAN.md](MFA_PLAN.md)

> Scope: the **basic** admin surface — the set of endpoints that removes production database
> and Redis credentials from routine operations. MFA is being built afterwards — nothing here
> waits on it, but **§13 is a forward-compatibility contract** so that ordering stays free.
>
> The service has no authenticated admin surface at all
> ([ARCHITECTURE.md §7](ARCHITECTURE.md#7-data-model): *"Populated manually — there is no
> admin API yet"*). Every task below is a `psql` session, a `redis-cli` session, or — for
> two of them — impossible at any privilege level.

---

## 0. TL;DR

Eleven endpoints across four groups, in this order:

| Group | Endpoints | Why |
|---|---|---|
| **Admin auth** | login, logout, whoami | Everything else needs it |
| **Clients** | list, create, get, disable, delete | The one workflow the README documents as raw SQL |
| **Users (read)** | list/search, get | Prerequisite for every support action |
| **Account ops** | unlock, revoke-sessions, suspend, delete, password-reset | The actual support workload |

Four decisions carry the design:

- **Admin tokens get their own `aud`.** User JWTs are handed to third-party relying apps by
  design — that is what `redirect_uri` is for. If admin authority were a claim on an ordinary
  token, every registered client would hold a root key the moment an admin logged into it. (§3.2)
- **Separate listener, loopback by default, off by default.** Until MFA lands this is the
  primary security boundary, not a defence-in-depth nicety. (§3.3)
- **Every mutation writes an audit row, in the same transaction, or the mutation fails.** (§6)
- **A0 builds the primitives MFA will need, in their final shape.** The per-user epoch, the
  scoped locker, `GetUserByID`, the `Deps` constructor and `Cache-Control: no-store` are all on
  [MFA_PLAN.md](MFA_PLAN.md)'s P0 list. Building them here — with MFA's signatures, not
  interim ones — costs almost nothing now and is the difference between MFA's P0 shrinking and
  MFA's P0 silently breaking this plane's endpoints. **§13 is the contract.**

---

## 1. What's needed, ranked

Ranked by frequency × how bad the current workaround is. The "today" column is the actual
procedure right now.

| # | Capability | Today | Why it ranks here |
|---|---|---|---|
| **1** | **Client management** | `psql` + `INSERT INTO clients …`, copy-pasted from [README.md](../README.md#note) | The only workflow the project documents as raw SQL. Onboarding a relying app requires production write access — so "add a new app" and "drop the users table" are the same privilege. Highest write frequency, easiest to make safe. |
| **2** | **Unlock a locked account** | `redis-cli DEL auth:lockout:locked:<email> auth:lockout:attempts:<email>`, or wait out `LOCKOUT_DURATION` | Highest-volume support ticket in any password system, and externally triggerable here: lockout is keyed by email alone, so anyone who knows an address can lock that user out ([ARCHITECTURE.md §5](ARCHITECTURE.md#5-account-lockout--abuse-protection)). That accepted gap is only tolerable if unlocking is cheap. |
| **3** | **Revoke every session for a user** | **Impossible.** Not hard — impossible. | Revocation is per-`jti` ([service.go:262-274](../internal/service/auth/service.go#L262-L274)) and nothing indexes which `jti`s belong to a user. A DBA with full Postgres *and* Redis access still cannot kill a compromised user's live tokens; the only lever is rotating `JWT_SECRET`, which logs out every user of the service. The missing incident-response primitive. |
| **4** | **Find a user** (search by email, read status) | `psql` + `SELECT` | Prerequisite for everything else on this list. Also the only way to answer "is this account locked / does it exist / when was it created", which today means joining a Postgres row against Redis keys by hand. |
| **5** | **Reset a user's password** | **No mechanism.** A DBA generates a bcrypt hash themselves and runs `UPDATE users SET password_hash = …` | No mail capability means no self-service reset, so every forgotten password is a manual hash-and-UPDATE with no audit trail, no expiry, and no proof the right person asked. |
| **6** | **Suspend / delete a user** | `psql DELETE` — cascades cleanly but leaves that user's JWTs valid for up to `TOKEN_TTL` | Offboarding and erasure. Note the deletion is *incomplete* today: nothing re-checks that a token's subject still exists, so a deleted user keeps a working session for an hour. Same fix as #3. |
| **7** | **Audit log** | Nothing | Not an endpoint anyone asks for, and the reason it is here rather than in "later": #1–#6 are all privileged mutations of other people's accounts. Audit has to land *with the first one*, not after — retrofitting it means the first months of admin activity are unreconstructable. |

**Items 3 and 6 both need the same missing primitive:** a way to invalidate one user's
existing tokens. That is a per-user epoch (§5.3) — roughly 30 lines, and it is what makes
"revoke sessions", "suspend", and "delete" mean anything before the token naturally expires.

---

## 2. Scope

### In

Client CRUD · user search/read · unlock · revoke sessions · suspend · delete · admin-initiated
password reset · durable audit log · two roles (`support`, `admin`).

### Out, and why

| Item | Why |
|---|---|
| **MFA itself** | Being built later. This plan does not wait on it, but it does build against its interfaces — see **§13**, which is a forward-compatibility contract, not a wish list. |
| Admin web UI | The API is the contract. A UI has its own session/CSRF story. |
| Full RBAC (permissions, groups, custom roles) | Two roles cover every task in §1. A permission model is the README's roadmap item #1 and should be designed against real requirements, not invented here. |
| Multi-tenancy / organizations | No tenant concept exists anywhere in the service. |
| Impersonation ("log in as user") | §12.2 — the v1 answer is no. |
| Per-session listing / per-session revocation | Needs a per-user `jti` index that doesn't exist. Revoke-all covers the real need at a fraction of the cost. |
| Self-service password reset (email) | No mail capability. §4.4's redemption endpoint is designed so an email flow can reuse it verbatim later. |
| Rate-limit override endpoint | §12.1. |
| Any endpoint returning a password hash or a live token | No §1 task needs one. |

---

## 3. Admin authentication without MFA

### 3.1 Admin identity is a `role` column on `users`

```sql
role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'support', 'admin'))
```

One human, one account, one password. Reuses registration, bcrypt, and the existing lockout
wholesale, and aligns with the roadmap's roles item.

The alternative — a separate `admin_users` table — buys one real property: admin credentials
would be invisible to the public login endpoint, so the internet-facing
`/api/auth/login` could not be used to test an admin password. It costs a parallel
password/lockout/(eventually)MFA stack. Not worth it; the mitigations are §3.3's network
boundary and §3.4's insistence on non-human-memorable admin passwords.

A static `ADMIN_API_KEY` from the environment is **rejected**: no actor attribution (so §6's
audit log records "the key" did it), no rotation without a restart, and it ends up in a CI
variable and someone's shell history. A shared secret is right for machine-to-machine calls
and wrong for privileged human actions — and every task in §1 is a human action.

### 3.2 Admin tokens must have their own audience

The finding that most changes the design.

`ExchangeCode` issues JWTs with `Audience: jwt.ClaimStrings{tokenIssuer}` — one audience for
everything ([service.go:245](../internal/service/auth/service.go#L245)) — and delivers them
to **third-party relying applications** through the redirect flow. That is what the `clients`
table is for.

So if admin authority were "a `role` claim on a normal token":

```
1. An admin logs into any registered relying app.
2. That app now holds a JWT whose subject is an admin.
3. The app replays it against the admin plane and owns the auth service.
```

The app need not be malicious — it needs to log the token, or be breached.

**Required:**

- Admin tokens are minted only by `POST /admin/auth/login`, a direct password exchange on the
  admin listener. No authorization code, no `redirect_uri`, no third party — nothing to hand
  the token to.
- `aud: "auth-service-admin"`, and the admin authenticator parses with
  `jwt.WithAudience(adminAudience)`. A user token presented to the admin plane fails on
  audience; an admin token presented to the public plane fails the same way, since
  `parseToken` already pins `jwt.WithAudience(tokenIssuer)`
  ([service.go:297-317](../internal/service/auth/service.go#L297-L317)). Add a test for both
  directions.
- Own TTL: `ADMIN_TOKEN_TTL`, default `15m` — much shorter than `TOKEN_TTL`, and the main
  compensating control for having no second factor.
- Own `jti` in the existing blocklist, so `POST /admin/auth/logout` works unchanged.

> **Do not authenticate the admin plane with `Introspect`.** Besides the audience problem, it
> reports an invalid token as a *successful call returning `Active: false`*
> ([service.go:276-280](../internal/service/auth/service.go#L276-L280)), so the obvious
> `if err != nil { 401 }` handler shape fails **open** — and here that is the difference
> between a 401 and an unauthenticated caller holding `DELETE /admin/users/{id}`. The admin
> plane calls its own parser and asserts a non-empty subject.

### 3.3 A separate listener, loopback by default

`main.go` starts one `http.Server` ([main.go:67-80](../cmd/server/main.go#L67-L80)). Add a
second:

```go
adminSrv := &http.Server{
    Addr:    cfg.adminBindAddr + ":" + cfg.adminPort,  // default 127.0.0.1:8081
    Handler: adminHandler,
    // same timeouts; shut down in the same signal handler
}
```

Worth ~25 lines rather than mounting `/admin/*` on the public mux:

- **Without MFA, this is the security boundary.** A password-only admin plane on the public
  internet is a bad idea; the same plane reachable only from a bastion or VPN is ordinary.
- **An authorization bug is not instantly internet-reachable.** One listener means a routing
  mistake exposes user deletion to the world.
- **The admin API is a user-enumeration oracle by design** — `GET /admin/users` *is* one.
  Fine internally, unacceptable publicly.
- **Different middleware.** Admin wants a fail-closed rate limiter, no CSRF cookie machinery,
  no static files, no hosted HTML. Composing a separate chain is clearer than conditioning
  the existing one on a path prefix.

Exposing it later becomes a reviewable deployment diff (`ADMIN_BIND_ADDR=0.0.0.0`) rather than
an invisible default. Both servers share the existing 15-second graceful shutdown.

### 3.4 Bootstrapping the first admin

`cmd/adminctl promote <email>` — a small binary reading `DATABASE_URL`.

Granting admin requires database access, which is precisely the privilege being granted, so
nothing is weakened. Explicit, one-shot, visible in shell history and DB logs, works before
the service is running, and gives `demote` / `list` and the last-admin guard (§3.5) one home.

`ADMIN_BOOTSTRAP_EMAIL` as an env var is **rejected**: it converts "can edit config" into "can
grant myself admin, silently, at the next restart" — a strictly larger group than "can write
to the database" — and being re-applied on every boot means demoting a compromised admin is
undone by the next deploy.

While admin accounts have no second factor, the compensating control is that the password
isn't guessable — so promotion should push toward a generated one.

> **Amended after implementation.** An earlier draft of this section said `adminctl promote`
> should *refuse an account whose password was set through the ordinary registration form*
> unless `--force` is passed. **That is not implementable as written and was not built:**
> nothing records how a password was set, so there is no fact to check. Writing the flag
> anyway would have produced a guard that always passes — worse than none, because it reads
> like protection.
>
> What ships instead is a printed reminder on promotion. What would make it real, in
> increasing order of cost:
>
> 1. **Force a reset on promotion** — have `promote` mint a password-reset token and require
>    it be redeemed before the account can log in to the admin plane. The mechanism exists
>    (§4.4); it needs a `password_reset_required` column and a check in admin login.
> 2. **Record provenance** — a `password_set_via` column (`register` / `reset` / `admin`),
>    which makes the original check possible and is useful independently.
>
> Until one of those lands, this is an accepted gap, not a control. It is tolerable only
> because the admin plane is loopback-bound by default (§3.3); it stops being tolerable the
> moment `ADMIN_BIND_ADDR` widens, which is the same threshold at which MFA becomes required
> (§13.3).

### 3.5 Two roles

| Role | Can |
|---|---|
| `support` | Read users and clients; **unlock**; **revoke sessions** |
| `admin` | Everything above, plus client CRUD, suspend/delete users, **password reset**, role changes, audit query |

Password reset is `admin`-only because it is the one action that hands over a working path
into an account. `support` — the role most people hold — can restore access to a locked-out
user and kill a compromised session, but cannot take an account over.

Two guards, enforced in the same transaction as the change:

- **The last `admin` cannot be demoted or deleted.** `SELECT count(*) … WHERE role='admin'
  FOR UPDATE`; refuse at 1. Otherwise the plane locks itself out and recovery is `adminctl`
  (fine as break-glass, not as routine).
- **Self-demotion and self-deletion are refused** with a distinct error. Ergonomics, not
  security, and it costs a line.

### 3.6 Role is read fresh, never trusted from the token

The role goes in the admin JWT for cheap routing, but **authorization re-reads it from
Postgres on every request**. One primary-key lookup on a low-traffic internal plane is free;
the alternative is that demoting a compromised admin leaves them fully privileged until the
token expires. A role change also bumps the epoch (§5.3), which kills the token outright —
the epoch is the fast path, the fresh read is what still works if the key is evicted.

---

## 4. Endpoints

Base path `/admin`, JSON only, **bearer token only** — never cookie auth (§7). `{id}` is a UUID.

### 4.1 Admin auth

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/admin/auth/login` | — | `{email, password}` → `{token, expires_in, role}`. Goes through the same lockout as public login — never a bare bcrypt compare. Refuses `role='user'` |
| POST | `/admin/auth/logout` | any | Blocklists the admin `jti` |
| GET | `/admin/auth/whoami` | any | `{user_id, email, role}` — the first thing anyone integrating will call |

### 4.2 Clients — priority #1

| Method | Path | Role | Replaces |
|---|---|---|---|
| GET | `/admin/clients?limit=&cursor=` | support | `SELECT * FROM clients` |
| POST | `/admin/clients` | admin | The `INSERT` in [README.md](../README.md#note). `{name, redirect_uri}`; 409 on duplicate — map `pq` code `23505` exactly as [postgres.go:24-30](../internal/store/auth/postgres.go#L24-L30) already does |
| GET | `/admin/clients/{id}` | support | — |
| PATCH | `/admin/clients/{id}` | admin | `{name}` only — see below |
| POST | `/admin/clients/{id}/disable` | admin | Soft delete: sets `disabled_at` |
| DELETE | `/admin/clients/{id}` | admin | Hard delete. Body must echo `{"redirect_uri": "<exact value>"}` as confirmation |

Three things the naive version gets wrong:

- **`redirect_uri` is not editable in place.** It is the client's identity everywhere else:
  codes are bound to the literal string
  ([service.go:200](../internal/service/auth/service.go#L200)) and `ExchangeCode` compares it
  verbatim ([service.go:231](../internal/service/auth/service.go#L231)). Editing it mid-flight
  silently breaks every code in the air. Rotation = create new, migrate the app, disable the
  old. `PATCH` refuses a `redirect_uri` change with a 400 explaining that.
- **Disabling doesn't stop what's already issued.** `ExchangeCode` never re-validates against
  `clients`, so outstanding codes stay redeemable for up to `CODE_TTL` (60s) and issued JWTs
  stay valid for `TOKEN_TTL` (1h). **Recommendation: have `ExchangeCode` re-check
  `ValidateRedirectURI` on redemption** — one extra indexed query per exchange, and it makes
  "disable" mean something within a minute. The 1-hour token window needs a per-client token
  index and stays open; document it.
- **Soft delete needs a partial index, not a filter everyone forgets.**
  `ValidateRedirectURI` ([postgres.go:46-56](../internal/store/auth/postgres.go#L46-L56)) gains
  `AND disabled_at IS NULL`, and the `UNIQUE` constraint becomes a partial unique index over
  live rows so a disabled URI can be recreated.

### 4.3 Users — read

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/admin/users?email=&limit=&cursor=` | support | Keyset pagination on `(created_at, id)`; `limit` default 25, max 100. `email` is an exact, normalized match |
| GET | `/admin/users/{id}` | support | Postgres row + live Redis state (locked, failed attempts, sessions-revoked-at) |

**Never return `password_hash`.** Define an explicit `AdminUserView` DTO rather than reusing
`store.UserRecord`, which carries the hash
([store.go:13-16](../internal/store/auth/store.go#L13-L16)). A struct with no field for it
cannot leak it through a future `json.Marshal`.

Skip prefix/fuzzy search in v1 — exact lookup covers the support workflow, and `LIKE 'foo%'`
won't use the existing unique index under a non-C collation without `text_pattern_ops`.

### 4.4 Account operations

| Method | Path | Role | Effect |
|---|---|---|---|
| POST | `/admin/users/{id}/unlock` | support | `{"scope": "pwd"\|"all"}`, default `all`. Clears the failure counter **and** the lock flag. Idempotent — see below |
| POST | `/admin/users/{id}/revoke-sessions` | support | Bumps `auth:user:epoch:<user_id>`. Every token issued at or before now stops introspecting as active. Idempotent |
| PATCH | `/admin/users/{id}` | admin | `{"status": "active"\|"suspended"}` and `{"role": …}`. Both bump the epoch |
| DELETE | `/admin/users/{id}` | admin | Hard delete (cascades on the existing FKs). Body must echo `{"email": "<exact value>"}`. Bumps the epoch so live tokens die with the row |
| POST | `/admin/users/{id}/password-reset` | admin | Mints a single-use reset token — see below |

**Unlock must go through the `locker` interface, never through hand-built Redis keys.**
[MFA_PLAN.md §5.1](MFA_PLAN.md) renames the lockout keys to
`auth:lockout:<scope>:attempts:<email>` when it lands. An unlock handler that `DEL`s the
literal key names would then delete nothing, return `200`, and leave the account locked —
a support endpoint that reports success while doing nothing is the worst failure mode this
plane has. §13.1 resolves it by adopting MFA's scoped signature up front, in A0a.

The interface also needs a new method. `ClearFailedAttempts`
([locker.go:28-30](../internal/store/redis/locker.go#L28-L30)) deletes only the attempts
counter; **nothing in the codebase clears the lock flag** — a locked account can only wait out
`LOCKOUT_DURATION`. A0 adds `Unlock(ctx, scope, email)` that deletes both keys.

**Password reset must not hand the admin a working credential.** The tempting design — admin
sets a temporary password and reads it out — means the admin knows a credential that works,
with no expiry and no forced change. Instead:

```
POST /admin/users/{id}/password-reset            ← admin plane
  → token = 32 random bytes; store SHA-256(token) → user_id in Redis under
    auth:pwreset:<hash>, 15m TTL                    ← hashed: a Redis dump is
  → 200 {reset_token, expires_in}                      not a takeover kit
  → admin delivers it out of band, after verifying identity however the
    organization verifies identity

POST /api/auth/password-reset                    ← public plane, unauthenticated
  {reset_token, new_password}
  → GETDEL the key (atomic, single use), validate against the existing
    minPasswordLen/maxPasswordLen rules, bcrypt at cfg.BcryptCost,
    UPDATE users, bump the epoch, clear the lockout
  → 204
```

Storing the hash rather than the token is correct here *and* a fast hash is correct: the token
is 256 bits of `crypto/rand`, so there is nothing to brute-force and a slow KDF buys nothing.

An admin who issues a reset token can redeem it themselves. That is inherent to
admin-initiated recovery without an out-of-band channel; it is why the action is `admin`-only
and audited on both issue and redemption. The public redemption endpoint is deliberately the
same one a future email flow would use — only delivery changes.

**Suspension has to be enforced or it is decoration**, and *where* the check goes is pinned
by two constraints, not one:

```go
u, err := s.store.GetUser(ctx, email)          // existing
…
if err := bcrypt.CompareHashAndPassword(…); err != nil { … }   // existing

// ── suspension check goes exactly here ──
if u.Status == store.StatusSuspended {
    return model.GenerateCodeResponse{}, ErrInvalidCredentials
}

// ClearFailedAttempts, then (later) the MFA branch, then code issuance
```

- **After the bcrypt compare.** Checking earlier skips the hash and makes suspended accounts
  detectable by response time — defeating the dummy-hash work at
  [service.go:176-181](../internal/service/auth/service.go#L176-L181).
- **Before the MFA branch** that [MFA_PLAN.md §6.3](MFA_PLAN.md) will insert after
  `ClearFailedAttempts`. Otherwise a suspended enrolled user receives a live `mfa_token`,
  which leaks enrollment state and burns a challenge key for an account that can never
  complete a login.

The error must be the generic `ErrInvalidCredentials`; a distinct one tells an attacker their
target exists and is suspended. This is the only change to the public login path in this plan,
so it gets its own commit and its own care.

Suspension also has to hold for **bearer-authenticated** endpoints, not just login. It does,
but only because suspending bumps the epoch (§5.3) — which is what will make it cover MFA's
`/api/auth/mfa/*` management routes for free when they arrive. §13.2 records the one place
that is *not* covered automatically.

### 4.5 Audit and health

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/admin/audit?actor=&target=&action=&from=&to=&limit=&cursor=` | admin | Append-only; there is no delete endpoint (§6.3) |
| GET | `/admin/health` | — | Deep check: `db.PingContext` + `redis.Ping`, per-component status, 503 when either is down |

The existing `GET /health` ([routes.go:51-54](../cmd/server/routes.go#L51-L54)) prints a
constant and touches neither dependency, so it reports healthy through a total database
outage. Fixing the public one changes load-balancer behaviour and is out of scope (§14.1), but
the admin plane should have the real one from day one.

---

## 5. Data model

> **Migration numbering — decided.** This plan ships first and takes **`005` and `006`**.
> [MFA_PLAN.md §4.1](MFA_PLAN.md) currently reserves `005` for `create_user_mfa`; **it must be
> renumbered to `007`** before either lands. This is not bookkeeping: `golang-migrate` records
> the version integer in `schema_migrations` and **silently skips** a file whose version is
> already recorded. A developer who ran MFA's `005` in a local database would then never get
> `users.role`, and the binary would fail at runtime against a schema that looks migrated.
> Because it depends on which migrations each environment happened to run first, it can pass
> CI and fail in production. See §13.1.

### 5.1 `005_add_user_role_status`

```sql
-- 005_add_user_role_status.up.sql
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role   TEXT NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'support', 'admin')),
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended'));

-- Admin accounts are rare; a partial index keeps "list the admins" and the
-- last-admin guard cheap without indexing every ordinary user.
CREATE INDEX IF NOT EXISTS users_role_idx ON users (role) WHERE role <> 'user';

ALTER TABLE clients ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

-- Uniqueness must apply only to live rows, so a disabled URI can be recreated.
ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_redirect_uri_key;
CREATE UNIQUE INDEX IF NOT EXISTS clients_redirect_uri_live_idx
    ON clients (redirect_uri) WHERE disabled_at IS NULL;
```

Defaults chosen so the migration is a no-op for existing rows and existing queries. `GetUser`
([postgres.go:34-44](../internal/store/auth/postgres.go#L34-L44)) selects explicit columns, so
it keeps compiling untouched — it gains `status` only when suspension enforcement lands.

### 5.2 `006_create_admin_audit_log`

```sql
-- 006_create_admin_audit_log.up.sql
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id            BIGSERIAL   PRIMARY KEY,       -- ordered; UUIDs are not
    actor_id      UUID        REFERENCES users(id) ON DELETE SET NULL,
    actor_email   TEXT        NOT NULL,          -- snapshot, survives actor deletion
    actor_role    TEXT        NOT NULL,
    action        TEXT        NOT NULL,          -- 'user.unlock', 'client.create', …
    target_type   TEXT,                          -- 'user' | 'client' | null
    target_id     TEXT,
    target_label  TEXT,                          -- email / redirect_uri snapshot
    result        TEXT        NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
    metadata      JSONB       NOT NULL DEFAULT '{}',
    remote_addr   INET,
    forwarded_for TEXT,                          -- untrusted; recorded, not believed
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS admin_audit_created_idx ON admin_audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_target_idx  ON admin_audit_log (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_actor_idx   ON admin_audit_log (actor_id, created_at DESC);
```

- **`ON DELETE SET NULL`, not `CASCADE`.** Every other FK in this schema cascades; cascading
  here would mean *deleting an admin erases the record of what they did* — the wrong default,
  and an obvious cleanup move for anyone covering their tracks. `actor_email`/`actor_role` are
  snapshots for the same reason.
- **`BIGSERIAL`, not `gen_random_uuid()`.** Unlike every other table here this one is read in
  time order and paginated; a monotonic key is a stable cursor for free.
- **`forwarded_for` is separate from `remote_addr`.** The rate limiter's habit of believing
  `X-Forwarded-For` ([ratelimit.go:47](../internal/middleware/ratelimit.go#L47)) must not
  propagate here. `remote_addr` is the TCP peer and trustworthy; the header is a hint.
- **`result` includes `'denied'`.** A rejected privileged attempt is the most interesting row
  in this table.

### 5.3 Redis additions

| Key | Type | Value | TTL | Purpose |
|---|---|---|---|---|
| `auth:user:epoch:<user_id>` | string | unix seconds | ≥ `TOKEN_TTL` | Session-invalidation watermark: revoke-sessions, suspend, delete, role change |
| `auth:pwreset:<sha256(token)>` | string | `user_id` | `ADMIN_PWRESET_TTL` (15m) | Single-use admin-issued reset (§4.4) |

`Introspect` rejects a token whose `iat` is **at or before** the epoch. Use `iat <= epoch`,
not `<` — JWT `iat` has one-second granularity, so a token minted in the same second as a
revocation survives a strict comparison. Erring toward revoking one extra second is free.

`Logout` should *not* reject on the epoch: an already-dead token should still log out cleanly
rather than return an error the caller can't act on. A missing epoch key means "never
revoked", so this is backward compatible with tokens issued before the feature exists.

**`ExchangeCode` must check the epoch too**, and this is easy to miss because
[MFA_PLAN.md §5.3](MFA_PLAN.md) only specifies the `Introspect` side. An authorization code
already in flight when the epoch is bumped still redeems into a *newly minted* token whose
`iat` is after the epoch — so it survives, and "revoke all sessions" has a hole one `CODE_TTL`
(60s) wide. `RedeemCode` returns the `userID`, so the check is one Redis `GET` on a path that
already does several. The same hole would otherwise apply to MFA's enroll-confirm bump, so
closing it here closes it for both.

The epoch is bumped by: revoke-sessions, suspend, role change, delete, password-reset
redemption — and later by MFA enroll-confirm, MFA disable, and recovery-code regeneration.
Keep the bump behind a single `s.revokeUserSessions(ctx, userID)` helper rather than scattering
`BumpEpoch` calls, so MFA adds three call sites rather than three chances to forget one.

Redemption of a reset token is `GETDEL` (one atomic command, go-redis `GetDel`) so two
concurrent redemptions cannot both win.

---

## 6. Audit log

### 6.1 One helper, not a call per handler

```go
// audit records a privileged action. Every mutating admin handler goes through
// exactly one of these, including on the denial and error paths.
func (s *Service) audit(ctx context.Context, e AuditEvent) error
```

Handlers that write to Postgres pass the open `*sql.Tx` and the audit insert happens **in the
same transaction as the change** — either both land or neither does, and there is no such
thing as an unaudited mutation of `users` or `clients`.

Redis-only mutations (unlock, revoke-sessions) cannot join that transaction. There the audit
row is written after the operation with its real result, and a crash in the gap loses one
record. Documented and accepted — better than optimistically recording something that may not
have happened.

Actions: `admin.login.ok` / `.failed` · `authz.denied` · `user.unlock` ·
`user.revoke_sessions` · `user.suspend` / `.unsuspend` · `user.role_change` ·
`user.password_reset.issued` / `.redeemed` · `user.delete` · `client.create` / `.update` /
`.disable` / `.delete`.

Reads are **not** audited to the table — a support console would swamp it and the signal is in
the mutations. Reads still go to the request log.

### 6.2 Audit failure fails the request

Everywhere else in this codebase a logging failure is best-effort: `ClearFailedAttempts` logs
and carries on ([service.go:189-191](../internal/service/auth/service.go#L189-L191)), the rate
limiter fails open by design. **The admin plane inverts this.** If the audit write fails the
handler returns 500 and the mutation does not happen.

Put that reasoning in a comment on the helper — "why does this return an error instead of just
logging?" is exactly the question someone answers wrongly in six months.

### 6.3 Append-only

No delete or update endpoint, and the application's database role should not hold
`DELETE`/`UPDATE` on this table. Retention is a separate scheduled job with its own
credentials. An audit log the application can rewrite is one an attacker who owns the
application can rewrite.

---

## 7. Threat model

| Attack | Mitigation | Where |
|---|---|---|
| A relying app replays an admin's user JWT against `/admin` | Separate audience; admin tokens never issued through the code flow | §3.2 |
| An admin token used as a user token | Public plane already pins `aud: auth-service` | §3.2 |
| Forged/expired token slips through as authenticated | Admin plane uses its own parser and asserts a non-empty subject — it does **not** call `Introspect`, whose invalid-token result is `(Active:false, nil)` | §3.2 |
| Admin password brute-forced via the public login endpoint | Shared lockout; loopback-only admin listener; short admin TTL; generated (not human-chosen) admin passwords | §3.1, §3.3, §3.4 |
| Compromised admin demoted but keeps acting | Role re-read from Postgres per request; role change bumps the epoch | §3.6 |
| Support role escalates to takeover | Password reset is `admin`-only | §3.5 |
| Reset token stolen from Redis | Only `SHA-256(token)` stored; 15m TTL; single-use via `GETDEL` | §5.3 |
| Wrong account deleted by a mistyped ID | Confirmation echo — the body must repeat the target's email / redirect URI | §4.2, §4.4 |
| Whole admin plane locked out | Last-admin guard in-transaction; `adminctl` break-glass | §3.4, §3.5 |
| Admin plane reachable from the internet | Separate listener, `127.0.0.1` default, `ADMIN_API_ENABLED=false` default | §3.3, §9 |
| Rate-limit bypass via spoofed `X-Forwarded-For` | Admin limiter keys on `r.RemoteAddr` only and ignores proxy headers; fails **closed** | §8 |
| Deleted or suspended user keeps a live session | Epoch bump on delete, suspend, role change | §4.4, §5.3 |
| Admin actions unattributable afterwards | In-transaction audit, denials included, `ON DELETE SET NULL` preserves the record | §6 |
| Credential-bearing responses cached by a proxy | `Cache-Control: no-store` across the admin plane | §8 |
| CSRF against the admin plane | Bearer-only. Cookie auth is not implemented and must not be added — there is no ambient credential to ride | below |

**On CSRF:** the admin API is JSON + bearer only. Adding cookie auth "so a browser tool can
call it" would make every endpoint here CSRF-able against an admin's browser. If a UI ever
needs it, the UI does the token exchange and holds the token in memory. Worth a comment in the
admin router.

**On no MFA:** the honest summary is that a stolen or guessed admin password is a full
compromise of the admin plane, bounded only by the network boundary and the 15-minute token
TTL. That is an acceptable posture for a loopback-bound internal plane with generated
passwords; it is not acceptable for a publicly exposed one. **This is a temporary posture with
a defined end state** (§13.3), not a permanent trade — and whoever proposes
`ADMIN_BIND_ADDR=0.0.0.0` is the person who should ship MFA first.

---

## 8. Code changes, file by file

| Path | Change |
|---|---|
| `db/migrations/005_*`, `006_*` | §5.1, §5.2 |
| `internal/store/auth/store.go` | `Store` gains `GetUserByID`, `ListUsers`, `UpdateUserRole`, `UpdateUserStatus`, `UpdateUserPassword`, `DeleteUser`, `CountAdmins`, plus `clients` CRUD. `UserRecord` gains `Email`, `Role`, `Status`, `CreatedAt` |
| `internal/store/auth/postgres.go`, `memory.go` | Implementations. `ValidateRedirectURI` gains `AND disabled_at IS NULL` |
| `internal/store/auth/audit_postgres.go` | **new** — tx-aware insert + keyset-paginated query |
| `internal/store/redis/epoch.go` | **new** — `BumpEpoch` / `Epoch` |
| `internal/store/redis/pwreset.go` | **new** — `StoreResetToken` / `RedeemResetToken` (`GetDel`) |
| `internal/store/redis/locker.go`, `store.go` | Scope parameter on all four methods + new `Unlock`; key helpers become `auth:lockout:<scope>:…`. MFA's signature, adopted now (§13.1) |
| `internal/service/auth/deps.go` | `locker` interface gains the scope parameter and `Unlock`; new `epochStore`, `resetStore` interfaces |
| `internal/service/admin/service.go` | **new** — admin business logic, its own narrow dependency interfaces per [ARCHITECTURE.md §12](ARCHITECTURE.md#12-extending-the-service) |
| `internal/service/admin/auth.go` | **new** — admin login, admin-audience mint/parse, `requireRole` |
| `internal/service/auth/service.go` | `New` becomes `New(Deps, Config)` (§13.1); `Introspect` **and `ExchangeCode`** check the epoch (§5.3); `GenerateCode` rejects suspended users; password-reset redemption; client re-check in `ExchangeCode` (§4.2) |
| `internal/handler/admin/*.go` | **new** — handlers, the `authenticate` helper, structured JSON errors |
| `internal/middleware/security.go` | Add `Cache-Control: no-store` |
| `internal/middleware/ratelimit.go` | Add a variant that ignores proxy headers and **fails closed**. As a new constructor, not a change to the default — the public plane's fail-open is deliberate |
| `cmd/server/main.go` | Second `http.Server`, shared shutdown (§3.3) |
| `cmd/server/config.go` | §9 |
| `cmd/adminctl/main.go` | **new** — `promote` / `demote` / `list` (§3.4) |

### 8.1 Error shape

The public plane returns plain-text `http.Error` bodies
([ARCHITECTURE.md §8](ARCHITECTURE.md#8-api-surface)). The admin plane is machine-consumed and
returns:

```json
{"error": {"code": "user_not_found", "message": "no user with that id"}}
```

A deliberate inconsistency, not an oversight — say so in the handler package doc. Retrofitting
the public plane is a separate breaking change and must not ride along.

### 8.2 `requireAdmin` / `requireRole`

One place, used by every route, asserting in order: bearer token present → parses with the
**admin** audience → not blocklisted → `iat > epoch` → subject non-empty → user exists →
`status = 'active'` → **role read from that row** satisfies the route's requirement. Any
failure is a 401/403 plus an `authz.denied` audit row.

Routes declare their required role at registration, so a new endpoint cannot be added without
choosing one:

```go
admin.Handle("POST /admin/users/{id}/unlock", requireRole(roleSupport, h.Unlock))
```

**Name it `requireAdmin`, not `authenticate`.** [MFA_PLAN.md §6.5](MFA_PLAN.md) specifies a
helper called `authenticate` in `internal/handler/auth` that is built *on* `Introspect`. This
one must not be (§3.2). Two same-named helpers in sibling packages with opposite rules about
the same fail-open trap is an invitation to copy the wrong one into the wrong place. §13.1
asks MFA to use `requireUser` for the symmetric reason.

---

## 9. Configuration

| Variable | Default | Description |
|---|---|---|
| `ADMIN_API_ENABLED` | `false` | Master switch. The admin listener does not start unless `true` |
| `ADMIN_BIND_ADDR` | `127.0.0.1` | Interface for the admin listener. `0.0.0.0` is an explicit, reviewable act |
| `ADMIN_PORT` | `8081` | Admin listener port |
| `ADMIN_TOKEN_TTL` | `15m` | Admin JWT lifetime — deliberately much shorter than `TOKEN_TTL` |
| `ADMIN_RATE_LIMIT_PER_MIN` | `60` | Per real peer IP, per route. Fails **closed** |
| `ADMIN_PWRESET_TTL` | `15m` | Lifetime of an admin-issued password reset token |

`ADMIN_REQUIRE_MFA` is **reserved, not implemented** — see §13.3 for its default and startup
behaviour when MFA lands. Do not add it as a no-op flag now; a security setting that reads as
configured while doing nothing is worse than one that is absent.

> **A kill switch is correct here.** [MFA_PLAN.md §7](MFA_PLAN.md) removes `MFA_ENABLED`
> because switching a security control off is an attack. Switching the admin API off *reduces*
> attack surface — the failure mode of `ADMIN_API_ENABLED=false` is "an operator has to use
> psql", not "everyone's protection stopped applying". Defaulting to `false` means an
> environment that never opted in has no admin plane to attack.

Wire through `cmd/server/config.go` using the existing `envInt`/`envDuration` helpers, which
already treat malformed values as startup failures. Add a strict `envBool` — `INSECURE_COOKIES`
currently does a bare `== "true"` ([config.go:37](../cmd/server/config.go#L37)), so
`ADMIN_API_ENABLED=1` or `=TRUE` would silently mean *false*. That direction fails safe for
this flag, but the pattern shouldn't spread; reject anything that isn't a recognized boolean.
Add the block to `.env.example`, commented, with defaults shown.

---

## 10. Testing

### 10.1 Authorization — the table that must exist

Table-driven over **every registered admin route**:

- no token → 401
- malformed / wrongly-signed token → 401
- **valid user-audience token → 401** (the §3.2 regression guard — the important one)
- expired admin token → 401
- admin token whose `iat` predates the epoch → 401
- `support` token on an `admin`-only route → 403, plus an audit row with `result='denied'`
- suspended admin → 401

Drive it from the route table itself, not a hand-maintained list, so an endpoint added without
a `requireRole` fails the suite instead of shipping.

### 10.2 Service logic

- Last-admin guard: demoting/deleting the only `admin` fails; with two, it succeeds
- Self-demotion and self-deletion refused
- Role change, suspension, delete and revoke-sessions each bump the epoch; a token minted
  before the change stops introspecting as active, **including the same-second `iat <= epoch`
  boundary**
- `Logout` still succeeds for an epoch-revoked token
- **`ExchangeCode` rejects a code issued before the epoch bump** — the §5.3 hole. Without this
  test the 60-second window reopens the first time someone refactors the exchange path
- Unlock is scope-aware: `scope=pwd` leaves other scopes untouched, `scope=all` clears
  everything registered. Assert against the `locker` interface, not against literal Redis key
  strings, or the test bakes in the names §13.1 exists to stop anyone depending on
- Suspended user cannot obtain a code, and the error is indistinguishable from a wrong password
- Unlock clears both lockout keys and is idempotent
- Password reset: single-use (second redemption fails); expired token fails; redemption bumps
  the epoch and clears the lockout
- Reset token stored hashed — assert the raw token never appears as a Redis key
- Client create rejects a duplicate live `redirect_uri` with 409; `PATCH` rejects a
  `redirect_uri` change with 400; a disabled client fails `ValidateRedirectURI`; a disabled
  URI can be recreated
- Confirmation echo: `DELETE` with a mismatched email/URI is refused and nothing is deleted

### 10.3 Audit

- Every mutating handler produces exactly one row (drive from the route table again)
- A failing audit writer rolls back the Postgres mutation and returns 500 — the §6.2 guard
- Denied authorization produces `result='denied'`
- No row contains a password, a reset token, or a JWT. A substring assertion over a serialized
  row catches the whole class

### 10.4 Not covered

Postgres and Redis implementations stay untested until the repo grows an integration target,
consistent with [ARCHITECTURE.md §10](ARCHITECTURE.md#10-testing). Flag explicitly that the
last-admin guard is a `FOR UPDATE` transaction property the in-memory fake **cannot** prove —
two concurrent demotions are exactly the case the fake passes and Postgres might not.

---

## 11. Phases

Each phase compiles, passes tests, and is safe to merge alone.

| Phase | Contents | Size | Status |
|---|---|---|---|
| **A0a** | **Shared refactors, no new behaviour** — the §13.1 list: `Deps` constructor, scoped `locker` + `Unlock`, `GetUserByID`, epoch store with the `Introspect`/`ExchangeCode` checks, `Cache-Control: no-store`, `log/slog`. Every one of these is on MFA's P0. Existing suite must be green after each commit | medium | ✅ done |
| **A0b** | Admin foundation, no business endpoints: migrations 005/006, second listener, `ADMIN_API_ENABLED` (off), admin-audience mint/parse, `requireAdmin`/`requireRole`, audit helper + store, `adminctl`. Only `/admin/auth/*` and `/admin/health` exist | large | ✅ done |
| **A1** | Read-only: users list/get, clients list/get. Nothing destructive behind a brand-new auth plane | small | ✅ done |
| **A2** | Client CRUD + soft delete + the `ExchangeCode` client re-check. **Priority #1 lands here** | medium | ✅ done |
| **A3** | `unlock`, `revoke-sessions`, suspend/unsuspend, role change, and suspension enforcement in `GenerateCode` — the only public-path *behaviour* change in this plan (the epoch checks it relies on already landed in A0a) | medium | ✅ done |
| **A4** | Password reset (admin issue + public redemption), user delete | medium | ✅ done |
| **A5** | `GET /admin/audit`, README endpoint table, ARCHITECTURE §5/§6/§7/§8/§9/§12, `.env.example` | small | ✅ done |

> **Implementation notes** — three things the plan did not anticipate:
>
> 1. **`Unlock` had to be a new `locker` method, not a call to `ClearFailedAttempts`.** That
>    method deletes only the attempts counter; nothing in the codebase cleared the lock flag,
>    so before this there was no way to release a lock early at all (§4.4).
> 2. **`ExchangeCode`'s epoch check needed the code's issue time**, which was not stored. The
>    code payload gained an `issued_at` field and `codeStore` gained a return value. Both the
>    code timestamp and the epoch are truncated to whole seconds before comparison, so the
>    `<=` rule behaves identically to the JWT path.
> 3. **`internal/store/memory` was extracted** as a full mirror of `store/redis`. Two service
>    packages needed the same test doubles, and a per-package hand-rolled fake would have
>    drifted from the real key layout — exactly the failure mode §13.1 exists to prevent.
>
> **Post-implementation review** found seven issues in the above, all since fixed. Four are
> worth carrying as design notes rather than changelog entries:
>
> - **Session revocation runs *before* the change it accompanies**, not after (§4.4). The two
>   live in different stores and cannot share a transaction, so one must go first; revoking
>   first makes the failure mode "logged out for a change that did not happen" instead of
>   "suspended with live tokens", which is the guarantee these endpoints exist to give.
> - **A PATCH touching both `status` and `role` is one transaction** with one audit row per
>   change. Applying half and returning an error leaves a state the caller cannot reason about.
> - **Audit records are completed after the write, not before it** — otherwise `client.create`
>   names a null target and is unreachable by the target filter that an incident review runs
>   first. `mutate` therefore takes `*AuditEvent`.
> - **The audit table holds attributable actions only.** Failed authentication and failed
>   logins against unknown addresses go to `slog`: `/admin/auth/login` is unauthenticated, so
>   recording every attempt would let anyone who can reach the port write unbounded rows.
>   Failures against a *real* privileged account are attributable and are recorded.

**A0a is split out deliberately.** It is pure refactoring of code that already works and is
already under test, it touches every existing auth path, and it is the phase MFA inherits
(§13.1). Reviewing it mixed in with a new authorization plane means reviewing a login
regression risk and a privilege-escalation risk in the same diff. Land each item as its own
commit with the existing suite green after each — the same argument
[MFA_PLAN.md §11](MFA_PLAN.md) makes about its own P0, which is now this phase.

A0a+A0b together are most of the work and none of the visible value — the usual shape for a
security boundary. Resist folding A2 into them to have something to demo: the authorization
plane should be reviewed on its own, with no destructive endpoint pulling the reviewer's
attention away.

### Pre-merge checks for A3

- `go test -race ./...`
- Manual: log in as a user, `revoke-sessions`, confirm `POST /api/auth/introspect` reports the
  previously-valid token inactive
- Manual: suspend a user, confirm `POST /api/auth/login` fails with the same error and roughly
  the same timing as a wrong password
- Manual: a non-suspended user's login is byte-identical to before
- Manual: `curl` the admin port from another host with `ADMIN_BIND_ADDR` unset → refused

---

## 12. Deferred

### 12.1 Rate-limit override (`POST /admin/ratelimit/reset`)

Tempting for "the customer is being throttled". Its only function is turning off an abuse
protection for a chosen IP, it will be used under pressure by whoever is nearest the incident,
and the window it clears is 60 seconds. Wait it out.

### 12.2 Impersonation / "log in as this user"

The most-requested admin feature with the worst failure mode: it mints a token
indistinguishable from the user's own, so afterwards nobody — including forensics — can tell
which actions were the user's. If ever built it needs an `act` claim (RFC 8693 delegation)
carried through introspection, a hard TTL in minutes, its own audit action, and a decision
about whether the user is told. That is a design, not a feature request. The read-only support
views in §4.3 cover most of the real need.

### 12.3 Per-session listing and revocation

Needs a per-user `jti` index — a Redis sorted set scored by `exp`, written on issue and
trimmed with `ZREMRANGEBYSCORE` on read. Real work; revoke-all covers the incident-response
need at a fraction of the cost.

---

## 13. Building for the MFA plan

MFA is being built **after** this. That ordering is fine, but it is only free if the admin
plane is built against MFA's final shapes rather than interim ones. This section is the
contract in three parts: what A0a builds *for* MFA (§13.1), what MFA must not break when it
arrives (§13.2), and what MFA adds to this plane (§13.3).

### 13.1 A0a builds MFA's P0, in MFA's shapes

Every item below is already on [MFA_PLAN.md §9](MFA_PLAN.md)'s P0 list. Building them now with
the signatures MFA specifies costs a few extra characters; building them in an interim shape
costs a second refactor plus a window where this plane's endpoints are quietly wrong.

| Piece | Build it as | Why the final shape, now |
|---|---|---|
| **Scoped `locker`** | `IsLocked(ctx, scope, key)`, `RecordFailedAttempt(ctx, scope, key, ttl)`, `LockAccount(ctx, scope, key, ttl)`, `ClearFailedAttempts(ctx, scope, key)`, **`Unlock(ctx, scope, key)`**; keys `auth:lockout:<scope>:…`. Only `"pwd"` is used until MFA adds `"mfa"` | The single sharpest interaction. If unlock ships against today's unscoped keys, MFA's P0 renames them and `POST /admin/users/{id}/unlock` starts returning `200` while clearing nothing (§4.4) |
| **Per-user epoch** | `auth:user:epoch:<user_id>`, TTL ≥ `TOKEN_TTL`; checked in `Introspect` **and `ExchangeCode`** with `iat <= epoch`; all bumps behind one `revokeUserSessions` helper | [MFA_PLAN.md §5.3](MFA_PLAN.md) needs the identical primitive for enroll/disable/regenerate. Its `ExchangeCode` gap (§5.3 here) would otherwise ship into MFA too |
| **`Deps` struct constructor** | `New(Deps, Config) (*Service, error)`, rejecting any nil dependency by name | `New` is 6 positional args today ([service.go:92](../internal/service/auth/service.go#L92)); this plan makes it 8, MFA makes it 12, most of them indistinguishable interfaces. [MFA_PLAN.md §6.4.1](MFA_PLAN.md) wants it done "while the refactor is still mechanical" — that is now |
| **`GetUserByID`** on `store.Store` | Returns the full record incl. `Role`, `Status` | Both plans need it. Widen `store.Store` **once**: the interface, `postgres.go`, `memory.go` and every fake move together, so two independent widenings are pure merge churn |
| **`Cache-Control: no-store`** | Unconditional in `SecurityHeaders`, `/static/` opts back in | Same line, same file, same reason (reset tokens here, recovery codes there) |
| **`log/slog`** | Replace `log.Printf` in the auth service and middleware | [MFA_PLAN.md §6.3.1](MFA_PLAN.md) makes this MFA's problem otherwise. The admin plane is already adding structured events, so it is the natural moment |

Note what is **not** here: nothing in A0a knows what a second factor is. These are all
primitives that this plan needs on its own merits — MFA just happens to need the same ones,
which is why building them to its spec is cheap rather than speculative.

### 13.2 What MFA must do to stay compatible

All four are now recorded in [MFA_PLAN.md](MFA_PLAN.md) itself, at the sections that would
otherwise have told the reader to do the wrong thing. Kept here as the rationale.

1. ~~**Renumber `005_create_user_mfa` → `007`.**~~ ✅ Applied — [MFA_PLAN.md §4.1](MFA_PLAN.md)
   now specifies `007`, since this plan shipped `005` and `006`. The hazard it avoided:
   `golang-migrate` records the version integer and silently skips an already-recorded one,
   so a collision fails *quietly*, per-environment, and can pass CI (§5).
2. **`VerifyMFA` must re-check `users.status`.** MFA's verify step resolves the user from the
   challenge and calls `issueCode` without re-reading the row — so an admin who suspends an
   account mid-login is bypassed for the whole `MFA_CHALLENGE_TTL` (5 min) window. MFA already
   re-reads `mfa.Get` there to catch "MFA disabled between login and verify"; the status check
   belongs beside it. This is the one suspension path the epoch does *not* cover for free,
   because no bearer token is involved yet.
3. **Call the user-side helper `requireUser`, not `authenticate`** (§8.2). ✅ recorded in
   MFA_PLAN §6.5.
4. **Bump the epoch through `Service.RevokeSessions`**, not by calling `BumpEpoch` directly,
   so enroll-confirm / disable / regenerate join the existing call sites rather than forming
   a second set with their own TTL (§5.3). ✅ recorded in MFA_PLAN §5.3.

A fifth surfaced while applying these: **add the `mfa` scope to `store.LockScopes`**. That
slice drives `Service.Unlock`, `Service.LockState` and the admin `unlock?scope=all` endpoint,
so appending one entry makes OTP lockouts visible and clearable through the admin API with no
further edits. Omitting it means support can clear a password lockout but not an OTP one, and
nothing reports the difference. Recorded in MFA_PLAN §5.1.

### 13.3 What MFA adds to the admin plane

| Addition | Detail |
|---|---|
| `POST /admin/users/{id}/mfa/reset` | `support` role. Deletes `user_mfa` + recovery codes, bumps the epoch, audits as `user.mfa_reset`. This is the endpoint [MFA_PLAN.md §11/§12](MFA_PLAN.md) is blocked on — without it, MFA's deliberate lack of a global kill switch means a user who loses their phone and burns their recovery codes needs a DBA |
| The role split holds | **`support` gets MFA reset, `admin` keeps password reset.** Together they are account takeover, so no single role holds both (§3.5). Assign the new endpoint accordingly — this is the reason the split exists |
| `ADMIN_REQUIRE_MFA` | Default `true`. An account with `role != 'user'` and no confirmed factor cannot complete `POST /admin/auth/login`. Startup **fails** if it is `true` while MFA is unconfigured, rather than letting a security flag read as set while meaning nothing (§9) |
| `otp` on admin login | `POST /admin/auth/login` gains the field. Admin login already lives alone in `internal/service/admin/auth.go` so this is a contained change — do not scatter the password check across handlers in the meantime |
| The §7 posture note retires | Mandatory second factors are what would make `ADMIN_BIND_ADDR=0.0.0.0` defensible. Until then the network boundary is doing that job alone |

MFA also unblocks itself here in one place worth noting: [MFA_PLAN.md §1](MFA_PLAN.md) lists
"org-level MFA enforcement policy" as a non-goal because it "requires a clients-level policy
model **and an admin API**, neither of which exists yet." Half of that blocker disappears when
this ships. The policy model still does not exist, and inventing it from the admin side would
be the wrong layer — but the reason recorded in that non-goal will be out of date.

---

## 14. Adjacent findings

Surfaced while tracing the paths this plan touches. None block it.

1. **`GET /health` never checks its dependencies.** It writes a constant JSON literal
   ([routes.go:51-54](../cmd/server/routes.go#L51-L54)), so it reports healthy through a total
   Postgres or Redis outage — an orchestrator keeps routing traffic to a process that cannot
   serve a single login. The admin plane gets a real one (§4.5); splitting the public one into
   liveness (constant) and readiness (checks dependencies) is a separate change because it
   alters load-balancer behaviour.

2. **`ExchangeCode` never re-validates the client.** A code issued for a `redirect_uri` is
   redeemable even if the client row is deleted a second later
   ([service.go:222-233](../internal/service/auth/service.go#L222-L233)). §4.2 closes this as
   part of client disable; noting it separately because it is a small pre-existing gap.

3. **`INSECURE_COOKIES` parses with `== "true"`**
   ([config.go:37](../cmd/server/config.go#L37)), so `INSECURE_COOKIES=TRUE` silently means
   *false*. Harmless in that direction, but §9 adds a strict `envBool` worth retrofitting.

4. **`IMPROVEMENTS.md` is linked from README.md and ARCHITECTURE.md but does not exist** (also
   noted in [MFA_PLAN.md §13](MFA_PLAN.md)). ARCHITECTURE §9 cites it for six known gaps,
   three of which this plan touches. Create it or drop the links.

5. **`UserRecord` carries `PasswordHash` and is the only user type in the store layer**
   ([store.go:13-16](../internal/store/auth/store.go#L13-L16)). Fine while nothing serializes
   it; a hazard the moment an admin endpoint returns user data. §4.3's separate DTO is the
   guard, but the sharp edge is worth knowing about independently.
