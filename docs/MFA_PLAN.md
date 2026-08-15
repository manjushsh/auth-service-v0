# Multi-Factor Authentication — Implementation Plan

Status: **proposed** (no code written yet) — revised after security review
Scope owner: `internal/service/auth`
Related: [ARCHITECTURE.md](ARCHITECTURE.md), [../README.md](../README.md)

> **Review pass 1.** Five things were wrong or weak and are corrected in place: the OTP
> brute-force budget was resettable by re-entering the password (§5.1); `MFA_ENABLED=false`
> was a global second-factor bypass (§7); changing a factor left old sessions valid (§5.3);
> AES-GCM became XChaCha20-Poly1305 with no new module (§4.3); server-side PNG QR codes and
> their CSP relaxation were dropped for an `otpauth://` URI plus inline SVG (§2.3).
>
> **Review pass 2.** Three more: the password-verifying MFA management endpoints were an
> unthrottled password oracle that bypassed the login lockout entirely (§5.3 — the serious
> one this round); `Introspect`'s error shape makes the bearer-auth helper silently
> fail-open (§6.5); and the phase order shipped enrollment before enforcement, so users
> could enroll into a factor nothing checked (§9). Plus a constructor-shape problem
> (§6.4.1), a non-atomic Redis write (§6.4), and missing `Cache-Control: no-store` (§6.5).
>
> Adjacent findings outside this plan's scope are in §13.
>
> **Update — the admin API shipped first.** It built most of P0 to this plan's own
> specifications (scoped `locker`, per-user epoch, `Deps` constructor, `GetUserByID`,
> injectable clock, `Cache-Control: no-store`, `log/slog`), so those sections now describe
> existing code and are marked ✅. Three things changed as a result: migration `005` became
> **unpinned — take the next free number** (§4.1); `VerifyMFA` gained a mandatory account re-read, because suspension is a
> state the challenge snapshot can miss (§6.3); and admin MFA reset moved out of "future
> work" into **P6** (§9). Search for ✅ to see what is already done.

---

## 0. TL;DR

Add TOTP (RFC 6238, "authenticator app") as a second factor, plus single-use recovery
codes as the backup channel. The authorization-code flow gains one intermediate step:
when a user with MFA enabled submits a correct password, the service returns an
**MFA challenge token** instead of an authorization code. The client submits that token
plus a 6-digit code to `/api/auth/mfa/verify`, which returns the authorization code.
Everything downstream (`/api/auth/token`, JWT, blocklist) is unchanged except for a new
`amr` claim recording which factors were used.

Seven phases (P0–P6), each independently mergeable. P0 is pure refactoring of existing code;
enrollment stays closed by config until enforcement ships (§9).

---

## 1. Goals and non-goals

### Goals

| # | Goal |
|---|---|
| G1 | Users can enroll a TOTP authenticator (Google Authenticator, Aegis, 1Password, …) |
| G2 | Enrollment is **confirmed** — a secret never becomes an active factor until the user proves they can generate a code from it |
| G3 | Login requires the second factor when enrolled, and cannot be bypassed by calling the API directly |
| G4 | TOTP secrets are encrypted at rest; a Postgres dump alone does not yield working second factors |
| G5 | Users get 10 single-use recovery codes so a lost phone is not an account loss |
| G6 | Relying applications can tell from the JWT whether MFA was actually used (`amr` claim) |
| G7 | Brute force against the 6-digit code is bounded, both per-challenge and per-account |
| G8 | The MFA path **fails closed** — if Redis or Postgres is unavailable, login fails rather than skipping the second factor |
| G9 | Works through both the JSON API and the hosted HTML login page |

### Non-goals (explicitly deferred)

| Item | Why deferred |
|---|---|
| WebAuthn / passkeys | Much larger surface (attestation, credential storage, browser JS). The challenge/`amr` structure below is designed so a second factor *type* can be added later without reshaping the login flow. |
| SMS / email OTP | SP 800-63B-4 classifies PSTN-delivered OTP as a *restricted* authenticator (SIM-swap, SS7). Email OTP is a single factor re-delivered, not a real second factor. Not worth building. |
| "Remember this device" / trusted devices | Real usability win, but it is a separate signed-cookie subsystem with its own revocation story. Sketched in §12. |
| Org-level MFA enforcement policy | Requires a `clients`-level policy model, which does not exist. (The admin API half of this blocker is gone — it shipped — but inventing the policy model from the admin side would be the wrong layer.) |
| Encryption-key rotation tooling | The schema carries a `key_version` column from day one so rotation is *possible*; the re-encrypt job itself is out of scope. |
| Admin/support MFA reset | **No longer deferred** — the admin plane exists and reserved the endpoint at `support` level. Moved into scope as **P6** (§9). |

---

## 2. Research summary

### 2.1 Standards

- **RFC 6238 (TOTP)** — HMAC over a time counter. Two requirements that are easy to miss:
  - §5.2: *the verifier must reject a second use of an OTP that has already been validated*.
    A 30-second code with ±1 step of skew is replayable for up to 90 seconds otherwise.
    This drives the replay-guard key in §4.2.
  - §6: the shared secret must be protected at rest — hence the AEAD encryption in §4.3.
- **RFC 4226 (HOTP)** §7.3 — throttling is mandatory for a 6-digit code. 10⁶ codespace
  and a 90-second acceptance window means an unthrottled endpoint is trivially brute-forced.
- **NIST SP 800-63B-4** — software OTP authenticators are acceptable at AAL2. Relevant
  points: ≥112-bit security strength for the seed (a 160-bit/20-byte secret satisfies
  this), and account-recovery mechanisms must be at least as strong as the factor they
  replace (which is why recovery codes are 128-bit random, not a memorable phrase).
- **RFC 8176** — `amr` (Authentication Methods References) claim values. We will emit
  `["pwd"]` or `["pwd","otp"]`; `mfa` is the registered value for "multiple factors used".

### 2.2 TOTP implementation choice

| Option | Verdict |
|---|---|
| **`github.com/pquerna/otp` v1.5.0** | **Recommended.** De-facto standard for Go, Apache-2.0, used by HashiCorp Vault/OpenBao. Handles base32 padding, `otpauth://` URI construction, digit/period/algorithm options, and constant-time comparison. Its only non-test requirement is `github.com/boombuler/barcode`, needed solely by `Key.Image()` — which we do not call (§2.3), so it never links into the binary. |
| Hand-rolled RFC 6238 | ~50 lines with `crypto/hmac`, `crypto/sha1`, `encoding/base32`, and testable against the RFC 6238 appendix B vectors. Consistent with this repo's habit of writing its own CSRF/rate-limit/lockout. But the failure modes (base32 padding, truncation offset, non-constant-time compare) are silent and security-relevant. Not worth the dependency saved. |

Either way the library sits behind a narrow `totpVerifier` interface (§6.2) so it can be
swapped without touching the service.

### 2.3 QR code

**Do not render QR server-side for the API.** `MFAEnrollResponse` returns the
`otpauth://` URI and the base32 secret; rendering is the client's problem. That is what
every provider does, and it keeps an image encoder off the login path.

For the *hosted* enrollment page only, render an **inline `<svg>`** using
[`github.com/piglig/go-qr`](https://github.com/piglig/go-qr) (pure Go, zero dependencies,
actively maintained — unlike `skip2/go-qrcode`, last touched in 2020).

Inline SVG markup is part of the document, so it satisfies `default-src 'self'` as-is.
This removes the CSP relaxation the earlier draft of this plan needed: a PNG `data:` URI
would have required widening the policy to `img-src 'self' data:`, and every CSP directive
you never add is one you never have to defend.

---

## 3. Flow design

### 3.1 Where the second factor goes

The current login is one round trip: `POST /api/auth/login` → authorization code.
Two ways to add a factor:

| Approach | Assessment |
|---|---|
| **A. Two-step challenge** — password returns an `mfa_token`; a second call exchanges `mfa_token` + OTP for the authorization code. | **Chosen.** Matches how every hosted login page works (you cannot ask for the OTP before you know whether the account needs one). Lets the OTP step be rate-limited and attempt-capped independently. Extends cleanly to other factor types. |
| B. Single-step — send `email`, `password`, `otp` together. | Simpler, but the hosted UI cannot use it (the page must first discover MFA is required), and a wrong OTP forces the client to re-send the password, so credentials get re-transmitted on every retry. |

### 3.2 Login with MFA

```
Client                     auth-service                          Redis / Postgres
  │                             │                                       │
  │ POST /api/auth/login        │                                       │
  │ {email, password,           │  GenerateCode()                       │
  │  redirect_uri}              │   1. locker.IsLocked?                 │
  ├────────────────────────────>│   2. GetUser + bcrypt compare         │
  │                             │   3. mfaStore.Get(userID) ────────────>│ SELECT ... user_mfa
  │                             │      no row → fall through to          │
  │                             │      today's path, unchanged          │
  │                             │   4. MFA enabled:                     │
  │                             │      ClearFailedAttempts (pwd scope)  │
  │                             │      challenge = random(32B)          │
  │                             ├──────────────────────────────────────>│ SET auth:mfa:challenge:<t>
  │ 200 {mfa_required: true,    │                                        │     {user_id,email,
  │      mfa_token: "..."}      │                                        │      redirect_uri} EX 300
  │<────────────────────────────┤                                       │
  │                             │                                       │
  │ POST /api/auth/mfa/verify   │  VerifyMFA()                          │
  │ {mfa_token, code,           │   1. challenge.Consume-or-count ──────>│ Lua: GET + HINCRBY attempts
  │  redirect_uri}              │      (attempt N of 5, else DEL)       │
  ├────────────────────────────>│   2. mfaStore.Get + cipher.Open       │
  │                             │   3. totp.Validate(code, skew=±1)     │
  │                             │      └─ or recovery-code redemption   │
  │                             │   4. replay guard SETNX ──────────────>│ SET auth:mfa:used:<u>:<h>
  │                             │                                        │     NX EX 90
  │                             │   5. DEL challenge (single use)       │
  │                             │   6. issue authorization code         │
  │ 200 {code, redirect_url}    │      (identical to today)             │
  │<────────────────────────────┤                                       │
  │                             │                                       │
  │ POST /api/auth/token ───────┴──> unchanged, JWT now carries amr:["pwd","otp"]
```

Users **without** MFA see byte-for-byte the same behaviour as today.

### 3.3 Enrollment

```
1. POST /api/auth/mfa/enroll            Bearer JWT + {password}
     → verifyPassword() — lockout-aware, never a bare bcrypt compare (§5.2)
     → refuse if MFA already confirmed
     → generate 20-byte secret, encrypt, store in Redis under
       auth:mfa:enroll:<user_id> with a 10-minute TTL  ← NOT Postgres
     → 200 {secret, otpauth_uri}        ← client renders its own QR (§2.3)

2. POST /api/auth/mfa/enroll/confirm    Bearer JWT + {code}
     → read pending secret from Redis (404 if expired → restart)
     → validate code against it (skew ±1)
     → INSERT INTO user_mfa (..., confirmed_at = NOW())
     → generate 10 recovery codes, store HMAC-SHA-256 hashes (§4.1)
     → bump auth:user:epoch:<user_id>   ← invalidates pre-MFA sessions (§5.3)
     → DEL the pending key
     → 201 {recovery_codes: [...]}      ← shown once, Cache-Control: no-store
```

The pending secret lives in **Redis, not Postgres**, so an abandoned enrollment expires by
itself and an unconfirmed secret can never be mistaken for an active factor. This is G2.

### 3.4 Recovery and disable

- `POST /api/auth/mfa/verify` accepts a recovery code in the same `code` field
  (discriminated by length/format). Redemption is an atomic `UPDATE ... WHERE used_at IS
  NULL` so a code cannot be spent twice, even concurrently.
- Redeeming a recovery code emits `amr: ["pwd","otp"]` too — it *is* a second factor — but
  the response includes `recovery_codes_remaining` so the client can nag the user.
- `POST /api/auth/mfa/disable` requires **password + a current OTP or recovery code**.
  Deletes the `user_mfa` row and all recovery codes (cascade).
- `POST /api/auth/mfa/recovery-codes` regenerates all 10, invalidating the previous set in
  the same transaction.

---

## 4. Data model

### 4.1 Postgres — migration `NNN_create_user_mfa`

> **Take the next free number when you write it — do not pin one here.** This section has
> already been renumbered twice (`005` → `007`) because shipped migrations kept claiming the
> number a plan had reserved: the admin API took `005`, `006`, then `007` for a users index.
> As of writing the next free number is **008**, but check `db/migrations/` rather than
> trusting that.
>
> The hazard is worth restating because it fails quietly: `golang-migrate` records the
> version integer in `schema_migrations` and **silently skips** a file whose version is
> already recorded. A developer who had run an earlier `005_create_user_mfa` locally would
> never receive `users.role`, and the binary would fail at runtime against a schema that
> looks fully migrated. Because it depends on which migrations each environment happened to
> run first, it can pass CI and fail in production.

```sql
-- NNN_create_user_mfa.up.sql
CREATE TABLE IF NOT EXISTS user_mfa (
    user_id       UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_cipher BYTEA       NOT NULL,   -- version||nonce||AEAD(base32 secret)
    key_version   SMALLINT    NOT NULL DEFAULT 1,
    algorithm     TEXT        NOT NULL DEFAULT 'SHA1'
                              CHECK (algorithm IN ('SHA1','SHA256','SHA512')),
    digits        SMALLINT    NOT NULL DEFAULT 6  CHECK (digits BETWEEN 6 AND 8),
    period        SMALLINT    NOT NULL DEFAULT 30 CHECK (period > 0),
    confirmed_at  TIMESTAMPTZ NOT NULL,   -- the row only exists once confirmed (§3.3)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  BYTEA       NOT NULL,      -- HMAC-SHA-256(pepper, raw code)
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS mfa_recovery_codes_user_hash_idx
    ON mfa_recovery_codes (user_id, code_hash);
```

```sql
-- NNN_create_user_mfa.down.sql
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS user_mfa;
```

Notes on specific columns:

- **`algorithm` / `digits` / `period` are stored, not assumed.** They cost nothing now and
  mean a future move to SHA-256 or 8 digits does not require re-enrolling existing users —
  validation reads the parameters the secret was issued under.
- **`key_version`** exists purely so encryption-key rotation is a background job later
  rather than a migration emergency. Adding the column now is free; adding it after
  10k rows exist is not.
- **Recovery codes are HMAC-SHA-256, not bcrypt.** Deliberate: the codes are 128 bits of
  `crypto/rand`, so there is nothing to brute-force and no need for a slow KDF. A fast hash
  also lets us look codes up by index instead of bcrypt-comparing against all 10 rows.
  (bcrypt is required for *passwords* precisely because passwords are low-entropy.)
  Keying the hash with a server-side pepper — reuse `MFA_ENCRYPTION_KEY` under a distinct
  HKDF label, do **not** use the raw key for two purposes — costs one line and means a
  database dump alone cannot be tested against a stolen code list.
- **`confirmed_at NOT NULL`.** An earlier draft made it nullable "in case" a pending state
  ever lands here. A column whose NULL case is unreachable is a column someone will
  eventually write a `WHERE confirmed_at IS NOT NULL` guard against and get wrong. Pending
  enrollment lives in Redis; the row's existence *is* the confirmation.
- **`ON DELETE CASCADE`** on both tables — deleting a user must not orphan a second factor.

### 4.2 Redis key space (additions)

| Key | Type | Value | TTL | Purpose |
|---|---|---|---|---|
| `auth:mfa:challenge:<token>` | hash | `user_id`, `email`, `redirect_uri`, `attempts` | `MFA_CHALLENGE_TTL` (5m) | Binds a verified password to a pending OTP step |
| `auth:mfa:enroll:<user_id>` | string | encrypted pending secret | `MFA_ENROLL_TTL` (10m) | Unconfirmed enrollment |
| `auth:mfa:used:<user_id>:<hash(code)>` | string | `1` | `period × (2×skew+1)` = 90s | RFC 6238 §5.2 replay guard |
| `auth:mfa:failures:<email>` | string | counter | `MFA_LOCKOUT_DURATION` (15m) | **Separate** OTP-failure budget — see §5.1 |
| `auth:mfa:locked:<email>` | string | `1` | `MFA_LOCKOUT_DURATION` | OTP-step lock flag |
| `auth:user:epoch:<user_id>` | string | unix seconds | ≥ `TOKEN_TTL` | Session-invalidation watermark — see §5.3 |

All of these follow the existing conventions in `internal/store/redis/store.go` (prefix
`auth:`, TTL on every key, atomic Lua where a read-modify-write is involved).

Two details worth pinning down:

- `<hash(code)>` in the replay-guard key should be the **same peppered HMAC** used for
  recovery codes (§4.1), not a bare digest. It costs nothing and avoids parking a
  recognisable fingerprint of a live OTP in Redis for 90 seconds.
- `auth:user:epoch:<user_id>` is the one key here without a natural TTL. Give it
  `≥ TOKEN_TTL` rather than persisting forever — once every token predating the bump has
  expired on its own, the watermark carries no information. That keeps the invariant the
  ARCHITECTURE doc states about Redis: nothing in it needs to survive a flush.

### 4.3 Secret encryption

TOTP secrets are **symmetrically encrypted, not hashed** — verification needs the plaintext
secret, so hashing is not an option.

**Cipher: XChaCha20-Poly1305**, from `golang.org/x/crypto/chacha20poly1305` — a module
already in `go.mod` as a direct dependency (bcrypt lives there), so this adds **zero new
modules**. Chosen over AES-256-GCM because its 24-byte nonce can be drawn randomly with no
collision budget worth reasoning about, whereas AES-GCM's 12-byte nonce technically has
one. It is also constant-time in pure software; AES-GCM is only constant-time where AES-NI
is available, which is not guaranteed across deployment targets.

> If FIPS 140 validation is ever a requirement, switch to `crypto/aes` + `cipher.NewGCM`.
> The `Cipher` interface in §6.2 and the `version` byte in the blob below exist so that is
> a one-file change, not a migration.

- 32-byte key from `MFA_ENCRYPTION_KEY` (base64), length-validated at startup;
- a fresh 24-byte `crypto/rand` nonce per encryption, stored alongside the ciphertext;
- **the user ID as additional authenticated data (AAD)**, so a row copied from user A to
  user B fails to decrypt. This is cheap and closes a real attack (an attacker with SQL
  write access swapping in a secret they control).

Blob layout: `version(1B) || nonce(24B) || ciphertext+tag`.

The recovery-code pepper (§4.1) must be **derived** from `MFA_ENCRYPTION_KEY` via HKDF with
a distinct label, not the key itself — one key, one purpose.

The key is a *separate secret from `JWT_SECRET`*. Deploying them to different places (e.g.
KMS/secret-manager vs. env) means one leak is not automatically both.

---

## 5. Threat model — how each attack is addressed

| Attack | Mitigation | Where |
|---|---|---|
| Brute-force the 6-digit code | 5 attempts per challenge, **plus a separate per-account OTP-failure counter that a successful password login does not reset**. See §5.1 — the obvious design here is wrong. | §5.1 |
| Replay a sniffed OTP inside its validity window | `SETNX auth:mfa:used:<user>:<hash>` with a 90s TTL; second use is rejected. Atomic, so concurrent replay loses too. | §4.2 |
| Skip MFA by calling `/api/auth/token` directly | Unchanged — the authorization code is only ever issued *after* `VerifyMFA` succeeds. There is no code to exchange. | §3.2 |
| Skip MFA by ignoring `mfa_required` in the login response | Same: the response contains no `code` and no `redirect_url` when MFA is required. Nothing to ignore. | §6.1 |
| Postgres dump → working second factors | Secrets are AEAD-encrypted (XChaCha20-Poly1305) with a key held outside the database; recovery codes are peppered. | §4.3 |
| SQL write access → attacker swaps in their own TOTP secret | User ID bound as AEAD additional data; a transplanted row fails to decrypt. | §4.3 |
| Stolen JWT used to add/remove a factor | Every MFA management endpoint requires password re-auth; disable additionally requires a current OTP. | §3.3, §3.4 |
| Recovery code reuse | `UPDATE ... SET used_at = NOW() WHERE id = $1 AND used_at IS NULL` — zero rows affected means already spent. | §3.4 |
| Recovery codes guessed | 128 bits of `crypto/rand`; also subject to the per-challenge attempt cap. | §4.1 |
| MFA-enabled user enumeration | `mfa_required` is only returned *after* a correct password, so it reveals nothing an attacker did not already have. | §3.2 |
| Challenge token stolen from a log / referrer | 5-minute TTL, single use, bound to the `redirect_uri`, and useless without the OTP. Must never appear in a URL — POST body only. | §6.1 |
| **Redis down → MFA silently skipped** | **Fail closed.** Challenge creation failure returns 500 and no authorization code. This is the opposite of the rate limiter's deliberate fail-open, and the distinction must be stated in the code comment or a future reader will "fix" it. | G8 |
| Race: two concurrent verifies on one challenge | Consumption is a single Lua script (read + increment + conditional delete), so only one caller can win. | §6.3 |
| Enrolling/disabling MFA leaves old sessions valid | Per-user token epoch; tokens issued before the change stop introspecting as active. | §5.3 |
| **Stolen JWT → grind the password via `/mfa/disable`** | Every password check routes through one `verifyPassword` helper that owns the lockout, not just the login handler. | §5.2 |
| Recovery codes / JWTs cached by a proxy or browser | `Cache-Control: no-store` on every response carrying a credential. | §6.5 |

### 5.1 The OTP-failure counter must be independent of the password counter

This is the one place where reusing the existing `locker` is actively wrong, and it is
worth spelling out because the intuitive design has a hole.

`GenerateCode` clears the failed-attempt counter as soon as bcrypt succeeds
([service.go:189](../internal/service/auth/service.go#L189)):

```go
// Successful login, clear any previous failed attempts.
if err := s.locker.ClearFailedAttempts(ctx, email); err != nil { ... }
```

If OTP failures increment that same counter, an attacker **who already has the password**
gets an unbounded OTP-guessing budget:

```
loop:
  POST /api/auth/login      → password OK → counter cleared → fresh mfa_token
  POST /api/auth/mfa/verify → 5 wrong OTPs → challenge destroyed
  goto loop                                  # counter is zero again
```

Nothing ever locks. The only remaining bound is the per-IP rate limiter — which fails open
on Redis errors *by design*, and trusts `X-Forwarded-For` unconditionally
([ratelimit.go:47](../internal/middleware/ratelimit.go#L47)), so it is spoofable whenever
the service is reachable without a proxy in front. That is a documented existing gap; MFA
must not be built on top of it.

**Required design:**

1. OTP failures increment `auth:mfa:failures:<email>`, a namespace the password path never
   touches. `ClearFailedAttempts` on password success must not reach it.
2. `VerifyMFA` checks `auth:mfa:locked:<email>` **first**, before touching the challenge,
   and returns `ErrAccountLocked` when set.
3. Only a *successful* OTP or recovery-code redemption clears
   `auth:mfa:failures:<email>`.
4. `GenerateCode` should also refuse to mint a new challenge while the OTP lock is set —
   otherwise a locked-out attacker still gets to burn Redis keys.

> **✅ Already built.** The admin API shipped the scoped `locker` in its A0a phase, with the
> signature below plus an `Unlock(ctx, scope, key)` the interface previously lacked entirely.
> The Redis keys are already `auth:lockout:<scope>:…`, and `store.LockScopePassword` /
> `store.LockScopeMFA` are defined. What remains for MFA is *using* the `mfa` scope.

```go
type locker interface {
    IsLocked(ctx context.Context, scope, key string) (bool, error)
    RecordFailedAttempt(ctx context.Context, scope, key string, ttl time.Duration) (int, error)
    LockAccount(ctx context.Context, scope, key string, ttl time.Duration) error
    ClearFailedAttempts(ctx context.Context, scope, key string) error
    Unlock(ctx context.Context, scope, key string) error
}
// scope is store.LockScopePassword ("pwd") or store.LockScopeMFA ("mfa"); the
// Redis key helpers are attemptsKey(scope, email) → "auth:lockout:<scope>:attempts:<email>"
```

Two follow-ups when the `mfa` scope goes live:

- **Add it to `store.LockScopes`.** That slice is what `Service.Unlock` and the admin
  `POST /admin/users/{id}/unlock?scope=all` iterate, so appending one entry makes the admin
  unlock endpoint cover the OTP scope with no further edits. Forgetting it means support can
  clear a password lockout but not an OTP lockout, with no error to say so.
- `Service.LockState` iterates the same slice, so `GET /admin/users/{id}` starts reporting
  OTP lockouts for free.

> Note the deliberate asymmetry: locking the OTP step by email is a self-inflicted-DoS
> vector only for someone who already knows the victim's password. That is a much narrower
> exposure than the existing password-step lockout (which anyone can trigger against any
> known email — the open finding in ARCHITECTURE §9), so it does not make things worse.

### 5.2 Every password check must go through the lockout, not just login

`StartEnrollment` and `DisableMFA` both take `{password}` and bcrypt-compare it (§3.3, §3.4).
As written, neither consults the lockout and neither records a failure — so they are
**unthrottled password-guessing oracles**, reachable by anyone holding a bearer token for
that account:

```
POST /api/auth/mfa/disable   Authorization: Bearer <token>
{"password": "guess-1", "code": "000000"}     → 401, no counter touched
{"password": "guess-2", "code": "000000"}     → 401, no counter touched
...
```

`MAX_LOGIN_ATTEMPTS` never trips because the login path is never used. The only bound is the
per-IP rate limiter — which fails open and trusts `X-Forwarded-For` (§5.1). This is
strictly worse than the login endpoint it routes around, and it is created *by this plan*:
these endpoints do not exist today.

It matters most in the exact scenario MFA is meant to defend: an attacker with a stolen
JWT but not the password. Today that attacker cannot escalate. With an unthrottled password
oracle they can grind for the password and then turn the second factor off.

**Required design:** extract the credential check into one place and route every caller
through it.

> **✅ Already built**, and exported, because the admin plane's login needed exactly this:
>
> ```go
> // VerifyPassword performs the lockout check, the bcrypt comparison, the
> // suspension check and the failure accounting as a single unit.
> func (s *Service) VerifyPassword(ctx context.Context, email, password string) (store.UserRecord, error)
> ```
>
> `GenerateCode` is now a thin caller of it, and `POST /admin/auth/login` goes through the
> same helper — which is what stops the admin endpoint becoming a second, unthrottled
> password oracle. `TestLogin_SharesTheAccountLockout` in `internal/service/admin` is the
> regression guard.

`StartEnrollment`, `DisableMFA` and `RegenerateRecoveryCodes` must all call it — never
`bcrypt.CompareHashAndPassword` directly. Enforce that by convention *and* by keeping
`bcrypt.CompareHashAndPassword` to exactly two appearances in the package: inside
`VerifyPassword` and in the `dummyHash` timing path it already owns.

Two consequences worth stating:

- The management endpoints inherit the account-lockout DoS property of the login endpoint.
  That is the correct trade: an attacker who can lock the account this way already holds a
  valid token for it.
- `DisableMFA` requires password **and** a valid OTP. Wrong-password attempts hit the `pwd`
  scope, wrong-OTP attempts hit the `mfa` scope (§5.1). Keep them separate; do not
  collapse them because both happen to live in one handler.

### 5.3 Changing a factor must invalidate existing sessions

Enrolling MFA, disabling it, or regenerating recovery codes are all security-state changes.
Today the only revocation mechanism is the per-`jti` blocklist, which cannot express
"revoke everything for user X" — so a token stolen *before* enrollment keeps working
afterwards, and MFA provides no protection to the session it was supposed to protect.

> **✅ Already built.** The per-user epoch shipped with the admin API's A0a phase, because
> admin revoke-sessions, suspension, deletion and role change all needed the same primitive.
> Everything below is describing existing behaviour; **MFA's remaining work is three call
> sites, not an implementation.**

- `auth:user:epoch:<user_id>` = unix seconds, TTL `2 × TOKEN_TTL`. Bumped today by admin
  revoke-sessions, suspension, role change, deletion and password-reset redemption.
- `token.Verifier` rejects a token whose `iat` is at or before the epoch. The comparison is
  **`iat <= epoch`, not `<`** — JWT `iat` has one-second granularity, so a token minted in
  the same second as the change would survive a strict `<`. Erring toward revoking one extra
  second is free; the alternative is a race that only shows up under load.
- `ExchangeCode` applies the same rule to the authorization code's issue time. This is not
  redundant with the `Introspect` check and was missing from the original draft of this
  section: a code already in flight redeems into a *newly minted* token whose `iat` is
  after the epoch, so without it every revocation had a hole one `CODE_TTL` wide. The code
  payload carries `issued_at` for exactly this, and both sides are truncated to whole
  seconds before comparing.
- `Logout` does *not* reject on the epoch — a token that is already dead should still log
  out cleanly rather than return an error the caller cannot act on.
- A missing epoch key means "never changed", so this is backward compatible with tokens
  issued before the feature existed.

**What MFA must do:** bump the epoch on enroll-confirm, disable, and recovery-code
regeneration — by calling **`Service.RevokeSessions(ctx, userID)`**, not `BumpEpoch`
directly. That helper owns the TTL and is where every existing bump already goes; adding a
second, parallel set of call sites is how one of them ends up forgotten or given the wrong
TTL. It is also what makes the `amr` claim honest: without it, `amr: ["pwd"]` tokens from
before enrollment linger.

---

## 6. Code changes, file by file

### 6.1 `internal/model/auth/user.go` — wire types

```go
// GenerateCodeResponse gains two fields. Both are omitempty, so the shape is
// unchanged for users without MFA.
type GenerateCodeResponse struct {
    Code        string `json:"code,omitempty"`         // ← now omitempty
    RedirectURL string `json:"redirect_url,omitempty"`
    MFARequired bool   `json:"mfa_required,omitempty"`
    MFAToken    string `json:"mfa_token,omitempty"`
}

type VerifyMFARequest struct {
    MFAToken    string `json:"mfa_token"`
    Code        string `json:"code"`         // TOTP digits or a recovery code
    RedirectURI string `json:"redirect_uri"`
}
// Response reuses GenerateCodeResponse, plus:
//   RecoveryCodesRemaining *int `json:"recovery_codes_remaining,omitempty"`

type MFAEnrollRequest  struct{ Password string `json:"password"` }
type MFAEnrollResponse struct {
    Secret     string `json:"secret"`        // base32, for manual entry
    OTPAuthURI string `json:"otpauth_uri"`   // client renders its own QR (§2.3)
}
type MFAConfirmRequest  struct{ Code string `json:"code"` }
type MFAConfirmResponse struct{ RecoveryCodes []string `json:"recovery_codes"` }
type MFADisableRequest  struct{ Password, Code string }
type MFAStatusResponse  struct {
    Enabled                bool  `json:"enabled"`
    ConfirmedAt            int64 `json:"confirmed_at,omitempty"`
    RecoveryCodesRemaining int   `json:"recovery_codes_remaining"`
}
```

**Client-visible contract change:** for an MFA-enabled user, `/api/auth/login` no longer
returns `code`. Existing integrations keep working until their users enroll. This belongs
in the README changelog.

### 6.2 `internal/service/auth/deps.go` — new narrow interfaces

Following the rule in ARCHITECTURE §12 (interface here, implementation in a store package):

```go
type mfaStore interface {
    Get(ctx context.Context, userID string) (store.MFARecord, error) // ErrNotFound if unenrolled
    Create(ctx context.Context, rec store.MFARecord, codeHashes [][]byte) error // one tx
    Delete(ctx context.Context, userID string) error
    RedeemRecoveryCode(ctx context.Context, userID string, hash []byte) error  // ErrNotFound if spent/absent
    CountUnusedRecoveryCodes(ctx context.Context, userID string) (int, error)
    ReplaceRecoveryCodes(ctx context.Context, userID string, hashes [][]byte) error // one tx
}

type mfaChallengeStore interface {
    StoreChallenge(ctx context.Context, token string, c Challenge, ttl time.Duration) error
    // ConsumeAttempt atomically fetches the challenge and increments its attempt
    // counter, deleting it once maxAttempts is reached. Returns ErrNotFound when
    // the challenge is gone or exhausted.
    ConsumeAttempt(ctx context.Context, token string, maxAttempts int) (Challenge, error)
    DeleteChallenge(ctx context.Context, token string) error

    StorePendingEnrollment(ctx context.Context, userID string, blob []byte, ttl time.Duration) error
    PendingEnrollment(ctx context.Context, userID string) ([]byte, error)
    DeletePendingEnrollment(ctx context.Context, userID string) error

    // MarkOTPUsed returns false if this code was already consumed (replay).
    MarkOTPUsed(ctx context.Context, userID, codeHash string, ttl time.Duration) (bool, error)
}

type totpVerifier interface {
    Generate(issuer, account string) (secret, otpauthURI string, err error)
    Validate(code, secret string, t time.Time, opts store.MFAParams) (bool, error)
}

type cipher interface {
    Seal(plaintext, aad []byte) ([]byte, error)
    Open(blob, aad []byte) ([]byte, error)
}
```

`store.Store` also needs the management endpoints to resolve a user from a JWT `sub` rather
than an email — **already available**, added by the admin API's A0a phase:

```go
GetUserByID(ctx context.Context, userID string) (UserRecord, error)
```

`UserRecord` now also carries `Email`, `Role`, `Status` and `CreatedAt`, so the re-read in
§6.3's `VerifyMFA` needs no extra query.

### 6.3 `internal/service/auth/` — new files

| File | Contents |
|---|---|
| `mfa.go` | `StartEnrollment`, `ConfirmEnrollment`, `DisableMFA`, `MFAStatus`, `RegenerateRecoveryCodes`, `VerifyMFA`, recovery-code generation/hashing |
| `service.go` (edit) | `Service` gains `mfa`, `challenges`, `totp`, `cipher`, `now func() time.Time`; `Config` gains the MFA knobs; `GenerateCode` gains the MFA branch; `ExchangeCode` and `parseToken` learn the `amr` claim |

The `GenerateCode` change is small and lands right after the existing
`ClearFailedAttempts` call:

```go
rec, err := s.mfa.Get(ctx, u.ID)
switch {
case errors.Is(err, store.ErrNotFound): // no MFA — existing path, unchanged
case err != nil:
    return model.GenerateCodeResponse{}, err   // fail closed
default:
    token, err := randomString()
    if err != nil { return model.GenerateCodeResponse{}, err }
    ch := Challenge{UserID: u.ID, Email: email, RedirectURI: req.RedirectURI}
    if err := s.challenges.StoreChallenge(ctx, token, ch, s.cfg.MFAChallengeTTL); err != nil {
        return model.GenerateCodeResponse{}, err // fail closed: no code is issued
    }
    return model.GenerateCodeResponse{MFARequired: true, MFAToken: token}, nil
}
```

Code issuance is currently inline at the end of `GenerateCode`; extract it into
`func (s *Service) issueCode(ctx, userID, redirectURI string) (model.GenerateCodeResponse, error)`
so `VerifyMFA` reuses it verbatim instead of duplicating the redirect-URL assembly.

`VerifyMFA` outline:

```go
func (s *Service) VerifyMFA(ctx, req) (model.GenerateCodeResponse, error) {
    ch, err := s.challenges.ConsumeAttempt(ctx, req.MFAToken, s.cfg.MFAMaxAttempts)
    if err != nil { return ..., ErrInvalidMFAToken }
    if ch.RedirectURI != req.RedirectURI { return ..., ErrInvalidMFAToken } // same binding as codes

    // Per-account OTP lock, checked against the "mfa" scope — NOT the password
    // counter, which a successful login clears. See §5.1.
    if locked, err := s.locker.IsLocked(ctx, scopeMFA, ch.Email); err != nil {
        return ..., err                        // fail closed
    } else if locked {
        return ..., ErrAccountLocked
    }

    // Re-read the account. The challenge is up to MFA_CHALLENGE_TTL old, and
    // anything an admin did to this user in the meantime must take effect —
    // see the note below.
    u, err := s.store.GetUserByID(ctx, ch.UserID)
    if err != nil || u.Suspended() {
        return ..., ErrInvalidMFAToken
    }

    rec, err := s.mfa.Get(ctx, ch.UserID)
    if errors.Is(err, store.ErrNotFound) {
        // MFA was disabled between login and verify. Do not fall through to
        // issuing a code — the challenge is stale, make the user log in again.
        return ..., ErrInvalidMFAToken
    }
    if err != nil { return ..., err }
    secret, err := s.cipher.Open(rec.SecretCipher, []byte(ch.UserID))
    if err != nil { return ..., err }

    ok, usedRecovery, err := s.checkFactor(ctx, ch.UserID, string(secret), rec.Params, req.Code)
    if err != nil { return ..., err }
    if !ok {
        s.recordFailedAttempt(ctx, scopeMFA, ch.Email)
        s.audit(ctx, "mfa.verify.failed", ch.UserID)
        return ..., ErrInvalidMFACode
    }

    s.challenges.DeleteChallenge(ctx, req.MFAToken)        // single use
    s.locker.ClearFailedAttempts(ctx, scopeMFA, ch.Email)  // only success clears it
    s.audit(ctx, "mfa.verify.ok", ch.UserID, "recovery", usedRecovery)
    return s.issueCode(ctx, ch.UserID, ch.RedirectURI)     // + recovery_codes_remaining
}
```

`checkFactor` tries TOTP first (numeric, `digits` long), else recovery-code redemption.
On TOTP success it calls `MarkOTPUsed`; a `false` return means replay → treat as failure.

Note that **every** early return above is a denial. There is no branch in `VerifyMFA` that
issues a code without a validated factor, and no `err != nil` path that falls through. That
property is what §8.1's fail-closed tests exist to protect.

> **Why the account re-read is not optional.** `GenerateCode` rejects a suspended user
> ([service.go](../internal/service/auth/service.go), immediately after the bcrypt
> comparison), but `VerifyMFA` resolves the user from the *challenge* — a snapshot taken
> before the password step. Without re-reading, an admin who suspends an account
> mid-login is bypassed for the whole `MFA_CHALLENGE_TTL` window (5 minutes by default),
> and the user walks away with a valid authorization code.
>
> This is the one suspension path the epoch does **not** cover for free. Everywhere else, a
> suspended user is stopped because suspension bumps `auth:user:epoch:<user_id>` and the
> bearer token dies — but here no token exists yet, so there is nothing for the epoch to
> invalidate. The check has to be explicit.
>
> It costs one primary-key lookup on a path that already does several, and it sits beside
> the `mfa.Get` check for the same reason: both ask "is the state this challenge was issued
> under still true?"

### 6.3.1 Audit logging

The service currently logs only HTTP requests and internal errors. MFA introduces events
that matter for incident response and that a user is entitled to be told about, and there is
nowhere to put them.

Add a minimal structured audit sink — `log/slog` to stdout is enough for v1 (stdlib since
Go 1.21; this module is on Go 1.26 and still uses the old `log` package throughout, so this
is also the natural moment to start migrating). Emit at least:

| Event | Fields |
|---|---|
| `mfa.enroll.started` / `.confirmed` / `.failed` | user_id, ip |
| `mfa.disabled` | user_id, ip |
| `mfa.verify.ok` / `.failed` | user_id, ip, whether a recovery code was used |
| `mfa.recovery.redeemed` | user_id, ip, codes remaining |
| `mfa.locked` | user_id, ip |
| `mfa.challenge.exhausted` | user_id, ip |

**Never log** the OTP, the secret, the `mfa_token`, or a recovery code — log the user ID and
the outcome. Worth a comment on the sink itself, because "just log the code to debug it" is
the single most likely way this gets undone in six months.

### 6.3.2 Injectable clock

Add `now func() time.Time` to `Service`, defaulting to `time.Now` in `New` (as a `Deps`
field — §6.4.1). Without it, TOTP skew and replay-window tests have to sleep, and tests
that sleep get deleted. `ExchangeCode` should switch to `s.now()` in the same change.

New sentinel errors, alongside the existing block in `service.go`:

```go
ErrInvalidMFAToken   = errors.New("invalid or expired mfa challenge")
ErrInvalidMFACode    = errors.New("invalid mfa code")
ErrMFAAlreadyEnabled = errors.New("mfa already enabled")
ErrMFANotEnabled     = errors.New("mfa not enabled")
ErrNoPendingEnroll   = errors.New("no pending mfa enrollment")
```

### 6.4 New packages

| Path | Purpose |
|---|---|
| `internal/secrets/aead.go` | `Cipher` type: `NewCipher(key []byte) (*Cipher, error)` (requires exactly 32 bytes), `Seal(pt, aad)`, `Open(blob, aad)`, plus the HKDF-derived recovery-code pepper. ~70 lines over `x/crypto/chacha20poly1305` + `x/crypto/hkdf` — no new modules. |
| `internal/totp/totp.go` | Thin adapter over `pquerna/otp`: `Generate` builds the key and the `otpauth://` URI; `Validate` calls `totp.ValidateCustom` with the stored period/digits/algorithm and `Skew: cfg.Skew`. Keeps the dependency in exactly one file. No image encoding — see §2.3. |
| `internal/handler/ui/qr.go` | Inline-SVG QR rendering via `piglig/go-qr`, hosted page only. |
| `internal/store/auth/mfa_postgres.go` | `mfaStore` on Postgres. `Create` and `ReplaceRecoveryCodes` use an explicit `sql.Tx`. |
| `internal/store/auth/mfa_memory.go` | In-memory `mfaStore` for tests, mirroring `memory.go`. |
| `internal/store/redis/mfa.go` | Challenge / pending-enrollment / replay-guard keys. `ConsumeAttempt` is a Lua script (see below). |

The `ConsumeAttempt` Lua script — same pattern as the existing `incrWithExpireScript`:

```lua
-- KEYS[1] = challenge key, ARGV[1] = maxAttempts
if redis.call("EXISTS", KEYS[1]) == 0 then return nil end
local n = redis.call("HINCRBY", KEYS[1], "attempts", 1)
local data = redis.call("HGETALL", KEYS[1])
if n >= tonumber(ARGV[1]) then redis.call("DEL", KEYS[1]) end
return data
```

Read + increment + conditional delete in one atomic step, so concurrent guesses cannot
each get a fresh attempt budget. Three implementation notes:

- **`StoreChallenge` must also be a single script.** A hash needs `HSET` followed by
  `EXPIRE`, and a crash between them leaves a challenge key with no TTL — *exactly* the
  failure `incrWithExpireScript` was written to prevent
  ([store.go:28-34](../internal/store/redis/store.go#L28-L34)). Repeating the bug the
  codebase already has a comment explaining would be an unforced error. Use
  `HSET ... ; EXPIRE ...` inside one `redis.NewScript`, or store the challenge as a JSON
  string via `SET key val EX ttl` (atomic in one command) and keep `attempts` as a separate
  counter — the single-script hash is tidier because the two halves cannot diverge.
- **`n >= maxAttempts` deletes on the last attempt, including a successful one.** That is
  intended — `VerifyMFA` already holds the returned data — but it means `maxAttempts` is the
  count of guesses *including* the winning one. Say so in the config docs so nobody
  "fixes" it to `>`.
- `HGETALL` returns a flat `[field, value, field, value, …]` array to go-redis, not a map.
  Parse in pairs.

### 6.4.1 `New()` takes a `Deps` struct

> **✅ Already built.** The admin API's A0a phase converted `New` to `New(Deps, Config)` with
> nil-dependency rejection, for the reason this section argued: the parameter list had grown
> to the point where transposing two indistinguishable interfaces would build cleanly and
> fail at runtime in a security-critical path.

MFA adds four fields to the existing struct:

```go
type Deps struct {
    Store     store.Store
    Codes     codeStore
    Blocklist blocklist
    Locker    locker
    Epochs    epochStore
    Resets    resetStore
    Audit     auditStore
    Tokens    *token.Manager
    Now       func() time.Time // nil → time.Now

    // added by this plan:
    MFA        mfaStore
    Challenges mfaChallengeStore
    TOTP       totpVerifier
    Cipher     cipher
}
```

Two things to carry over rather than reinvent:

- **Add each new dependency to the nil check in `New`.** A nil `Cipher` or nil `MFA` reaching
  production is a silent MFA bypass, and `New` is the only place that can catch it cheaply.
  `TestNew_RejectsNilDependency` is table-driven over the field list, so extend that table in
  the same commit — otherwise the new fields are the only ones unguarded.
- **`Now` already exists** and is threaded through the service, the token manager and the
  volatile store by the test clock, which is what makes the second-granular epoch boundary
  testable without sleeping. TOTP skew and replay-window tests get the same seam for free.

Note also that `JWTSecret []byte` is gone: token minting moved to `internal/token.Manager`,
which validates the secret length once at construction and owns the user/admin audience
split. MFA's `amr` claim (§6.8) belongs on `token.Claims`, which already declares the field.

Relatedly, split `mfaChallengeStore` (§6.2). As written it bundles three unrelated
lifetimes — login challenges, pending enrollments, and the OTP replay guard — into one
eight-method interface, which is the opposite of the narrow-interface rule in
ARCHITECTURE §12. Three interfaces (`challengeStore`, `enrollmentStore`, `otpReplayGuard`),
one Redis type satisfying all three, and each consumer depends only on what it uses.

### 6.5 `internal/handler/auth/handler.go`

Extend the `service` interface and add five handlers. Error mapping:

| Service error | HTTP |
|---|---|
| `ErrInvalidMFAToken` | 401 |
| `ErrInvalidMFACode` | 401 |
| `ErrMFAAlreadyEnabled` | 409 |
| `ErrMFANotEnabled` | 409 |
| `ErrNoPendingEnroll` | 400 |
| `ErrAccountLocked` | 429 (existing) |

The management endpoints share a small helper that extracts the bearer token, resolves it,
and returns the `sub` — rather than each handler re-implementing it.

**Call it `requireUser`, not `authenticate`.** The admin plane already has a `requireAdmin`
with the same job and the opposite rule about `Introspect` (it must not use it at all,
because admin tokens carry a different audience). Two same-named helpers in sibling handler
packages, differing on exactly the trap described below, is an invitation to copy the wrong
one into the wrong place. Distinct names make the mistake visible at the call site.

**That helper is a trap, and it must be written carefully.** `Introspect` reports an invalid
token as a *successful call with a false result*
([service.go:276-279](../internal/service/auth/service.go#L276-L279)):

```go
claims, err := s.parseToken(tokenString)
if err != nil {
    return model.IntrospectResponse{Active: false}, nil   // ← err is nil
}
```

So the obvious handler shape fails open:

```go
resp, err := h.svc.Introspect(ctx, token)
if err != nil { /* 401 */ }        // never fires for a forged token
userID := resp.Subject             // "" — and now an unauthenticated caller is inside
```

An empty `sub` happens to fail downstream today (Postgres rejects `''` for a UUID column,
the memory store finds nothing), so this is a latent bug rather than a live one — but it is
latent only by accident, and the accident is a database type check, not an auth decision.
The helper must assert **`resp.Active && resp.Subject != ""`** and return 401 otherwise:

```go
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
    token := extractBearerToken(r)
    if token == "" { http.Error(w, "...", http.StatusUnauthorized); return "", false }
    resp, err := h.svc.Introspect(r.Context(), token)
    if err != nil  { http.Error(w, "internal error", 500); return "", false }
    if !resp.Active || resp.Subject == "" {
        http.Error(w, "invalid token", http.StatusUnauthorized); return "", false
    }
    return resp.Subject, true
}
```

Add a handler test that passes a syntactically valid but wrongly-signed JWT and asserts 401
on **every** management endpoint. This is the cheapest possible guard against the whole
class.

#### `Cache-Control` on credential-bearing responses

> **✅ Already built.** `SecurityHeaders` now sets `Cache-Control: no-store` on everything
> except `/static/`, which opts back in — the fix this section recommended.

It matters more once MFA lands than it did when the gap was found: `MFAConfirmResponse`
returns ten long-lived recovery codes in a response body, and the hosted UI renders them into
HTML that a browser will happily write to disk. Nothing more to do here, but the hosted
enrollment page must not add its own caching headers on top.

**Note:** `fakeService` in `handler_test.go` must gain the new methods or the package stops
compiling. Same for `service` in `internal/handler/ui/handler.go`.

### 6.6 `cmd/server/routes.go`

```go
mux.Handle("POST /api/auth/mfa/verify",         rl(http.HandlerFunc(authH.VerifyMFA)))
mux.Handle("POST /api/auth/mfa/enroll",         rl(http.HandlerFunc(authH.MFAEnroll)))
mux.Handle("POST /api/auth/mfa/enroll/confirm", rl(http.HandlerFunc(authH.MFAConfirm)))
mux.Handle("POST /api/auth/mfa/disable",        rl(http.HandlerFunc(authH.MFADisable)))
mux.Handle("GET  /api/auth/mfa/status",     rlToken(http.HandlerFunc(authH.MFAStatus)))
mux.Handle("POST /api/auth/mfa/recovery-codes", rl(http.HandlerFunc(authH.MFARecoveryCodes)))

// UI
mux.HandleFunc("GET /login/mfa", uiH.MFAPage)
mux.Handle("POST /login/mfa", rl(http.HandlerFunc(uiH.MFASubmit)))
```

Everything credential-adjacent gets the tight `rl` tier; only the read-only status endpoint
gets `rlToken`.

### 6.7 `internal/handler/ui/`

`LoginSubmit` currently redirects to `resp.RedirectURL` unconditionally. It must branch:

```go
if resp.MFARequired {
    // mfa_token in a short-lived cookie, never a query string — a token in the URL
    // leaks via Referer, browser history, and access logs.
    http.SetCookie(w, &http.Cookie{
        Name:     "mfa_token",
        Value:    resp.MFAToken,
        Path:     "/login/mfa",          // narrower than the CSRF cookie's "/"
        HttpOnly: true,
        Secure:   h.secureCookies,
        SameSite: http.SameSiteStrictMode,
        MaxAge:   int(mfaChallengeTTL.Seconds()),
    })
    http.Redirect(w, r, "/login/mfa?redirect_uri="+url.QueryEscape(redirectURI), http.StatusFound)
    return
}
```

`MFASubmit` must delete the cookie (`MaxAge: -1`, same Name/Path) on **both** success and
terminal failure — otherwise a spent or exhausted challenge token sits in the browser until
its TTL expires. The `Path` is deliberately narrower than the CSRF cookie's `/`: nothing
outside `/login/mfa` has any business receiving it.

New `templates/mfa.html`: one 6-digit field (`inputmode="numeric"`,
`autocomplete="one-time-code"`), a "use a recovery code instead" toggle, CSRF hidden field,
and the same `pageData` error rendering the login page uses. `pageData` gains a
`RecoveryMode bool`.

### 6.8 JWT `amr` claim

`RegisteredClaims` has no extension point, so a custom claims type is required:

```go
type tokenClaims struct {
    jwt.RegisteredClaims
    AMR []string `json:"amr,omitempty"`
}
```

`ExchangeCode` sets `AMR: []string{"pwd"}` or `{"pwd","otp"}`, `parseToken` returns
`*tokenClaims`, and `IntrospectResponse` gains `AMR []string \`json:"amr,omitempty"\``.
Tokens issued before this change simply decode with a nil `AMR`, so it is backward
compatible — but it means the authorization code must carry the AMR from the login step
through to exchange. Extend `codePayload` in `internal/store/redis/code.go` with an
`amr` field and widen `codeStore.StoreCode`/`RedeemCode` accordingly.

> This is the one change that ripples furthest (three interfaces, both fakes). If it makes
> the first PR too large, land phases 1–3 without `amr` and add it as its own phase — the
> flow works without it; relying parties just cannot distinguish MFA'd sessions yet.

---

## 7. Configuration

| Variable | Default | Required | Description |
|---|---|---|---|
| `MFA_ENCRYPTION_KEY` | — | **yes** | base64 of exactly 32 random bytes. `openssl rand -base64 32` |
| `MFA_ENROLLMENT_OPEN` | `true` | no | `false` stops *new* enrollments. **It does not disable verification for already-enrolled users** — see the note below |
| `MFA_ISSUER` | `auth-service` | no | Label shown in the authenticator app |
| `MFA_CHALLENGE_TTL` | `5m` | no | Lifetime of an `mfa_token` |
| `MFA_ENROLL_TTL` | `10m` | no | Lifetime of a pending enrollment secret |
| `MFA_MAX_ATTEMPTS` | `5` | no | OTP guesses per challenge before it is destroyed |
| `MFA_MAX_VERIFY_FAILURES` | `10` | no | Per-account OTP failures before the OTP step locks (§5.1) |
| `MFA_LOCKOUT_DURATION` | `15m` | no | How long the OTP step stays locked |
| `MFA_TOTP_SKEW` | `1` | no | Time steps of clock drift tolerated either side (±30s at the default period) |
| `MFA_RECOVERY_CODES` | `10` | no | Codes issued per enrollment |

> **On the missing kill switch.** An earlier draft of this plan had `MFA_ENABLED=false`
> skip the login challenge entirely, as a production escape hatch. That is a
> single-environment-variable bypass of every user's second factor — precisely the lever an
> attacker with config access, or an operator under incident pressure, will pull. A
> security control with a documented off switch is a security control with a documented
> attack. The flag is therefore reduced to gating *new enrollments*; enrolled users are
> always challenged. If an individual user is genuinely locked out, the answer is an
> authenticated admin reset path (§12), not a global one.

`MFA_ENCRYPTION_KEY` is now unconditionally required, since the code path that reads it can
no longer be switched off. Generating it must be part of the deployment checklist, and it
must be a *different* secret from `JWT_SECRET`, stored somewhere `JWT_SECRET` is not.

Wire through `cmd/server/config.go` using the existing `envInt`/`envDuration` helpers —
which already treat a malformed value as a *startup failure*, matching ARCHITECTURE §6.
`MFA_ENCRYPTION_KEY` needs a new `envBase64Key` helper that validates the decoded length is
32 and fails startup otherwise. Add all of these to `.env.example`, commented, with defaults
shown — same style as the existing block.

Deliberate: **there is no `MFA_REQUIRED` global**. Forcing MFA on every account is a policy
decision that needs a migration path (grace period, enrollment interstitial) rather than a
boolean. Deferred with the rest of policy enforcement (§1).

---

## 8. Testing

### 8.1 `internal/service/auth` — the bulk

Extend the existing fakes (`fakeCodeStore`, `fakeBlocklist`, `fakeLocker`) with
`fakeMFAStore`, `fakeChallengeStore`, and a real `secrets.Cipher` over a fixed test key —
the crypto is fast and testing against the real implementation is more valuable than a
fake here.

- Enrollment: start → confirm with a code derived from the returned secret → `Get` shows
  confirmed; wrong code at confirm leaves MFA off; expired pending secret → `ErrNoPendingEnroll`
- Start enrollment with a wrong password → `ErrInvalidCredentials`
- Start enrollment when already enrolled → `ErrMFAAlreadyEnabled`
- `GenerateCode` for an enrolled user returns `MFARequired`, **empty `Code`, empty `RedirectURL`**
- `GenerateCode` for a non-enrolled user is unchanged (regression guard on the existing tests)
- `VerifyMFA` happy path → a code that `ExchangeCode` accepts, JWT has `amr: [pwd, otp]`
- **Replay:** the same OTP twice → second attempt `ErrInvalidMFACode`
- **Skew:** with the injected clock, `t-30s` and `t+30s` accepted, `t±60s` rejected
- **Attempt cap:** `MFAMaxAttempts` wrong codes → challenge destroyed; a *correct* code
  afterwards still fails
- **§5.1 regression guard (the important one):** loop *N* times — log in with the correct
  password, burn all `MFAMaxAttempts` on the resulting challenge — and assert that after
  `MFA_MAX_VERIFY_FAILURES` total OTP failures the account is OTP-locked, *even though every
  iteration passed the password check*. This test fails against the naive
  "reuse the password counter" implementation, which is exactly why it is worth writing
- Password-step and OTP-step lockouts are independent: locking one does not lock the other,
  and a successful password login does not clear the OTP counter
- Challenge is single-use; a mismatched `redirect_uri` at verify fails
- MFA disabled between login and verify → `ErrInvalidMFAToken`, no code issued
- Recovery code: redeem once → success; redeem again → failure; count decrements
- Disable requires password **and** a valid factor; after disable, login returns a code directly
- **Fail-closed:** a challenge store that returns an error → `GenerateCode` errors and
  returns no code (this is the test that protects G8 from a future refactor)
- **§5.2 regression guard:** `MAX_LOGIN_ATTEMPTS` wrong passwords submitted to
  `StartEnrollment` (not to login) must lock the account — proving the management endpoints
  share the login lockout rather than routing around it. Repeat for `DisableMFA`
- **§5.3:** a token issued before enroll-confirm introspects as inactive afterwards. The
  `<=` boundary and the `ExchangeCode` case are already covered by
  `TestRevokeSessions_*` / `TestExchangeCode_RejectsCodeIssuedBeforeRevocation`; what MFA
  adds is asserting that enroll-confirm, disable and regenerate each reach
  `RevokeSessions` at all
- **Suspension during the challenge window (§6.3):** suspend an account between
  `GenerateCode` and `VerifyMFA`, then submit a *correct* OTP — no code may be issued. This
  is the test that fails against the obvious implementation, which trusts the challenge's
  snapshot of the user
- Nil-dependency guard: `New(Deps{...})` with a nil `Cipher` or nil `MFA` returns an error
  rather than constructing a service that silently skips MFA

### 8.2 `internal/totp`

Validate the adapter against the RFC 6238 Appendix B vectors (secret `12345678901234567890`,
known outputs at fixed timestamps). Cheap, and it catches base32/padding mistakes whichever
implementation ends up behind the interface.

### 8.3 `internal/secrets`

Round-trip; wrong key fails; **wrong AAD fails** (this is the test that proves the
user-ID-binding in §4.3 actually works); tampered ciphertext fails; nonce differs across
two encryptions of the same plaintext; the HKDF-derived recovery pepper is **not** equal to
the raw `MFA_ENCRYPTION_KEY` (cheap guard against someone "simplifying" the derivation away).

### 8.4 `internal/handler/auth`

Status-code mapping for the new errors, following the existing table-driven style. Plus the
one from §6.5: a **wrongly-signed but well-formed JWT must produce 401 on every management
endpoint** — table-driven over the endpoint list, so a future endpoint added without the
`requireUser` helper fails the suite instead of shipping. The admin plane already does this
by driving the table off its route list rather than a hand-maintained one
([ADMIN_API_PLAN.md §10.1](ADMIN_API_PLAN.md)); copy that shape.

### 8.5 Not covered (consistent with today's gaps)

The Postgres `mfaStore` and the Redis stores stay untested until the repo grows an
integration-test target — same position as the existing Postgres/Redis adapters. Worth
noting that `RedeemRecoveryCode`'s single-use guarantee is a *SQL-level* property
(`WHERE used_at IS NULL`) that the in-memory fake cannot prove. Flag it for review rather
than pretending the fake covers it.

---

## 9. Implementation phases

Each phase compiles, passes tests, and is safe to merge alone.

> **Sequencing hazard.** P2 ships the enrollment *API*; P3 ships the login *enforcement*.
> Between those two deploys there is a window where a user can enroll a TOTP secret, scan
> the QR, see "MFA enabled" — and log in with a password alone, because `GenerateCode` does
> not yet branch. That is worse than having no MFA: it is a security control the user
> believes in and that does not exist.
>
> Ship P2 with **`MFA_ENROLLMENT_OPEN=false` as the deployed default**, flip it to `true`
> only once P3 is live, or merge P2 and P3 into one release. The flag exists for exactly
> this (§7). Whichever route, no user-facing "enable MFA" affordance appears before
> enforcement does.

| Phase | Contents | Reviewable size |
|---|---|---|
| **P0** | ~~`Deps` struct + nil checks (§6.4.1), `VerifyPassword` helper (§5.2), `locker` scope (§5.1), injectable clock, `Cache-Control: no-store` (§6.5), `log/slog`, per-user epoch (§5.3), `GetUserByID`~~ — **all shipped by the admin API's A0a phase.** What remains: `internal/secrets` + `MFA_ENCRYPTION_KEY` plumbing | small |
| **P1** | Migration `NNN_create_user_mfa` — next free number, §4.1, `mfa_postgres.go`, `mfa_memory.go`, `redis/mfa.go` — `GetUserByID` already exists | medium |
| **P2** | `internal/totp`, enrollment/confirm/disable/status/recovery-code service methods + API handlers + routes + the `requireUser` helper (§6.5). **Deploys with `MFA_ENROLLMENT_OPEN=false`** | large |
| **P3** | Login challenge branch, `VerifyMFA` (incl. the account re-read — §6.3), OTP lockout scope + `store.LockScopes` entry (§5.1), model changes, handler + route. **Flip `MFA_ENROLLMENT_OPEN=true` only after this is live** | medium |
| **P4** | Hosted UI: `mfa.html`, `MFAPage`/`MFASubmit`, `LoginSubmit` branch, inline-SVG QR (no CSP change) | medium |
| **P5** | `amr` claim end to end (`token.Claims.AMR` already exists; wire `codePayload` and `IntrospectResponse`) | medium |
| **P6** | Admin MFA reset endpoint at `support` role ([ADMIN_API_PLAN.md §13.3](ADMIN_API_PLAN.md)), `ADMIN_REQUIRE_MFA`, `otp` on admin login | small |
| **P7** | README endpoint table + flow, ARCHITECTURE §4/§5/§6/§7/§9, `.env.example` | small |

P0 grew in review pass 2 into the load-bearing phase, then shrank to almost nothing: the
admin API needed the same seams and built them first, to this plan's specifications. The
scoped locker, the per-user epoch, the `Deps` constructor, `GetUserByID`, the injectable
clock, `no-store` and `log/slog` all exist. Everything after P0 still assumes those seams —
it just no longer has to create them.

Two consequences worth stating: the riskiest refactoring is already merged and under test, so
the remaining phases are additive; and P3's OTP lockout is now a matter of *using* the `mfa`
scope rather than introducing scoping, which removes the signature change that would
otherwise have rippled through every locker call site mid-feature.

Ordering rationale: P0 and P1 are pure infrastructure with no behaviour change. P2 lets a
developer enroll via curl and verify against a real authenticator app **before** any login
path changes — so if TOTP interop is wrong, it surfaces before it can lock anyone out. P3
is the only phase that changes existing behaviour. P5 is separable on purpose (§6.8).

P6 is the reciprocal of what the admin API did for this plan: it adds the MFA reset endpoint
that [ADMIN_API_PLAN.md §13.3](ADMIN_API_PLAN.md) reserved at `support` level, plus
`ADMIN_REQUIRE_MFA`. **Do not ship P3 without P6 close behind** — §11 accepts "a user burns
their recovery codes and needs a DBA" only as a temporary state, and P6 is what ends it.
P6 is also what makes exposing the admin plane beyond loopback defensible, since admin
accounts have no second factor until then.

### Pre-merge checks for P3 (the risky one)

- `go test -race ./...`
- Manual: enroll → log out → log in → confirm the challenge step appears and a real
  authenticator app's code is accepted
- Manual: stop Redis, attempt a login as an enrolled user → **must fail**, must not issue
  a code
- Manual: a non-enrolled user's login is byte-identical to before

---

## 10. Documentation to update

- **README.md** — endpoint table (6 new rows), the "Flow" section (steps 2a/2b), a short
  "Enabling MFA" walkthrough, and a note that `/api/auth/login` returns `mfa_required`
  instead of `code` for enrolled users. Also drop `Role (Authorization)` MFA from the TODO
  list once shipped.
- **docs/ARCHITECTURE.md** — §4 (flow diagram), §5 (add the challenge attempt cap to the
  abuse-protection table), §6 (config reference), §7 (both data-model tables), §9 (security
  posture: add MFA to "implemented"), §10 (testing coverage), §12 (extension points).
- **.env.example** — the new block from §7.

> Housekeeping: both README.md and ARCHITECTURE.md link to `IMPROVEMENTS.md`, which does
> not exist in the repo. Worth either creating it or removing the links while the docs are
> already being edited.

---

## 11. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| A user enrolls, loses their phone, and burns all recovery codes | Medium | **There is no emergency lever, by design** (§7). The account needs a manual `DELETE FROM user_mfa WHERE user_id = ...` by an operator with database access, which is auditable and per-user. Ship the admin reset path (§12) before this becomes common. Accepting a global bypass instead would be trading a support problem for a security hole. |
| Server clock drift breaks TOTP for everyone at once | Low | `MFA_TOTP_SKEW=1` (±30s) absorbs normal drift; NTP on the host is a deployment prerequisite. A large drift is a total-outage failure mode, so it belongs on the runbook. |
| `MFA_ENCRYPTION_KEY` lost | Low | Every enrolled user must re-enroll. `key_version` makes rotation possible; there is no recovery from a *lost* key by design. |
| The `amr`/`codePayload` change breaks in-flight authorization codes during deploy | Low | Codes have a 60s TTL. Make `RedeemCode` tolerate a payload with no `amr` field (it already will — `encoding/json` leaves it zero), so codes issued by the old binary still redeem. |
| First-PR scope creep | High | Seven phases above; P5 explicitly droppable. |
| ~~P0's refactors touch every existing auth path~~ | — | **Retired.** `Deps`, `VerifyPassword`, the `locker` scope and the epoch were landed by the admin API's A0a phase, as separate commits with the suite green after each. The login-regression risk this row described has been taken and paid. |
| **`VerifyMFA` re-reads the account, and a future refactor removes it** | Medium | The check in §6.3 is the only thing stopping a suspension being bypassed for the whole challenge window, and it looks redundant next to the epoch — which covers every *other* suspension path. Write the test (§8.1) before the code, and keep the comment explaining why the epoch does not help here. |

---

## 12. Future work

- **Trusted devices** — a `SameSite=Strict`, `HttpOnly`, signed cookie holding a
  server-stored device ID with an independent TTL; presenting a valid one skips the
  challenge. Needs a device list + per-device revocation UI, or it becomes a permanent MFA
  bypass nobody can see.
- **WebAuthn / passkeys** — plugs into the challenge step as a second factor *type*. The
  challenge payload would gain a `factor_type`, and `amr` would carry `hwk`/`swk`.
- **Encryption-key rotation** — a background job reading `key_version`, decrypting with the
  old key, re-encrypting with the new. The column already exists for it.
- **Step-up authentication** — require a fresh OTP for high-value actions on a client's
  side, exposed via an `auth_time` claim and a `max_age` parameter.
- ~~**Admin MFA reset**~~ — moved from future work into **P6** (§9), now that the admin API
  exists. It was previously blocked on an admin API existing at all, and promoted in priority by
  the removal of the global kill switch (§7): without it, a locked-out user needs a DBA.
- **Notify the user out-of-band on factor changes** — "MFA was enabled/disabled on your
  account" and "a recovery code was used" emails. For an account-takeover victim this is
  often the *only* signal they get, and the audit log in §6.3.1 only helps someone who is
  already looking. Genuinely out of scope — the service has no mail capability of any kind
  — but it is the highest-value follow-up on this list, above trusted devices and WebAuthn.
  Worth deciding now whether MFA ships with an explicit "you will not be notified" caveat
  in the README.

---

## 13. Adjacent findings (out of scope, surfaced by this review)

None of these block MFA. They came up while tracing the paths MFA touches and are recorded
so they are not rediscovered later.

1. **`/api/auth/introspect` is unauthenticated** (already tracked in ARCHITECTURE §9). Once
   it returns `amr`, an attacker holding a stolen token learns whether that session was
   MFA-backed — useful for picking targets. The `amr` change makes fixing this more urgent,
   not less. Consider requiring client credentials on introspect in the same release.

2. **`lib/pq` is in maintenance mode**; its own maintainer points users at
   [`jackc/pgx`](https://github.com/jackc/pgx). This plan introduces the repo's first
   multi-statement transactions (`Create`, `ReplaceRecoveryCodes`), which is a natural
   moment to decide. A migration is mechanical — swap the driver import and the
   `sql.Open` driver name — but it is a separate change and should not ride along with MFA.

3. **Unbounded challenge creation.** An attacker with a valid password can mint one Redis
   challenge key per request. The per-IP rate limiter is the only bound, and it fails open.
   Low severity (keys are 5-minute TTL and tiny), but if it matters, key the challenge index
   per user and cap concurrent challenges at ~3.

4. **The whole flow could be a library.** If the destination is standards-compliant OIDC
   rather than a bespoke code flow, [`ory/fosite`](https://github.com/ory/fosite) or
   [`zitadel/oidc`](https://github.com/zitadel/oidc) provide `acr`/`amr`, PKCE, refresh
   tokens, and client authentication as a package — much of the open list in ARCHITECTURE
   §9. That is a rewrite, not a refactor, and the right time to consider it was before this
   plan; noting it only so the decision is explicit rather than accidental.

5. **`IMPROVEMENTS.md` is referenced from both README.md and ARCHITECTURE.md but does not
   exist in the repo.** Several sections above cite it. Create it or drop the links.
