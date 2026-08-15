-- Admin identity lives on the users table: one human, one account, one password.
-- Defaults are chosen so this migration is a no-op for every existing row and
-- every existing query.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role   TEXT NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'support', 'admin')),
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended'));

-- Admin accounts are rare; a partial index keeps "list the admins" and the
-- last-admin guard cheap without indexing every ordinary user.
CREATE INDEX IF NOT EXISTS users_role_idx ON users (role) WHERE role <> 'user';

-- Clients are disabled rather than deleted, so outstanding codes/tokens can be
-- reasoned about. Uniqueness must then apply only to live rows, otherwise a
-- disabled redirect_uri could never be recreated.
ALTER TABLE clients ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_redirect_uri_key;
CREATE UNIQUE INDEX IF NOT EXISTS clients_redirect_uri_live_idx
    ON clients (redirect_uri) WHERE disabled_at IS NULL;
