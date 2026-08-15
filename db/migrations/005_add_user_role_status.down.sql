DROP INDEX IF EXISTS clients_redirect_uri_live_idx;
ALTER TABLE clients DROP COLUMN IF EXISTS disabled_at;
ALTER TABLE clients ADD CONSTRAINT clients_redirect_uri_key UNIQUE (redirect_uri);

DROP INDEX IF EXISTS users_role_idx;
ALTER TABLE users DROP COLUMN IF EXISTS status;
ALTER TABLE users DROP COLUMN IF EXISTS role;
