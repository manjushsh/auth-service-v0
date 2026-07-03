-- The sessions table was created in 002 but auth is stateless (JWT + Redis
-- code/blocklist stores); nothing in the codebase reads or writes it.
DROP TABLE IF EXISTS sessions;
