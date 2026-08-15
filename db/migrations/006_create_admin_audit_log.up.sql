-- Durable record of every privileged action. Append-only: the application has
-- no code path that updates or deletes a row here, and the database role it
-- connects with should not hold UPDATE/DELETE on this table either.
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id            BIGSERIAL   PRIMARY KEY,   -- read in time order; UUIDs are not
    -- SET NULL, not CASCADE: deleting an admin must not erase the record of
    -- what they did. Every other FK in this schema cascades; this one must not.
    actor_id      UUID        REFERENCES users(id) ON DELETE SET NULL,
    actor_email   TEXT        NOT NULL,      -- snapshot, survives actor deletion
    actor_role    TEXT        NOT NULL,
    action        TEXT        NOT NULL,      -- 'user.unlock', 'client.create', ...
    target_type   TEXT,                      -- 'user' | 'client' | null
    target_id     TEXT,
    target_label  TEXT,                      -- email / redirect_uri snapshot
    result        TEXT        NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
    metadata      JSONB       NOT NULL DEFAULT '{}',
    remote_addr   INET,                      -- TCP peer; trustworthy
    forwarded_for TEXT,                      -- attacker-supplied hint; recorded, not believed
    user_agent    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS admin_audit_created_idx ON admin_audit_log (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS admin_audit_target_idx  ON admin_audit_log (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_actor_idx   ON admin_audit_log (actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_action_idx  ON admin_audit_log (action, created_at DESC);
