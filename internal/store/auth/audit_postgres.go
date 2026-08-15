package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
)

const auditColumns = `id, actor_id, actor_email, actor_role, action, target_type, target_id,
	target_label, result, metadata, remote_addr, forwarded_for, user_agent, created_at`

// InsertAudit records an event outside a transaction. It is used for the
// Redis-backed mutations (unlock, revoke-sessions) that have no Postgres
// transaction to join, and for denied-authorization records.
//
// For anything that writes to Postgres, the audit row goes in the same
// transaction as the change instead — see PostgresStore.mutate.
func (s *PostgresStore) InsertAudit(ctx context.Context, ev AuditEvent) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		return insertAuditTx(ctx, tx, &ev)
	})
}

func insertAuditTx(ctx context.Context, tx *sql.Tx, ev *AuditEvent) error {
	metadata, err := json.Marshal(orEmptyMap(ev.Metadata))
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO admin_audit_log
			(actor_id, actor_email, actor_role, action, target_type, target_id,
			 target_label, result, metadata, remote_addr, forwarded_for, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		nullIf(ev.ActorID), ev.ActorEmail, ev.ActorRole, ev.Action,
		nullIf(ev.TargetType), nullIf(ev.TargetID), nullIf(ev.TargetLabel),
		ev.Result, metadata, nullIf(ev.RemoteAddr), nullIf(ev.ForwardedFor), nullIf(ev.UserAgent),
	)
	if err != nil {
		return fmt.Errorf("insert audit row: %w", err)
	}
	return nil
}

// ListAudit returns one keyset page of the log, newest first.
func (s *PostgresStore) ListAudit(ctx context.Context, af AuditFilter) ([]AuditRecord, error) {
	page := af.Page.Normalize()

	var f filter
	f.eq("actor_id::text", af.ActorID)
	f.eq("target_id", af.TargetID)
	f.eq("action", af.Action)
	f.from("created_at", af.From)
	f.to("created_at", af.To)

	if !page.Cursor.IsZero() {
		id, err := strconv.ParseInt(page.Cursor.ID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("malformed cursor")
		}
		f.keyset("created_at, id", page.Cursor, id)
	}

	q := `SELECT ` + auditColumns + ` FROM admin_audit_log` + f.where() +
		orderAndLimit("created_at DESC, id DESC", page.Limit)
	return collect(ctx, s.db, q, f.args, scanAudit)
}

func scanAudit(s rowScanner) (AuditRecord, error) {
	var (
		r        AuditRecord
		actorID  sql.NullString
		tType    sql.NullString
		tID      sql.NullString
		tLabel   sql.NullString
		remote   sql.NullString
		fwd      sql.NullString
		ua       sql.NullString
		metadata []byte
	)
	err := s.Scan(&r.ID, &actorID, &r.ActorEmail, &r.ActorRole, &r.Action,
		&tType, &tID, &tLabel, &r.Result, &metadata, &remote, &fwd, &ua, &r.CreatedAt)
	if err != nil {
		return AuditRecord{}, err
	}

	r.ActorID, r.TargetType, r.TargetID = actorID.String, tType.String, tID.String
	r.TargetLabel, r.RemoteAddr, r.ForwardedFor, r.UserAgent = tLabel.String, remote.String, fwd.String, ua.String

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &r.Metadata); err != nil {
			return AuditRecord{}, fmt.Errorf("unmarshal audit metadata: %w", err)
		}
	}
	return r, nil
}

// nullIf maps "" to a SQL NULL. Needed for remote_addr in particular: INET
// rejects an empty string outright.
func nullIf(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
