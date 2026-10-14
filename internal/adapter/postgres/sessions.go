package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/session"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ port.Sessions = (*Sessions)(nil)

// Sessions reads and writes security.session and security.refresh_token.
type Sessions struct {
	pool *pgxpool.Pool
}

func NewSessions(pool *pgxpool.Pool) *Sessions { return &Sessions{pool: pool} }

// One statement: the session and its first value are both stored or neither, so a refused value leaves no session.
const openSession = `
WITH opened AS (
    INSERT INTO security.session (identity_id, created_at, expires_at)
    VALUES ($1::uuid, $2::timestamptz, $2::timestamptz + make_interval(secs => $3::double precision))
    RETURNING session_id, expires_at
)
INSERT INTO security.refresh_token (token_hash, session_id, expires_at)
SELECT $4, session_id, expires_at FROM opened
RETURNING session_id::text`

func (r *Sessions) Open(ctx context.Context, accountID, valueHash string, now time.Time) (string, error) {
	var id string
	err := r.pool.QueryRow(ctx, openSession, accountID, now, session.Life.Seconds(), valueHash).Scan(&id)
	return id, err
}

// the rows of the value and of its session are locked, so two renewals of one value are one after the other and the
// second sees it consumed, and a renewal cannot succeed on a session that a reuse is revoking at the same time
const lockValue = `
SELECT r.session_id::text, r.consumed_at, r.expires_at, s.identity_id::text, s.created_at, s.expires_at, s.revoked_at,
       i.identity_status, i.sessions_revoked_from
FROM security.refresh_token r
JOIN security.session s ON s.session_id = r.session_id
JOIN security.identity i ON i.identity_id = s.identity_id
WHERE r.token_hash = $1
FOR UPDATE OF r, s`

func (r *Sessions) Rotate(ctx context.Context, oldHash, newHash string, now time.Time) (port.Renewed, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return port.Renewed{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var sessionID, accountID, status string
	var consumed, revoked, cutoff *time.Time
	var valueExpires, created, sessionExpires time.Time
	err = tx.QueryRow(ctx, lockValue, oldHash).Scan(&sessionID, &consumed, &valueExpires, &accountID, &created, &sessionExpires,
		&revoked, &status, &cutoff)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.Renewed{}, port.ErrRefreshInvalid
	}
	if err != nil {
		return port.Renewed{}, err
	}
	if consumed != nil {
		// the revocation is committed before the refusal is returned: it is the point of detecting the reuse
		if _, err := tx.Exec(ctx, `UPDATE security.session SET revoked_at = COALESCE(revoked_at, $2::timestamptz)
			WHERE session_id = $1::uuid`, sessionID, now); err != nil {
			return port.Renewed{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return port.Renewed{}, err
		}
		return port.Renewed{}, port.ErrRefreshReused
	}
	if revoked != nil || !now.Before(valueExpires) || !now.Before(sessionExpires) || status != "ACTIVE" ||
		(cutoff != nil && !created.After(*cutoff)) {
		return port.Renewed{}, port.ErrRefreshInvalid
	}
	if _, err := tx.Exec(ctx, `UPDATE security.refresh_token SET consumed_at = $2::timestamptz WHERE token_hash = $1`, oldHash, now); err != nil {
		return port.Renewed{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security.refresh_token (token_hash, session_id, expires_at) VALUES ($1, $2::uuid, $3)`,
		newHash, sessionID, sessionExpires); err != nil {
		return port.Renewed{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return port.Renewed{}, err
	}
	return port.Renewed{AccountID: accountID, SessionID: sessionID}, nil
}

// One statement: the cutoff and its event are both written or neither. GREATEST keeps a cutoff from moving backwards.
const revokeAll = `
WITH cut AS (
    UPDATE security.identity SET sessions_revoked_from = GREATEST(COALESCE(sessions_revoked_from, $2::timestamptz), $2::timestamptz)
    WHERE identity_id = $1::uuid
    RETURNING identity_id, tenant_id, sessions_revoked_from
)
INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, payload, correlation_id, occurred_at)
SELECT tenant_id, 'AccountSessionsRevoked', identity_id,
       jsonb_build_object('accountId', identity_id,
           'revokedFrom', to_char(sessions_revoked_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
       $3, $2::timestamptz
FROM cut`

func (r *Sessions) RevokeAll(ctx context.Context, accountID string, cutoff time.Time, correlationID string) error {
	tag, err := r.pool.Exec(ctx, revokeAll, accountID, cutoff, correlationID)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrAccountNotFound
	}
	return err
}
