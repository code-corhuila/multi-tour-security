package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ port.Verifications = (*Verifications)(nil)

// Verifications reads and writes security.email_verification (HU-SEC-003). It only ever sees the hash of a link.
type Verifications struct {
	pool *pgxpool.Pool
}

func NewVerifications(pool *pgxpool.Pool) *Verifications { return &Verifications{pool: pool} }

// Issue counts, retires and writes in one transaction that holds the row of the account, so links asked for at the same
// time take turns: the third passes, the fourth finds three and writes nothing. Only a pending account gets a link; an
// account that was verified a moment ago, or does not exist, gets none and no error.
func (v *Verifications) Issue(ctx context.Context, accountID string, link port.NewLink, now time.Time, limit int, window time.Duration) (bool, error) {
	tx, err := v.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op once committed

	var locked string
	err = tx.QueryRow(ctx, `SELECT identity_id::text FROM security.identity WHERE identity_id = $1::uuid AND identity_status = 'PENDING' FOR UPDATE`,
		accountID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var recent int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM security.email_verification
		WHERE identity_id = $1::uuid AND created_at > $2::timestamptz - make_interval(secs => $3::double precision)`,
		accountID, now, window.Seconds()).Scan(&recent); err != nil {
		return false, err
	}
	if recent >= limit {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE security.email_verification SET replaced_at = $2::timestamptz
		WHERE identity_id = $1::uuid AND used_at IS NULL AND replaced_at IS NULL`, accountID, now); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security.email_verification (identity_id, token_hash, created_at, expires_at)
		VALUES ($1::uuid, $2, $3::timestamptz, $4::timestamptz)`, accountID, link.TokenHash, now, link.ExpiresAt); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// Find reads a link by its hash with the tenant of its account.
func (v *Verifications) Find(ctx context.Context, tokenHash string) (port.LinkState, bool, error) {
	var s port.LinkState
	var used, replaced *time.Time
	err := v.pool.QueryRow(ctx, `SELECT i.identity_id::text, COALESCE(i.tenant_id::text, ''), l.expires_at, l.used_at, l.replaced_at
		FROM security.email_verification l JOIN security.identity i USING (identity_id) WHERE l.token_hash = $1`, tokenHash).
		Scan(&s.AccountID, &s.TenantID, &s.ExpiresAt, &used, &replaced)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.LinkState{}, false, nil
	}
	if err != nil {
		return port.LinkState{}, false, err
	}
	s.ExpiresAt, s.UsedAt, s.ReplacedAt = s.ExpiresAt.UTC(), utc(used), utc(replaced)
	return s, true, nil
}

// One statement: the link is used, the account is verified and active, and the fact is written, or none of it. The link
// must still be unused, unreplaced and unexpired and its account pending, so two confirmations at once have one winner
// (the second waits for the row, finds it used and writes nothing).
const confirmLink = `
WITH link AS (
    UPDATE security.email_verification l SET used_at = $2::timestamptz
    WHERE l.token_hash = $1 AND l.used_at IS NULL AND l.replaced_at IS NULL AND l.expires_at > $2::timestamptz
      AND EXISTS (SELECT 1 FROM security.identity i WHERE i.identity_id = l.identity_id AND i.identity_status = 'PENDING')
    RETURNING l.identity_id
), verified AS (
    UPDATE security.identity i SET identity_status = 'ACTIVE', email_verified = true, email_verified_at = $2::timestamptz
    FROM link WHERE i.identity_id = link.identity_id AND i.identity_status = 'PENDING'
    RETURNING i.identity_id, i.tenant_id, i.email_normalized
)
INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, payload, correlation_id, occurred_at)
SELECT tenant_id, 'AccountEmailVerified', identity_id,
       jsonb_build_object('accountId', identity_id, 'email', email_normalized,
           'verifiedAt', to_char($2::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
       $3, $2::timestamptz
FROM verified`

// Confirm verifies the account of the link at now and says whether it did. It takes the row of the account first, as Issue
// does, so the two never wait for each other in opposite orders (that is a deadlock), and the statement then sees the state
// the account has once that row is its own: an account inactivated a moment ago is not verified by a link.
func (v *Verifications) Confirm(ctx context.Context, tokenHash string, now time.Time, correlationID string) (bool, error) {
	tx, err := v.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op once committed

	var locked string
	err = tx.QueryRow(ctx, `SELECT i.identity_id::text FROM security.email_verification l
		JOIN security.identity i USING (identity_id) WHERE l.token_hash = $1 FOR UPDATE OF i`, tokenHash).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, confirmLink, tokenHash, now, correlationID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, tx.Commit(ctx)
}

// MarkSendFailed records that the e-mail of a link was not sent and why. The cause is bounded by the table, and the use case
// has already taken the link out of it. A NUL byte, which a text column refuses and a server may put in its answer, is
// dropped, so the failure is recorded all the same.
func (v *Verifications) MarkSendFailed(ctx context.Context, tokenHash string, now time.Time, cause string) error {
	tag, err := v.pool.Exec(ctx, `UPDATE security.email_verification SET send_failed_at = $2::timestamptz, send_error = $3
		WHERE token_hash = $1`, tokenHash, now, strings.ReplaceAll(cause, "\x00", ""))
	if err == nil && tag.RowsAffected() == 0 {
		err = fmt.Errorf("the link to mark as not sent does not exist")
	}
	return err
}
