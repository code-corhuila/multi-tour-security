package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

var _ port.Verifications = (*Verifications)(nil)

func (v *Verifications) Confirm(context.Context, string, time.Time, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (v *Verifications) MarkSendFailed(context.Context, string, time.Time, string) error {
	return errors.New("not implemented")
}
