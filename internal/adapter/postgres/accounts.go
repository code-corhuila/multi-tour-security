// Package postgres is the adapter of the core to the schema security of the single PostgreSQL instance (plan D-09).
// The constraints that matter (unique e-mail per tenant, bcrypt shape of the hash) are in the database and not here.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAccountNotFound is an operation on an account that does not exist; a lookup answers found=false instead.
var ErrAccountNotFound = errors.New("the account does not exist")

var _ port.Accounts = (*Accounts)(nil)

// Accounts reads and updates security.identity.
type Accounts struct {
	pool *pgxpool.Pool
}

func NewAccounts(pool *pgxpool.Pool) *Accounts { return &Accounts{pool: pool} }

const accountColumns = `identity_id::text, COALESCE(tenant_id::text, ''), email_normalized, password_hash, identity_status,
	temporary_until, failed_count, first_failed_at, blocked_until`

func scanAccount(row pgx.Row, extra ...any) (account.Account, error) {
	var a account.Account
	var status string
	var temporary, first, blocked *time.Time
	dest := append([]any{&a.ID, &a.TenantID, &a.EmailNormalized, &a.PasswordHash, &status, &temporary, &a.Failed, &first, &blocked}, extra...)
	if err := row.Scan(dest...); err != nil {
		return account.Account{}, err
	}
	if status == "INACTIVE" {
		a.Status = account.Inactive
	}
	a.TemporaryUntil, a.FirstFailedAt, a.BlockedUntil = utc(temporary), utc(first), utc(blocked)
	return a, nil
}

func utc(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

// FindByEmail looks an account up by its tenant (empty for the platform) and its already normalized e-mail.
func (r *Accounts) FindByEmail(ctx context.Context, tenantID, emailNormalized string) (account.Account, bool, error) {
	return found(scanAccount(r.pool.QueryRow(ctx, `SELECT `+accountColumns+` FROM security.identity
		WHERE tenant_id IS NOT DISTINCT FROM NULLIF($1, '')::uuid AND email_normalized = $2`, tenantID, emailNormalized)))
}

func (r *Accounts) FindByID(ctx context.Context, id string) (account.Account, bool, error) {
	return found(scanAccount(r.pool.QueryRow(ctx, `SELECT `+accountColumns+` FROM security.identity WHERE identity_id = $1::uuid`, id)))
}

func found(a account.Account, err error) (account.Account, bool, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return account.Account{}, false, nil
	}
	return a, err == nil, err
}

// the window of the count restarts when none is open or the one open has ended: the same rule as account.AfterFailure
const windowEnded = `(failed_count = 0 OR $2::timestamptz >= first_failed_at + make_interval(secs => $3::double precision))`

// One statement counts the failure, opens or ends the window, blocks at the fifth and writes the event of the block:
// the count and the event are both written or neither is, and two instances cannot count the same failure twice. A
// failure while the account is blocked matches no row and changes nothing.
const recordFailure = `
WITH counted AS (
    UPDATE security.identity SET
        failed_count    = CASE WHEN ` + windowEnded + ` THEN 1 ELSE failed_count + 1 END,
        first_failed_at = CASE WHEN ` + windowEnded + ` THEN $2::timestamptz ELSE first_failed_at END,
        blocked_until   = CASE WHEN ` + windowEnded + ` THEN NULL
                               WHEN failed_count + 1 >= $4 THEN $2::timestamptz + make_interval(secs => $5::double precision)
                               ELSE NULL END
    WHERE identity_id = $1::uuid AND (blocked_until IS NULL OR $2::timestamptz >= blocked_until)
    RETURNING identity_id, tenant_id, email_normalized, password_hash, identity_status, temporary_until, failed_count,
              first_failed_at, blocked_until
), audit AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'AccountBlocked', identity_id,
           jsonb_build_object('accountId', identity_id,
               'blockedUntil', to_char(blocked_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')), $6, $2::timestamptz
    FROM counted WHERE blocked_until IS NOT NULL
)
SELECT identity_id::text, COALESCE(tenant_id::text, ''), email_normalized, password_hash, identity_status, temporary_until,
       failed_count, first_failed_at, blocked_until, blocked_until IS NOT NULL
FROM counted`

// RecordFailure counts a failed sign-in at now and says whether this one blocked the account.
func (r *Accounts) RecordFailure(ctx context.Context, id string, now time.Time, correlationID string) (account.Account, bool, error) {
	var blocked bool
	a, err := scanAccount(r.pool.QueryRow(ctx, recordFailure, id, now, account.FailureWindow.Seconds(), account.MaxFailures,
		account.BlockLife.Seconds(), correlationID), &blocked)
	if errors.Is(err, pgx.ErrNoRows) {
		current, ok, err := r.FindByID(ctx, id)
		if err == nil && !ok {
			err = ErrAccountNotFound
		}
		return current, false, err
	}
	return a, blocked, err
}

// One statement: the hash, the end of the temporary state, the cutoff of the older sessions and the event of the
// revocation are all written or none. The row must still carry a temporary credential in force, so two changes at
// once have one winner.
const changePassword = `
WITH changed AS (
    UPDATE security.identity SET
        password_hash = $2, temporary_until = NULL, failed_count = 0, first_failed_at = NULL, blocked_until = NULL,
        sessions_revoked_from = GREATEST(COALESCE(sessions_revoked_from, $3::timestamptz), $3::timestamptz)
    WHERE identity_id = $1::uuid AND temporary_until IS NOT NULL AND temporary_until > $3::timestamptz
    RETURNING identity_id, tenant_id, sessions_revoked_from
)
INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, payload, correlation_id, occurred_at)
SELECT tenant_id, 'AccountSessionsRevoked', identity_id,
       jsonb_build_object('accountId', identity_id,
           'revokedFrom', to_char(sessions_revoked_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
       $4, $3::timestamptz
FROM changed`

// ChangePassword stores the first password chosen in place of the temporary credential.
func (r *Accounts) ChangePassword(ctx context.Context, id, hash string, now time.Time, correlationID string) error {
	tag, err := r.pool.Exec(ctx, changePassword, id, hash, now, correlationID)
	if err == nil && tag.RowsAffected() == 0 {
		err = port.ErrNotTemporary
	}
	return err
}

// RecordSuccess clears the count and the block.
func (r *Accounts) RecordSuccess(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE security.identity SET failed_count = 0, first_failed_at = NULL, blocked_until = NULL
		WHERE identity_id = $1::uuid`, id)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrAccountNotFound
	}
	return err
}

// RolesOf gives the roles of the active membership of the account, by name.
func (r *Accounts) RolesOf(ctx context.Context, id string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT mr.role FROM security.membership m
		JOIN security.membership_role mr USING (membership_id)
		WHERE m.identity_id = $1::uuid AND m.membership_status = 'ACTIVE' ORDER BY mr.role`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := []string{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}
