package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/recovery"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ port.RecoveryCodes = (*RecoveryCodes)(nil)

// RecoveryCodes reads and writes security.recovery_code (HU-SEC-004). It only ever sees the HMAC of a code, never the code.
type RecoveryCodes struct {
	pool *pgxpool.Pool
}

func NewRecoveryCodes(pool *pgxpool.Pool) *RecoveryCodes { return &RecoveryCodes{pool: pool} }

// utcTime is how an instant is written in a payload, as the other facts of this service write it.
const utcTime = `'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'`

// The name shown as the sender of the notice is the commercial name of the tenant, or the platform's when it has none or the account has no
// tenant: the rule of tenant.Copy.DisplayName, written here because the fact is built inside the statement of the reset.
const (
	tenantNameOfAccount = `COALESCE((SELECT c.commercial_name FROM security.tenant_copy c WHERE c.tenant_id = i.tenant_id), 'Multitour')`
	tenantNameOfChanged = `COALESCE((SELECT c.commercial_name FROM security.tenant_copy c WHERE c.tenant_id = changed.tenant_id), 'Multitour')`
	// the roles of the active membership, whatever their own status, as RolesHeld reads them
	rolesOfAccount = `COALESCE((SELECT jsonb_agg(mr.role ORDER BY mr.role) FROM security.membership m
		JOIN security.membership_role mr USING (membership_id) WHERE m.identity_id = i.identity_id AND m.membership_status = 'ACTIVE'), '[]'::jsonb)`
)

// Issue counts, retires and writes in one transaction that holds the row of the account, so codes asked for at the same
// time take turns: the third passes, the fourth finds three and writes nothing. The fact PasswordRecoveryRequested is written
// with the code. An inactive account, or one that does not exist, gets no code and no error.
func (r *RecoveryCodes) Issue(ctx context.Context, c port.IssueCode) (bool, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op once committed

	// the tenant of the fact is the one of the row, never the caller's word: the audit must not name a tenant by mistake
	var tenantID string
	err = tx.QueryRow(ctx, `SELECT COALESCE(tenant_id::text, '') FROM security.identity
		WHERE identity_id = $1::uuid AND identity_status IN ('ACTIVE', 'PENDING') FOR UPDATE`, c.AccountID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var recent int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM security.recovery_code
		WHERE identity_id = $1::uuid AND created_at > $2::timestamptz - make_interval(secs => $3::double precision)`,
		c.AccountID, c.Now, c.Window.Seconds()).Scan(&recent); err != nil {
		return false, err
	}
	if recent >= c.Limit {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE security.recovery_code SET retired_at = $2::timestamptz
		WHERE identity_id = $1::uuid AND used_at IS NULL AND retired_at IS NULL`, c.AccountID, c.Now); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security.recovery_code (identity_id, code_hmac, created_at, expires_at)
		VALUES ($1::uuid, $2, $3::timestamptz, $4::timestamptz)`, c.AccountID, c.Code.HMAC, c.Code.CreatedAt, c.Code.ExpiresAt); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, payload, correlation_id, occurred_at)
		VALUES (NULLIF($2, '')::uuid, 'PasswordRecoveryRequested', $1::uuid,
		        jsonb_build_object('accountId', $1::uuid, 'requestedAt', to_char($3::timestamptz AT TIME ZONE 'UTC', `+utcTime+`)),
		        $4, $3::timestamptz)`, c.AccountID, tenantID, c.Now, c.CorrelationID); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// Newest reads the newest code of the account that is unused, not retired and not expired at now.
func (r *RecoveryCodes) Newest(ctx context.Context, accountID string, now time.Time) (port.CodeState, bool, error) {
	var s port.CodeState
	err := r.pool.QueryRow(ctx, `SELECT recovery_id::text, code_hmac, wrong_tries FROM security.recovery_code
		WHERE identity_id = $1::uuid AND used_at IS NULL AND retired_at IS NULL AND expires_at > $2::timestamptz
		ORDER BY created_at DESC LIMIT 1`, accountID, now).Scan(&s.ID, &s.HMAC, &s.WrongTries)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.CodeState{}, false, nil
	}
	if err != nil {
		return port.CodeState{}, false, err
	}
	return s, true, nil
}

// One statement: the wrong try is counted, and the code is retired at the fifth, only while the code is live and has fewer
// than five, so two tries at once count two and a sixth is never counted; and the fact of a failed reset is written for an
// administrative account, with a code or without one. A refusal that is not a wrong code counts nothing.
const failedReset = `
WITH counted AS (
    UPDATE security.recovery_code SET
        wrong_tries = wrong_tries + 1,
        retired_at  = CASE WHEN wrong_tries + 1 >= $5 THEN $4::timestamptz ELSE retired_at END
    WHERE recovery_id = NULLIF($2, '')::uuid AND identity_id = $1::uuid AND $3::text = 'WRONG_CODE'
      AND used_at IS NULL AND retired_at IS NULL AND expires_at > $4::timestamptz AND wrong_tries < $5
    RETURNING 1
)
INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, reason, payload, correlation_id, occurred_at)
SELECT i.tenant_id, 'PasswordResetFailed', i.identity_id, $3::text,
       jsonb_build_object('accountId', i.identity_id, 'reason', $3::text, 'email', i.email_normalized, 'tenantName', ` + tenantNameOfAccount + `,
           'roles', ` + rolesOfAccount + `, 'failedAt', to_char($4::timestamptz AT TIME ZONE 'UTC', ` + utcTime + `)),
       $6, $4::timestamptz
FROM security.identity i WHERE i.identity_id = $1::uuid AND $7::boolean`

// RecordFailure counts a wrong try and writes the fact for an administrative account, all together.
func (r *RecoveryCodes) RecordFailure(ctx context.Context, f port.FailedReset) error {
	_, err := r.pool.Exec(ctx, failedReset, f.AccountID, f.CodeID, f.Reason, f.Now, recovery.MaxWrongTries, f.CorrelationID, f.Administrative)
	return err
}

// One statement: the code is used, the password is replaced, the block of failed sign-ins is lifted, the older sessions are
// cut off, a pending account is made active and verified, and the facts are written, or none of it. The code must still be
// live, so two resets at once have one winner (the second waits for the row, finds the code used and writes nothing).
const resetPassword = `
WITH used AS (
    UPDATE security.recovery_code SET used_at = $4::timestamptz
    WHERE recovery_id = $2::uuid AND identity_id = $1::uuid AND used_at IS NULL AND retired_at IS NULL AND expires_at > $4::timestamptz
    RETURNING identity_id
), changed AS (
    UPDATE security.identity i SET
        password_hash = $3, temporary_until = NULL, failed_count = 0, first_failed_at = NULL, blocked_until = NULL,
        sessions_revoked_from = GREATEST(COALESCE(i.sessions_revoked_from, $4::timestamptz), $4::timestamptz),
        identity_status  = 'ACTIVE',
        email_verified    = CASE WHEN $7::boolean THEN true ELSE i.email_verified END,
        email_verified_at = CASE WHEN $7::boolean THEN $4::timestamptz ELSE i.email_verified_at END
    FROM used WHERE i.identity_id = used.identity_id AND i.identity_status IN ('ACTIVE', 'PENDING')
    RETURNING i.identity_id, i.tenant_id, i.email_normalized, i.sessions_revoked_from
), revoked AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, reason, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'AccountSessionsRevoked', identity_id, 'PASSWORD_RESET',
           jsonb_build_object('accountId', identity_id, 'revokedFrom', to_char(sessions_revoked_from AT TIME ZONE 'UTC', ` + utcTime + `),
               'reason', 'PASSWORD_RESET'), $5, $4::timestamptz
    FROM changed RETURNING 1
), reset AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'PasswordReset', identity_id,
           jsonb_build_object('accountId', identity_id, 'roles', to_jsonb($6::text[]), 'email', email_normalized, 'tenantName', ` + tenantNameOfChanged + `,
               'resetAt', to_char($4::timestamptz AT TIME ZONE 'UTC', ` + utcTime + `)), $5, $4::timestamptz
    FROM changed RETURNING 1
), verified AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'AccountEmailVerified', identity_id,
           jsonb_build_object('accountId', identity_id, 'email', email_normalized,
               'verifiedAt', to_char($4::timestamptz AT TIME ZONE 'UTC', ` + utcTime + `)), $5, $4::timestamptz
    FROM changed WHERE $7::boolean RETURNING 1
)
SELECT count(*) FROM changed`

// Reset takes the row of the account first, as Issue does, so the two never wait for each other in opposite orders (that
// is a deadlock), and reads from it whether the account is pending: the store trusts the row it holds, never the flag the
// use case saw a moment ago. An account inactivated meanwhile is not reset and its code stays unused.
func (r *RecoveryCodes) Reset(ctx context.Context, c port.ResetCommand) (bool, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op once committed

	var status string
	err = tx.QueryRow(ctx, `SELECT identity_status FROM security.identity
		WHERE identity_id = $1::uuid AND identity_status IN ('ACTIVE', 'PENDING') FOR UPDATE`, c.AccountID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	roles := c.Roles
	if roles == nil {
		roles = []string{}
	}
	var changed int
	if err := tx.QueryRow(ctx, resetPassword, c.AccountID, c.CodeID, c.NewHash, c.Now, c.CorrelationID, roles, status == "PENDING").Scan(&changed); err != nil {
		return false, err
	}
	if changed != 1 {
		return false, nil
	}
	return true, tx.Commit(ctx)
}

// MarkSendFailed records that the e-mail of a code was not sent and why. The cause is bounded by the table, and the use case
// has already taken the code out of it. A NUL byte, which a text column refuses and a server may put in its answer, is
// dropped, so the failure is recorded all the same. The code is found by its account and its HMAC: the same digits sent to
// another account are another code.
func (r *RecoveryCodes) MarkSendFailed(ctx context.Context, accountID, hmac string, now time.Time, cause string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE security.recovery_code SET send_failed_at = $3::timestamptz, send_error = $4
		WHERE identity_id = $1::uuid AND code_hmac = $2 AND used_at IS NULL`, accountID, hmac, now, strings.ReplaceAll(cause, "\x00", ""))
	if err == nil && tag.RowsAffected() == 0 {
		err = fmt.Errorf("the code to mark as not sent does not exist")
	}
	return err
}
