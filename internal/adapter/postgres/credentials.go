package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// TemporaryCredentials issues a new temporary credential to an internal user (HU-SEC-005, RN-SEC-003-14 and -15).
type TemporaryCredentials struct{ pool *pgxpool.Pool }

// NewTemporaryCredentials expects a non-nil pool; the composition root owns it.
func NewTemporaryCredentials(pool *pgxpool.Pool) *TemporaryCredentials {
	return &TemporaryCredentials{pool: pool}
}

// the facts of the authority in one read. An administrator counts as able to sign in when the account is active and not blocked,
// and has no temporary credential or one still in force, which is what the sign-in asks of it; the membership must be active, as
// RolesOf asks. The first Administrator is the one whose membership a service created.
const credentialTarget = `
SELECT i.identity_id::text, i.tenant_id::text, i.identity_status = 'ACTIVE', i.temporary_until IS NOT NULL,
       EXISTS (SELECT 1 FROM security.membership m JOIN security.membership_role mr USING (membership_id)
               WHERE m.identity_id = i.identity_id AND m.membership_status = 'ACTIVE' AND mr.role = 'TENANT_ADMINISTRATOR' AND mr.role_status = 'ACTIVE'),
       EXISTS (SELECT 1 FROM security.membership m JOIN security.membership_role mr USING (membership_id)
               WHERE m.identity_id = i.identity_id AND m.membership_status = 'ACTIVE' AND mr.role = 'TENANT_ADMINISTRATOR' AND mr.role_status = 'ACTIVE'
                 AND m.created_by LIKE 'service/%'),
       (SELECT count(*) FROM security.identity a WHERE a.tenant_id = i.tenant_id AND a.identity_status = 'ACTIVE'
            AND (a.blocked_until IS NULL OR a.blocked_until <= $2::timestamptz)
            AND (a.temporary_until IS NULL OR a.temporary_until > $2::timestamptz)
            AND EXISTS (SELECT 1 FROM security.membership m JOIN security.membership_role mr USING (membership_id)
                        WHERE m.identity_id = a.identity_id AND m.membership_status = 'ACTIVE' AND mr.role = 'TENANT_ADMINISTRATOR' AND mr.role_status = 'ACTIVE'))
FROM security.identity i
WHERE i.identity_id = $1::uuid AND i.tenant_id IS NOT NULL AND EXISTS (SELECT 1 FROM security.membership m
        JOIN security.membership_role mr USING (membership_id) WHERE m.identity_id = i.identity_id AND mr.role = ANY($3))`

func (s *TemporaryCredentials) Target(ctx context.Context, accountID string, now time.Time) (port.CredentialTarget, bool, error) {
	var t port.CredentialTarget
	err := s.pool.QueryRow(ctx, credentialTarget, accountID, now, internalRoleNames).Scan(&t.AccountID, &t.TenantID, &t.Active, &t.HasTemporary,
		&t.Administrator, &t.FirstAdministrator, &t.AdministratorsAbleToSignIn)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.CredentialTarget{}, false, nil
	}
	return t, err == nil, err
}

// One statement: the hash, the 72 hours, the clean sign-in state, who and when, and the event are all written or none. The row must
// still be active and carry a temporary credential, in force or expired, so a person who already chose a password is not reached
// and two issues at once leave the last one. The event names the issuer and never the credential.
const issueCredential = `
WITH issued AS (
    UPDATE security.identity i SET password_hash = $2, temporary_until = $4::timestamptz, failed_count = 0, first_failed_at = NULL,
        blocked_until = NULL, temporary_issued_at = $3::timestamptz, temporary_issued_by = $5
    WHERE i.identity_id = $1::uuid AND i.tenant_id = $6::uuid AND i.identity_status = 'ACTIVE' AND i.temporary_until IS NOT NULL
      AND EXISTS (SELECT 1 FROM security.membership m JOIN security.membership_role mr USING (membership_id)
                  WHERE m.identity_id = i.identity_id AND mr.role = ANY($10))
    RETURNING i.identity_id, i.tenant_id
), audit AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'AccountTemporaryCredentialIssued', identity_id, $7::uuid,
           jsonb_build_object('accountId', identity_id, 'tenantId', tenant_id,
               'issuedBy', jsonb_build_object('accountId', $7::text, 'role', $8::text),
               'issuedAt', to_char($3::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
           $9, $3::timestamptz
    FROM issued
)
SELECT count(*) FROM issued`

func (s *TemporaryCredentials) Issue(ctx context.Context, c port.IssueCommand) (port.Registered, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return port.Registered{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var issued int
	if err := tx.QueryRow(ctx, issueCredential, c.AccountID, c.Hash, c.Now, c.Now.Add(account.TemporaryCredentialLife), c.By, c.TenantID,
		c.ActorID, c.ActorRole, c.CorrelationID, internalRoleNames).Scan(&issued); err != nil {
		return port.Registered{}, err
	}
	if issued == 0 {
		return port.Registered{}, port.ErrNotTemporary
	}
	reg, err := readUser(ctx, tx, c.TenantID, c.AccountID)
	if err != nil {
		return port.Registered{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return port.Registered{}, err
	}
	return reg, nil
}

var _ port.TemporaryCredentials = (*TemporaryCredentials)(nil)
