package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

var _ port.EmergencyAccesses = (*SupportAccesses)(nil)

// The two keys of the advisory lock are the tenant and the Platform Administrator: two openings of the same pair wait for each other, so only one
// sees the pair free (RN-SEC-010-09; plan D-07). The lock lasts until the transaction ends.
const lockOpeningPair = `SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text, 0))`

const findOpenOfPair = `SELECT count(*) FROM security.support_access WHERE tenant_id = $1::uuid AND requested_by = $2::uuid AND status = 'APPROVED'`

const insertEmergency = `
INSERT INTO security.support_access (tenant_id, requested_by, request_key, reason, areas, hours, status, requested_at, decided_at, expires_at, opened_at,
    basis, statement, sensitive, sensitive_reason)
VALUES ($1::uuid, $2::uuid, $3, $4, $5::text[], $6, 'APPROVED', $7::timestamptz, $7::timestamptz, $8::timestamptz, $7::timestamptz,
    'EMERGENCY', $9, $10, NULLIF($11, ''))
ON CONFLICT (requested_by, request_key) DO NOTHING
RETURNING ` + supportColumns

// The fact that the access opened, with its basis, its statement and whether it reaches the sensitive data; never the data (RN-SEC-010-07).
const emergencyOpenedFact = `
INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, payload, correlation_id, occurred_at)
VALUES ($1::uuid, 'PlatformExceptionalAccessOpened', $2::uuid, $3::uuid,
    jsonb_build_object('authorizationId', $2::uuid, 'platformAdministratorId', $3::uuid, 'basis', 'EMERGENCY', 'reason', $4::text,
        'statement', $5::text, 'scope', to_jsonb($6::text[]), 'includesSensitiveData', $7::boolean,
        'openedAt', to_char($8::timestamptz AT TIME ZONE 'UTC', ` + utcTime + `),
        'expiresAt', to_char($9::timestamptz AT TIME ZONE 'UTC', ` + utcTime + `))
    || CASE WHEN $7::boolean THEN jsonb_build_object('sensitiveReason', $10::text) ELSE '{}'::jsonb END,
    $11, $8::timestamptz)`

// OpenEmergency stores the emergency access and writes the fact that it opened in one transaction, or returns the access that the key of its author
// already made. An access to the same tenant that is still open refuses it; one whose hours are over is expired first, with its closing fact.
func (s *SupportAccesses) OpenEmergency(ctx context.Context, a supportaccess.Access, key, correlationID string) (supportaccess.Access, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return supportaccess.Access{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, lockOpeningPair, a.TenantID, a.RequestedBy); err != nil {
		return supportaccess.Access{}, false, err
	}
	if prior, err := scanAccess(tx.QueryRow(ctx, `SELECT `+supportColumns+` FROM security.support_access WHERE requested_by = $1::uuid AND request_key = $2`, a.RequestedBy, key)); err == nil {
		return prior, false, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return supportaccess.Access{}, false, err
	}
	if _, err := tx.Exec(ctx, expireApproved, a.RequestedAt, a.RequestedBy, a.TenantID); err != nil {
		return supportaccess.Access{}, false, err
	}
	var open int
	if err := tx.QueryRow(ctx, findOpenOfPair, a.TenantID, a.RequestedBy).Scan(&open); err != nil {
		return supportaccess.Access{}, false, err
	}
	if open > 0 {
		return supportaccess.Access{}, false, supportaccess.ErrOpenAccessExists
	}
	made, err := scanAccess(tx.QueryRow(ctx, insertEmergency, a.TenantID, a.RequestedBy, key, a.Reason, a.AreaNames(), a.Hours, a.RequestedAt, a.ExpiresAt,
		a.Statement, a.Sensitive, a.SensitiveReason))
	if errors.Is(err, pgx.ErrNoRows) {
		// the lock is of the pair, the key is of the author: the same key for another tenant, or from the ask route, was committed first and the
		// insert waited for it (RN-SEC-010-08); the access that won is the answer
		prior, found, findErr := s.FindByKey(ctx, a.RequestedBy, key)
		if findErr != nil || !found {
			return supportaccess.Access{}, false, errors.Join(err, findErr)
		}
		return prior, false, nil
	}
	if err != nil {
		return supportaccess.Access{}, false, err
	}
	if _, err := tx.Exec(ctx, emergencyOpenedFact, made.TenantID, made.ID, made.RequestedBy, made.Reason, made.Statement, made.AreaNames(), made.Sensitive,
		made.OpenedAt, made.ExpiresAt, made.SensitiveReason, correlationID); err != nil {
		return supportaccess.Access{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return supportaccess.Access{}, false, err
	}
	return made, true, nil
}
