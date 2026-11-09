package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

// FindOwn returns the request with that id when the caller is the Platform Administrator who asked for it.
func (s *SupportAccesses) FindOwn(ctx context.Context, requestedBy, id string) (supportaccess.Access, bool, error) {
	a, err := scanAccess(s.pool.QueryRow(ctx, `SELECT `+supportColumns+` FROM security.support_access WHERE support_access_id = $1::uuid AND requested_by = $2::uuid`, id, requestedBy))
	if errors.Is(err, pgx.ErrNoRows) {
		return supportaccess.Access{}, false, nil
	}
	return a, err == nil, err
}

// One statement: the access opens the first time a token is taken, and only then is its fact written (a second token changes nothing). The access
// must be approved, the caller must be the one who asked, and its hours must not be over: otherwise nothing matches and nothing is written.
// FOR UPDATE keeps two first tokens at once from writing the fact twice.
const openSupportAccess = `
WITH target AS (
    SELECT support_access_id, tenant_id, requested_by, reason, areas, expires_at, opened_at
    FROM security.support_access
    WHERE support_access_id = $1::uuid AND requested_by = $2::uuid AND status = 'APPROVED' AND expires_at > $3::timestamptz
    FOR UPDATE
), opened AS (
    UPDATE security.support_access a SET opened_at = $3::timestamptz
    FROM target WHERE a.support_access_id = target.support_access_id AND target.opened_at IS NULL
    RETURNING a.support_access_id
), audit AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, payload, correlation_id, occurred_at)
    SELECT target.tenant_id, 'PlatformExceptionalAccessOpened', target.support_access_id, target.requested_by,
           jsonb_build_object('authorizationId', target.support_access_id, 'platformAdministratorId', target.requested_by,
               'basis', 'TENANT_AUTHORIZATION', 'reason', target.reason, 'scope', to_jsonb(target.areas), 'includesSensitiveData', false,
               'openedAt', to_char($3::timestamptz AT TIME ZONE 'UTC', ` + utcTime + `),
               'expiresAt', to_char(target.expires_at AT TIME ZONE 'UTC', ` + utcTime + `)),
           $4, $3::timestamptz
    FROM target JOIN opened ON opened.support_access_id = target.support_access_id
)
SELECT count(*) FROM target`

// Open records that a token was taken at that instant. It says false when there is nothing to open: not approved, not the caller's, or over.
func (s *SupportAccesses) Open(ctx context.Context, requestedBy, id string, now time.Time, correlationID string) (supportaccess.Access, bool, error) {
	var matched int
	if err := s.pool.QueryRow(ctx, openSupportAccess, id, requestedBy, now, correlationID).Scan(&matched); err != nil {
		return supportaccess.Access{}, false, err
	}
	if matched == 0 {
		return supportaccess.Access{}, false, nil
	}
	a, found, err := s.FindOwn(ctx, requestedBy, id)
	return a, found, err
}

// One statement: the access closes while it is approved and its hours are not over, the sessions of the Platform Administrator are cut and
// the fact of the cut is written, and, if the access had been opened, the fact of its closing; or none of it. A never opened access has no
// closing fact: nothing opened, so nothing closes.
const closeSupportAccess = `
WITH closed AS (
    UPDATE security.support_access SET status = 'CLOSED', closed_at = $2::timestamptz, closed_reason = $3
    WHERE support_access_id = $1::uuid AND requested_by = $5::uuid AND status = 'APPROVED' AND expires_at > $2::timestamptz
    RETURNING support_access_id, tenant_id, requested_by, opened_at
), cut AS (
    UPDATE security.identity i SET sessions_revoked_from = GREATEST(COALESCE(i.sessions_revoked_from, $2::timestamptz), $2::timestamptz)
    FROM closed WHERE i.identity_id = closed.requested_by
    RETURNING i.identity_id, i.tenant_id, i.sessions_revoked_from
), revoked AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, reason, payload, correlation_id, occurred_at)
    SELECT cut.tenant_id, 'AccountSessionsRevoked', cut.identity_id, cut.identity_id, 'SUPPORT_ACCESS_CLOSED',
           jsonb_build_object('accountId', cut.identity_id, 'revokedFrom', to_char(cut.sessions_revoked_from AT TIME ZONE 'UTC', ` + utcTime + `),
               'reason', 'SUPPORT_ACCESS_CLOSED'), $4, $2::timestamptz
    FROM cut
), ended AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, reason, payload, correlation_id, occurred_at)
    SELECT closed.tenant_id, 'PlatformExceptionalAccessClosed', closed.support_access_id, closed.requested_by, $3,
           jsonb_build_object('authorizationId', closed.support_access_id, 'platformAdministratorId', closed.requested_by,
               'openedAt', to_char(closed.opened_at AT TIME ZONE 'UTC', ` + utcTime + `),
               'closedAt', to_char($2::timestamptz AT TIME ZONE 'UTC', ` + utcTime + `), 'endedBy', 'CLOSED_EARLY', 'reason', $3::text),
           $4, $2::timestamptz
    FROM closed WHERE closed.opened_at IS NOT NULL
)
SELECT count(*) FROM closed`

// Close ends an access before its time. It says false when the access is not the caller's, is not approved any more or has run out.
func (s *SupportAccesses) Close(ctx context.Context, a supportaccess.Access, correlationID string) (bool, error) {
	var closed int
	if err := s.pool.QueryRow(ctx, closeSupportAccess, a.ID, a.ClosedAt, a.ClosedReason, correlationID, a.RequestedBy).Scan(&closed); err != nil {
		return false, err
	}
	return closed == 1, nil
}

// the correlation id of the facts written by an expiry, which no request caused
const expiryCorrelationID = "support-access-expiry"

// One statement: the approved accesses whose hours are over (of one author, or of one tenant) become expired, and the ones that had been
// opened write the fact of their closing, dated at the end of their hours; or none. Asking again matches nothing.
const expireApproved = `
WITH expired AS (
    UPDATE security.support_access SET status = 'EXPIRED', closed_at = expires_at
    WHERE status = 'APPROVED' AND expires_at <= $1::timestamptz
      AND ($2 = '' OR requested_by = $2::uuid) AND ($3 = '' OR tenant_id = $3::uuid)
    RETURNING support_access_id, tenant_id, requested_by, opened_at, expires_at
)
INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, payload, correlation_id, occurred_at)
SELECT tenant_id, 'PlatformExceptionalAccessClosed', support_access_id, requested_by,
       jsonb_build_object('authorizationId', support_access_id, 'platformAdministratorId', requested_by,
           'openedAt', to_char(opened_at AT TIME ZONE 'UTC', ` + utcTime + `),
           'closedAt', to_char(expires_at AT TIME ZONE 'UTC', ` + utcTime + `), 'endedBy', 'EXPIRED'),
       '` + expiryCorrelationID + `', expires_at
FROM expired WHERE opened_at IS NOT NULL`

// ExpireApproved marks as expired the approved accesses that ran out, of one author or of one tenant (the other filter is empty).
func (s *SupportAccesses) ExpireApproved(ctx context.Context, requestedBy, tenantID string, now time.Time) error {
	if requestedBy == "" && tenantID == "" {
		return errors.New("an expiry is of one author or of one tenant, never of every tenant")
	}
	_, err := s.pool.Exec(ctx, expireApproved, now, requestedBy, tenantID)
	return err
}
