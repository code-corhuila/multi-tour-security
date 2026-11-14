package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// UserPermissions keeps the special permissions of the internal users of a tenant (HU-SEC-006, plan D-08).
type UserPermissions struct{ pool *pgxpool.Pool }

// NewUserPermissions expects a non-nil pool; the composition root owns it.
func NewUserPermissions(pool *pgxpool.Pool) *UserPermissions { return &UserPermissions{pool: pool} }

// the membership of an internal user of the tenant: a customer, the platform and another tenant's account have none that counts, so
// they are not found. $1 is the account, $2 the tenant and $3 the internal roles.
const permissionTarget = `
SELECT m.membership_id, i.identity_id, i.tenant_id
FROM security.identity i JOIN security.membership m USING (identity_id)
WHERE i.identity_id = $1::uuid AND i.tenant_id = $2::uuid AND EXISTS (SELECT 1 FROM security.membership_role mr
        WHERE mr.membership_id = m.membership_id AND mr.role = ANY($3))`

// One statement: the permission with who and when, and its event, are written or none. A permission already held (a row with no
// removal) matches nothing, so it writes no row and no event; one that was removed is held again and the removal is cleared. It
// cuts no session: an assignment reaches the next sign-in or refresh.
const grantPermission = `
WITH target AS (` + permissionTarget + `
), granted AS (
    INSERT INTO security.membership_permission (membership_id, permission, granted_at, granted_by)
    SELECT membership_id, $4, $5::timestamptz, $6 FROM target
    ON CONFLICT (membership_id, permission) DO UPDATE
        SET granted_at = EXCLUDED.granted_at, granted_by = EXCLUDED.granted_by, revoked_at = NULL, revoked_by = NULL
        WHERE security.membership_permission.revoked_at IS NOT NULL
    RETURNING membership_id
), audit AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, payload, correlation_id, occurred_at)
    SELECT t.tenant_id, 'SpecialPermissionGranted', t.identity_id, $7::uuid,
           jsonb_build_object('accountId', t.identity_id, 'tenantId', t.tenant_id, 'membershipId', t.membership_id, 'permission', $4::text,
               'grantedBy', jsonb_build_object('accountId', $7::text, 'role', $8::text),
               'grantedAt', to_char($5::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
           $9, $5::timestamptz
    FROM target t JOIN granted g USING (membership_id)
)
SELECT (SELECT count(*) FROM target)`

// One statement: the removal with who and when, the cutoff that cuts every session of the user, AccountSessionsRevoked with the actor
// and the reason, and SpecialPermissionRevoked are all written or none. Only a permission that is held matches, so removing one that
// is not writes nothing and never moves the cutoff. The cutoff and its event are those of an inactivation (userstatus.go).
const removePermission = `
WITH target AS (` + permissionTarget + `
), removed AS (
    UPDATE security.membership_permission p SET revoked_at = $5::timestamptz, revoked_by = $6
    FROM target t WHERE p.membership_id = t.membership_id AND p.permission = $4 AND p.revoked_at IS NULL
    RETURNING p.membership_id
), cut AS (
    UPDATE security.identity i SET sessions_revoked_from = GREATEST(COALESCE(i.sessions_revoked_from, $5::timestamptz), $5::timestamptz)
    FROM target t JOIN removed r USING (membership_id) WHERE i.identity_id = t.identity_id
    RETURNING i.identity_id, i.tenant_id, i.sessions_revoked_from
), sessions_event AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, reason, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'AccountSessionsRevoked', identity_id, $7::uuid, 'special permission removed: ' || $4::text,
           jsonb_strip_nulls(jsonb_build_object('accountId', identity_id, 'tenantId', tenant_id,
               'revokedFrom', to_char(sessions_revoked_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),
           $9, $5::timestamptz
    FROM cut
), audit AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, payload, correlation_id, occurred_at)
    SELECT t.tenant_id, 'SpecialPermissionRevoked', t.identity_id, $7::uuid,
           jsonb_build_object('accountId', t.identity_id, 'tenantId', t.tenant_id, 'membershipId', t.membership_id, 'permission', $4::text,
               'revokedBy', jsonb_build_object('accountId', $7::text, 'role', $8::text),
               'revokedAt', to_char($5::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
           $9, $5::timestamptz
    FROM target t JOIN removed r USING (membership_id)
)
SELECT (SELECT count(*) FROM target)`

// Holder gives the role and the permissions the user holds now. The role shown is the smallest by name of the internal ones, as the list
// shows it; a user has one internal role in Phase 1.
func (s *UserPermissions) Holder(ctx context.Context, tenantID, accountID string) (port.PermissionHolder, error) {
	var h port.PermissionHolder
	err := s.pool.QueryRow(ctx, `
SELECT (SELECT min(mr.role) FROM security.membership_role mr WHERE mr.membership_id = t.membership_id AND mr.role = ANY($3)),
       COALESCE((SELECT array_agg(p.permission ORDER BY p.permission) FROM security.membership_permission p
                 WHERE p.membership_id = t.membership_id AND p.revoked_at IS NULL), '{}')
FROM (`+permissionTarget+`) t`, accountID, tenantID, internalRoleNames).Scan(&h.Role, &h.Held)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.PermissionHolder{}, port.ErrUserNotFound
	}
	return h, err
}

func (s *UserPermissions) Grant(ctx context.Context, c port.PermissionChange) (port.Registered, error) {
	return s.write(ctx, grantPermission, c)
}

func (s *UserPermissions) Remove(ctx context.Context, c port.PermissionChange) (port.Registered, error) {
	return s.write(ctx, removePermission, c)
}

// write runs one of the two statements and answers the user as they are now, in the same transaction.
func (s *UserPermissions) write(ctx context.Context, statement string, c port.PermissionChange) (port.Registered, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return port.Registered{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var found int
	if err := tx.QueryRow(ctx, statement, c.AccountID, c.TenantID, internalRoleNames, c.Permission, c.Now, c.By, c.ActorID, c.ActorRole,
		c.CorrelationID).Scan(&found); err != nil {
		return port.Registered{}, err
	}
	if found == 0 {
		return port.Registered{}, port.ErrUserNotFound
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

var _ port.UserPermissions = (*UserPermissions)(nil)
