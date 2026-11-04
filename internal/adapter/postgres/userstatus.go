package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// UserStatus inactivates and reactivates the internal users of a tenant.
type UserStatus struct{ pool *pgxpool.Pool }

// NewUserStatus expects a non-nil pool; the composition root owns it.
func NewUserStatus(pool *pgxpool.Pool) *UserStatus { return &UserStatus{pool: pool} }

// internalRoleNames must stay equal to the internal roles of the use case that lists users (core/listusers): both name the
// five roles that a Tenant Administrator manages.
var internalRoleNames = []string{"TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "MANAGER", "ACCOUNTANT", "ANALYST"}

// isInternal keeps a customer, the platform and another tenant's account out of reach: they are not found, not refused.
const isInternal = `i.tenant_id = $2::uuid AND EXISTS (SELECT 1 FROM security.membership m
		JOIN security.membership_role mr USING (membership_id)
		WHERE m.identity_id = i.identity_id AND mr.role = ANY($8))`

// One statement: the status and its trace, the cutoff that cuts the sessions of an inactivation and its event are all
// written or none. The row must still have the status the change starts from, so two changes at once have one winner.
// Only an inactivation moves the cutoff, so a reactivation leaves the credentials issued before it cut.
const changeStatus = `
WITH changed AS (
    UPDATE security.identity i SET identity_status = $4, status_changed_at = $5::timestamptz, status_changed_by = $6, status_reason = $7,
        sessions_revoked_from = CASE WHEN $4 = 'INACTIVE'
            THEN GREATEST(COALESCE(i.sessions_revoked_from, $5::timestamptz), $5::timestamptz) ELSE i.sessions_revoked_from END
    WHERE i.identity_id = $1::uuid AND ` + isInternal + ` AND i.identity_status = $3
    RETURNING i.identity_id, i.tenant_id, i.sessions_revoked_from
), audit AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, reason, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'AccountSessionsRevoked', identity_id, $9::uuid, $7,
           jsonb_build_object('accountId', identity_id,
               'revokedFrom', to_char(sessions_revoked_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
           $10, $5::timestamptz
    FROM changed WHERE $4 = 'INACTIVE'
)
SELECT count(*) FROM changed`

// the status a change can start from: only an active user is inactivated and only an inactive one is reactivated
func startsFrom(to account.Status) (string, string, bool) {
	switch to {
	case account.Inactive:
		return "INACTIVE", "ACTIVE", true
	case account.Active:
		return "ACTIVE", "INACTIVE", true
	}
	return "", "", false
}

// the same test of "an internal user of the tenant" with the parameters it needs: the id, the tenant and the roles
var probe = `SELECT EXISTS (SELECT 1 FROM security.identity i WHERE i.identity_id = $1::uuid AND ` + strings.Replace(isInternal, "$8", "$3", 1) + `)`

func (s *UserStatus) ChangeStatus(ctx context.Context, c port.StatusCommand) (port.Registered, error) {
	to, from, possible := startsFrom(c.To)
	if !possible {
		return port.Registered{}, port.ErrStatusTransition
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return port.Registered{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if to == "INACTIVE" {
		if err := keepOneAdministrator(ctx, tx, c); err != nil {
			return port.Registered{}, err
		}
	}
	var changed int
	if err := tx.QueryRow(ctx, changeStatus, c.AccountID, c.TenantID, from, to, c.Now, c.By, c.Reason, internalRoleNames, c.ActorID, c.CorrelationID).Scan(&changed); err != nil {
		return port.Registered{}, err
	}
	if changed == 0 {
		// nothing changed: either it is not a user of the tenant, or it is already where the change goes
		var found bool
		if err := tx.QueryRow(ctx, probe, c.AccountID, c.TenantID, internalRoleNames).Scan(&found); err != nil {
			return port.Registered{}, err
		}
		if !found {
			return port.Registered{}, port.ErrUserNotFound
		}
		return port.Registered{}, port.ErrStatusTransition
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

// keepOneAdministrator refuses the inactivation of the only active Tenant Administrator of the tenant (RN-SEC-003-11). It locks
// every active administrator of the tenant (one whose membership is not active cannot act as one, as RolesOf says), in the order of their ids so that two calls cannot wait on each other, and counts them
// under the lock: two administrators inactivating each other at once are serialized, and the second finds the first already gone.
func keepOneAdministrator(ctx context.Context, tx pgx.Tx, c port.StatusCommand) error {
	rows, err := tx.Query(ctx, `SELECT i.identity_id::text FROM security.identity i
		WHERE i.tenant_id = $1::uuid AND i.identity_status = 'ACTIVE' AND EXISTS (SELECT 1 FROM security.membership m
			JOIN security.membership_role mr USING (membership_id) WHERE m.identity_id = i.identity_id AND m.membership_status = 'ACTIVE' AND mr.role = 'TENANT_ADMINISTRATOR')
		ORDER BY i.identity_id FOR NO KEY UPDATE OF i`, c.TenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	active, target := 0, false
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		active++
		target = target || id == c.AccountID
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if target && active == 1 {
		return port.ErrLastAdministrator
	}
	return nil
}

// readUser is one user of the tenant as the list shows it.
func readUser(ctx context.Context, q pgx.Tx, tenantID, id string) (port.Registered, error) {
	var u port.Registered
	var status string
	var temporary, changedAt *time.Time
	err := q.QueryRow(ctx, `SELECT identity_id::text, COALESCE(tenant_id::text, ''), email_normalized, identity_status, temporary_until,
			COALESCE(full_name, ''), COALESCE(phone, ''), email_verified, r.role, created_at,
			status_changed_at, COALESCE(status_changed_by, ''), COALESCE(status_reason, '')
		FROM security.identity `+userRole+` WHERE tenant_id = $1::uuid AND identity_id = $3::uuid`, tenantID, internalRoleNames, id).
		Scan(&u.Account.ID, &u.Account.TenantID, &u.Account.EmailNormalized, &status, &temporary, &u.FullName, &u.Phone, &u.EmailVerified,
			&u.Role, &u.CreatedAt, &changedAt, &u.Changed.By, &u.Changed.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.Registered{}, port.ErrUserNotFound
	}
	if err != nil {
		return port.Registered{}, err
	}
	if u.Account.Status, err = statusOf(status); err != nil {
		return port.Registered{}, err
	}
	u.Account.TemporaryUntil, u.CreatedAt, u.Changed.At = utc(temporary), u.CreatedAt.UTC(), utc(changedAt)
	return u, nil
}

var _ port.UserStatus = (*UserStatus)(nil)
