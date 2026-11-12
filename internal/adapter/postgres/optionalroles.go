package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// OptionalRoles keeps the optional roles that each tenant enabled (HU-SEC-006, plan D-09).
type OptionalRoles struct{ pool *pgxpool.Pool }

// NewOptionalRoles expects a non-nil pool; the composition root owns it.
func NewOptionalRoles(pool *pgxpool.Pool) *OptionalRoles { return &OptionalRoles{pool: pool} }

// One statement: the role is enabled with who and when, and its event is written, or none. A role that is already enabled matches
// nothing, so it writes no row and no event; one that was disabled, or that the tenant never touched, is enabled.
const enableRole = `
WITH enabled AS (
    INSERT INTO security.tenant_optional_role (tenant_id, role, enabled, changed_at, changed_by)
    VALUES ($1::uuid, $2, true, $3::timestamptz, $4)
    ON CONFLICT (tenant_id, role) DO UPDATE
        SET enabled = true, changed_at = EXCLUDED.changed_at, changed_by = EXCLUDED.changed_by
        WHERE NOT security.tenant_optional_role.enabled
    RETURNING tenant_id, role
), audit AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'OptionalRoleEnabled', tenant_id, $5::uuid,
           jsonb_build_object('tenantId', tenant_id, 'role', role, 'changedBy', jsonb_build_object('accountId', $5::text, 'role', $6::text),
               'changedAt', to_char($3::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
           $7, $3::timestamptz
    FROM enabled
)
SELECT count(*) FROM enabled`

// the disabling of a role, once the count under the lock allowed it: the role is disabled with who and when and its event is written, or none
const disableRole = `
WITH disabled AS (
    UPDATE security.tenant_optional_role SET enabled = false, changed_at = $3::timestamptz, changed_by = $4
    WHERE tenant_id = $1::uuid AND role = $2 AND enabled
    RETURNING tenant_id, role
), audit AS (
    INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, actor_id, payload, correlation_id, occurred_at)
    SELECT tenant_id, 'OptionalRoleDisabled', tenant_id, $5::uuid,
           jsonb_build_object('tenantId', tenant_id, 'role', role, 'changedBy', jsonb_build_object('accountId', $5::text, 'role', $6::text),
               'changedAt', to_char($3::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
           $7, $3::timestamptz
    FROM disabled
)
SELECT count(*) FROM disabled`

// the active accounts of the tenant with an active membership that hold the role: the ones that keep it from being disabled
const activeHolders = `
SELECT count(*) FROM security.identity i
JOIN security.membership m USING (identity_id)
JOIN security.membership_role r USING (membership_id)
WHERE i.tenant_id = $1::uuid AND i.identity_status = 'ACTIVE' AND m.membership_status = 'ACTIVE' AND r.role = $2`

// List gives the three optional roles, in a fixed order: each with its row, or not enabled when the tenant never touched it.
func (s *OptionalRoles) List(ctx context.Context, tenantID string) ([]port.OptionalRoleState, error) {
	return readRoles(ctx, s.pool, tenantID)
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func readRoles(ctx context.Context, q querier, tenantID string) ([]port.OptionalRoleState, error) {
	rows, err := q.Query(ctx, `SELECT role, enabled, changed_at, changed_by FROM security.tenant_optional_role WHERE tenant_id = $1::uuid`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stored := map[string]port.OptionalRoleState{}
	for rows.Next() {
		var st port.OptionalRoleState
		if err := rows.Scan(&st.Role, &st.Enabled, &st.ChangedAt, &st.ChangedBy); err != nil {
			return nil, err
		}
		st.ChangedAt = st.ChangedAt.UTC()
		stored[st.Role] = st
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]port.OptionalRoleState, 0, 3)
	for _, role := range account.OptionalRoles() {
		st, ok := stored[role]
		if !ok {
			st = port.OptionalRoleState{Role: role}
		}
		out = append(out, st)
	}
	return out, nil
}

func (s *OptionalRoles) Enable(ctx context.Context, c port.OptionalRoleChange) (port.OptionalRoleState, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return port.OptionalRoleState{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var changed int
	if err := tx.QueryRow(ctx, enableRole, c.TenantID, c.Role, c.Now, c.By, c.ActorID, c.ActorRole, c.CorrelationID).Scan(&changed); err != nil {
		return port.OptionalRoleState{}, err
	}
	if changed == 0 {
		return port.OptionalRoleState{}, port.ErrStatusTransition
	}
	return finish(ctx, tx, c)
}

// Disable counts the active holders under the lock of the setting row, in the same transaction as the write: the registration of a user
// with the role reads that row in share mode, so a registration and a disabling at once are serialized and none lands between the count
// and the update (plan D-09, D-10). It is the atomicity trade-off that keepOneAdministrator makes. It relies on READ COMMITTED, the
// default of the pool: the count takes its snapshot after the lock is granted, so it sees a registration that committed while it waited.
func (s *OptionalRoles) Disable(ctx context.Context, c port.OptionalRoleChange) (port.OptionalRoleState, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return port.OptionalRoleState{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT enabled FROM security.tenant_optional_role WHERE tenant_id = $1::uuid AND role = $2 FOR UPDATE`, c.TenantID, c.Role).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		return port.OptionalRoleState{}, port.ErrStatusTransition
	}
	if err != nil {
		return port.OptionalRoleState{}, err
	}
	var holders int
	if err := tx.QueryRow(ctx, activeHolders, c.TenantID, c.Role).Scan(&holders); err != nil {
		return port.OptionalRoleState{}, err
	}
	if holders > 0 {
		return port.OptionalRoleState{}, port.ErrRoleInUse
	}
	var changed int
	if err := tx.QueryRow(ctx, disableRole, c.TenantID, c.Role, c.Now, c.By, c.ActorID, c.ActorRole, c.CorrelationID).Scan(&changed); err != nil {
		return port.OptionalRoleState{}, err
	}
	if changed == 0 {
		return port.OptionalRoleState{}, port.ErrStatusTransition
	}
	return finish(ctx, tx, c)
}

// finish answers the role as it is now, in the transaction that wrote it, and commits.
func finish(ctx context.Context, tx pgx.Tx, c port.OptionalRoleChange) (port.OptionalRoleState, error) {
	states, err := readRoles(ctx, tx, c.TenantID)
	if err != nil {
		return port.OptionalRoleState{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return port.OptionalRoleState{}, err
	}
	for _, st := range states {
		if st.Role == c.Role {
			return st, nil
		}
	}
	return port.OptionalRoleState{}, errors.New("the role that was changed is not one of the optional roles")
}

var _ port.OptionalRoles = (*OptionalRoles)(nil)
