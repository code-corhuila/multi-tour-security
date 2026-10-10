package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ port.Tenants = (*Tenants)(nil)

// Tenants reads and writes security.tenant_copy.
type Tenants struct {
	pool *pgxpool.Pool
}

func NewTenants(pool *pgxpool.Pool) *Tenants { return &Tenants{pool: pool} }

// One statement decides "newer" and writes, so two events of one tenant that arrive together end in the newest one.
const applyTenant = `
INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at)
VALUES ($1::uuid, $2, $3, $4::timestamptz)
ON CONFLICT (tenant_id) DO UPDATE
SET identifier = EXCLUDED.identifier, status = EXCLUDED.status, occurred_at = EXCLUDED.occurred_at
WHERE security.tenant_copy.occurred_at < EXCLUDED.occurred_at`

// Apply keeps the instant in microseconds, the precision of the column, so that two events a few nanoseconds apart are
// not told apart in Go and found equal in the database.
func (r *Tenants) Apply(ctx context.Context, c tenant.Copy) (bool, error) {
	if c.OccurredAt.IsZero() {
		return false, errors.New("an event of a tenant has the instant it happened")
	}
	tag, err := r.pool.Exec(ctx, applyTenant, c.TenantID, c.Identifier, string(c.Status), c.OccurredAt.Truncate(time.Microsecond))
	return err == nil && tag.RowsAffected() == 1, err
}

const selectTenant = `SELECT tenant_id::text, identifier, status, occurred_at FROM security.tenant_copy WHERE `

func (r *Tenants) FindByIdentifier(ctx context.Context, identifier string) (tenant.Copy, bool, error) {
	return r.find(ctx, selectTenant+`identifier = $1`, identifier)
}

func (r *Tenants) FindByID(ctx context.Context, tenantID string) (tenant.Copy, bool, error) {
	return r.find(ctx, selectTenant+`tenant_id = $1::uuid`, tenantID)
}

func (r *Tenants) find(ctx context.Context, query, arg string) (tenant.Copy, bool, error) {
	var c tenant.Copy
	var status string
	err := r.pool.QueryRow(ctx, query, arg).Scan(&c.TenantID, &c.Identifier, &status, &c.OccurredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.Copy{}, false, nil
	}
	if err != nil {
		return tenant.Copy{}, false, err
	}
	c.Status = tenant.Status(status)
	c.OccurredAt = c.OccurredAt.UTC()
	return c, true, nil
}
