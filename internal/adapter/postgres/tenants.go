package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at, commercial_name)
VALUES ($1::uuid, $2, $3, $4::timestamptz, NULLIF($5, ''))
ON CONFLICT (tenant_id) DO UPDATE
SET identifier = EXCLUDED.identifier, status = EXCLUDED.status, occurred_at = EXCLUDED.occurred_at,
    commercial_name = COALESCE(EXCLUDED.commercial_name, security.tenant_copy.commercial_name)
WHERE security.tenant_copy.occurred_at < EXCLUDED.occurred_at`

// Apply keeps the instant in microseconds, the precision of the column, so that two events a few nanoseconds apart are
// not told apart in Go and found equal in the database.
func (r *Tenants) Apply(ctx context.Context, c tenant.Copy) (bool, error) {
	if c.OccurredAt.IsZero() {
		return false, errors.New("an event of a tenant has the instant it happened")
	}
	tag, err := r.pool.Exec(ctx, applyTenant, c.TenantID, c.Identifier, string(c.Status), c.OccurredAt.Truncate(time.Microsecond), cut(c.CommercialName, maxCommercialName))
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" { // unique_violation: the identifier is unique, and the tenant id is handled by ON CONFLICT
		// another tenant holds the identifier; the driver's error stays reachable for the log
		err = fmt.Errorf("%w: %w", port.ErrIdentifierTaken, err)
	}
	return err == nil && tag.RowsAffected() == 1, err
}

// maxCommercialName is what the column holds. A longer name is cut, because refusing it would refuse the whole event, and with
// it the status of the tenant, over a name that only decorates an e-mail.
const maxCommercialName = 100

func cut(text string, runes int) string {
	for i := range text {
		if runes == 0 {
			return text[:i]
		}
		runes--
	}
	return text
}

const selectTenant = `SELECT tenant_id::text, identifier, status, occurred_at, COALESCE(commercial_name, '') FROM security.tenant_copy WHERE `

func (r *Tenants) FindByIdentifier(ctx context.Context, identifier string) (tenant.Copy, bool, error) {
	return r.find(ctx, selectTenant+`identifier = $1`, identifier)
}

func (r *Tenants) FindByID(ctx context.Context, tenantID string) (tenant.Copy, bool, error) {
	return r.find(ctx, selectTenant+`tenant_id = $1::uuid`, tenantID)
}

func (r *Tenants) find(ctx context.Context, query, arg string) (tenant.Copy, bool, error) {
	var c tenant.Copy
	var status string
	err := r.pool.QueryRow(ctx, query, arg).Scan(&c.TenantID, &c.Identifier, &status, &c.OccurredAt, &c.CommercialName)
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
