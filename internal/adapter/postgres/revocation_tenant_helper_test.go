package postgres_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireRevocationsCarryTheTenant fails when an AccountSessionsRevoked fact of an account with a tenant lacks that tenant in its payload,
// or when the fact of a platform account (no tenant) carries one: the services that receive it read the tenant from the payload (RN-SEC-M-10).
func requireRevocationsCarryTheTenant(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var all, wrong int
	err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE (tenant_id IS NOT NULL AND payload->>'tenantId' IS DISTINCT FROM tenant_id::text)
		  OR (tenant_id IS NULL AND jsonb_exists(payload, 'tenantId')))
		FROM security.outbox_event WHERE event_type = 'AccountSessionsRevoked'`).Scan(&all, &wrong)
	if err != nil || all == 0 || wrong != 0 {
		t.Fatalf("%d of %d AccountSessionsRevoked facts do not carry their tenant in the payload (none is also a failure): %v", wrong, all, err)
	}
}
