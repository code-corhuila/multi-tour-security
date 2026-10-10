package postgres_test

import (
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// The Platform Administrator has no tenant: the event of the revocation has none either.
func TestI_ThePlatformAdministratorChoosesAPasswordAndTheEventHasNoTenant(t *testing.T) {
	pool := pgtest.Open(t)
	id, err := pgtest.AccountWith(ctx, pool, "", "root@example.com", pgtest.ValidHash,
		pgtest.Options{TemporaryUntil: base.Add(time.Hour)}, "PLATFORM_ADMINISTRATOR")
	if err != nil {
		t.Fatal(err)
	}
	accounts := postgres.NewAccounts(pool)
	if err := accounts.ChangePassword(ctx, id, chosenHash, base, "c"); err != nil {
		t.Fatal(err)
	}
	var withoutTenant int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountSessionsRevoked'
		AND aggregate_id = $1::uuid AND tenant_id IS NULL`, id).Scan(&withoutTenant); err != nil || withoutTenant != 1 {
		t.Fatalf("one event with no tenant: %d %v", withoutTenant, err)
	}
}
