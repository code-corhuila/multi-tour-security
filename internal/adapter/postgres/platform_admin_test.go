package postgres_test

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/jackc/pgx/v5/pgxpool"
)

func countOf(t *testing.T, pool *pgxpool.Pool, query string) int {
	t.Helper()
	return count(t, pool, query)
}

// I·bootstrap_creates_one_admin_once (RN-SEC-001-09): the Platform Administrator exists only because a one-shot command
// made the account.
func TestI_TheFirstPlatformAdministratorIsMadeWithNoTenantARoleAndATemporaryCredential(t *testing.T) {
	pool := pgtest.Open(t)
	admins := postgres.NewPlatformAdmins(pool)
	made, err := admins.CreateFirst(ctx, "root@example.com", chosenHash, base.Add(72*time.Hour))
	if err != nil || !made {
		t.Fatalf("made=%v err=%v", made, err)
	}
	var email, hash, status, createdBy, role string
	var tenantNull bool
	var until time.Time
	err = pool.QueryRow(ctx, `SELECT i.email_normalized, i.password_hash, i.identity_status, i.tenant_id IS NULL, i.temporary_until, m.created_by, r.role
		FROM security.identity i JOIN security.membership m USING (identity_id) JOIN security.membership_role r USING (membership_id)`).
		Scan(&email, &hash, &status, &tenantNull, &until, &createdBy, &role)
	if err != nil || email != "root@example.com" || hash != chosenHash || status != "ACTIVE" || !tenantNull || !until.Equal(base.Add(72*time.Hour)) ||
		createdBy != "bootstrap" || role != "PLATFORM_ADMINISTRATOR" {
		t.Fatalf("%q %q %q tenantNull=%v %v %q %q: %v", email, hash, status, tenantNull, until, createdBy, role, err)
	}
	if n := countOf(t, pool, `SELECT count(*) FROM security.membership`); n != 1 {
		t.Fatalf("one membership: %d", n)
	}
}

func TestI_ASecondCallWithAnyEmailDoesNothing(t *testing.T) {
	pool := pgtest.Open(t)
	admins := postgres.NewPlatformAdmins(pool)
	if made, err := admins.CreateFirst(ctx, "root@example.com", chosenHash, base); err != nil || !made {
		t.Fatalf("first: %v %v", made, err)
	}
	for _, email := range []string{"root@example.com", "other@example.com"} {
		if made, err := admins.CreateFirst(ctx, email, chosenHash, base); err != nil || made {
			t.Errorf("%s: made=%v err=%v", email, made, err)
		}
	}
	if n := countOf(t, pool, `SELECT count(*) FROM security.identity`); n != 1 {
		t.Fatalf("still one account: %d", n)
	}
}

func TestI_AdministratorsOfTenantsDoNotCountAsThePlatformOne(t *testing.T) {
	pool := pgtest.Open(t)
	pgtest.MustAccount(t, pool, tenant, "boss@example.com", "TENANT_ADMINISTRATOR")
	if made, err := postgres.NewPlatformAdmins(pool).CreateFirst(ctx, "root@example.com", chosenHash, base); err != nil || !made {
		t.Fatalf("a tenant account is not a platform one: %v %v", made, err)
	}
}

func TestI_EightCallsAtOnceWithDifferentEmailsMakeExactlyOneAdministrator(t *testing.T) {
	pool := pgtest.Open(t)
	admins := postgres.NewPlatformAdmins(pool)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var made atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := admins.CreateFirst(ctx, "root"+strings.Repeat("x", i)+"@example.com", chosenHash, base)
			if err != nil {
				t.Error(err)
			}
			if ok {
				made.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if made.Load() != 1 || countOf(t, pool, `SELECT count(*) FROM security.identity WHERE tenant_id IS NULL`) != 1 {
		t.Fatalf("one winner: %d", made.Load())
	}
}

func TestI_ABadHashOrEmailLeavesNothingBehind(t *testing.T) {
	pool := pgtest.Open(t)
	admins := postgres.NewPlatformAdmins(pool)
	if made, err := admins.CreateFirst(ctx, "root@example.com", "plain-password", base); err == nil || made {
		t.Fatalf("a password in clear was stored: %v %v", made, err)
	}
	if made, err := admins.CreateFirst(ctx, "Root@Example.com", chosenHash, base); err == nil || made {
		t.Fatalf("an e-mail with capitals breaks the table: %v %v", made, err)
	}
	for _, table := range []string{"identity", "membership", "membership_role"} {
		if n := countOf(t, pool, `SELECT count(*) FROM security.`+table); n != 0 {
			t.Errorf("%s keeps %d rows of a refused creation", table, n)
		}
	}
}
