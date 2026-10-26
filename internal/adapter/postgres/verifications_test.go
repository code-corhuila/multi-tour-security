package postgres_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The tests below cover the store of the verification links (spec 004-hu-sec-003, RN-SEC-004-02, -04 to -08).

func verificationSetup(t *testing.T) (*postgres.Verifications, *pgxpool.Pool, string) {
	t.Helper()
	pool := pgtest.Open(t)
	id, err := pgtest.AccountWith(ctx, pool, tenant, "ana@example.com", pgtest.ValidHash, pgtest.Options{Pending: true}, "FINAL_CUSTOMER")
	if err != nil {
		t.Fatal(err)
	}
	return postgres.NewVerifications(pool), pool, id
}

func issue(t *testing.T, store *postgres.Verifications, id string, l port.NewLink, at time.Time) bool {
	t.Helper()
	ok, err := store.Issue(ctx, id, l, at, 3, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return ok
}

func TestI_AnIssuedLinkIsFoundByItsHashWithItsAccountTenantAndExpiry(t *testing.T) {
	store, pool, id := verificationSetup(t)
	l := linkN(1, base)
	if !issue(t, store, id, l, base) {
		t.Fatal("the first link of a pending account was not written")
	}
	got, found, err := store.Find(ctx, l.TokenHash)
	if err != nil || !found {
		t.Fatalf("Find: %+v %v %v", got, found, err)
	}
	if got.AccountID != id || got.TenantID != tenant || !got.ExpiresAt.Equal(l.ExpiresAt) || !got.UsedAt.IsZero() || !got.ReplacedAt.IsZero() {
		t.Fatalf("state = %+v", got)
	}
	if _, found, err := store.Find(ctx, linkN(99, base).TokenHash); err != nil || found {
		t.Fatalf("an unknown hash must be not found: %v %v", found, err)
	}
	var stored string
	if err := pool.QueryRow(ctx, `SELECT token_hash FROM security.email_verification`).Scan(&stored); err != nil || stored != l.TokenHash {
		t.Fatalf("the table keeps only the hash: %q %v", stored, err)
	}
}

func TestI_ANewLinkRetiresTheEarlierOnes(t *testing.T) {
	store, _, id := verificationSetup(t)
	first, second := linkN(1, base), linkN(2, base.Add(time.Minute))
	issue(t, store, id, first, base)
	if !issue(t, store, id, second, base.Add(time.Minute)) {
		t.Fatal("the second link was not written")
	}
	a, _, _ := store.Find(ctx, first.TokenHash)
	b, _, _ := store.Find(ctx, second.TokenHash)
	if !a.ReplacedAt.Equal(base.Add(time.Minute)) || !b.ReplacedAt.IsZero() {
		t.Fatalf("first replaced at %v, second replaced at %v: only the newest may work", a.ReplacedAt, b.ReplacedAt)
	}
}

func TestI_TheFourthLinkInAnHourIsNotWrittenAndTheWindowSlides(t *testing.T) {
	store, pool, id := verificationSetup(t)
	for i := 0; i < 3; i++ {
		if !issue(t, store, id, linkN(i, base), base.Add(time.Duration(i)*10*time.Minute)) {
			t.Fatalf("link %d was refused under the limit", i+1)
		}
	}
	if issue(t, store, id, linkN(3, base), base.Add(30*time.Minute)) {
		t.Fatal("the fourth link within the hour was written")
	}
	if n := rows(t, pool, "email_verification"); n != 3 {
		t.Fatalf("%d rows, want 3: a refused link writes nothing", n)
	}
	if !issue(t, store, id, linkN(4, base), base.Add(61*time.Minute)) {
		t.Fatal("an hour after the first link, the window must have room again")
	}
}

func TestI_OnlyAPendingAccountOfThisTenantGetsALink(t *testing.T) {
	store, pool, _ := verificationSetup(t)
	active := pgtest.MustAccount(t, pool, tenant, "luis@example.com", "FINAL_CUSTOMER")
	if issue(t, store, active, linkN(1, base), base) {
		t.Fatal("an account that is already verified got a link")
	}
	if issue(t, store, "00000000-0000-4000-8000-0000000000ff", linkN(2, base), base) {
		t.Fatal("an account that does not exist got a link")
	}
	if n := rows(t, pool, "email_verification"); n != 0 {
		t.Fatalf("%d rows written for accounts that cannot receive a link", n)
	}
}

func TestI_LinksIssuedAtTheSameTimeNeverPassTheLimit(t *testing.T) {
	store, pool, id := verificationSetup(t)
	var written atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if issue(t, store, id, linkN(n, base), base) {
				written.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if written.Load() != 3 || rows(t, pool, "email_verification") != 3 {
		t.Fatalf("%d links written, %d rows: exactly three may pass", written.Load(), rows(t, pool, "email_verification"))
	}
	var valid int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.email_verification WHERE replaced_at IS NULL`).Scan(&valid); err != nil || valid != 1 {
		t.Fatalf("%d links still work, want exactly the newest: %v", valid, err)
	}
}

func TestI_TheWindowOfAnHourClosesExactlyAnHourAfterTheLink(t *testing.T) {
	store, _, id := verificationSetup(t)
	for i := 0; i < 3; i++ {
		issue(t, store, id, linkN(i, base), base)
	}
	if issue(t, store, id, linkN(10, base), base.Add(time.Hour-time.Second)) {
		t.Fatal("a second before the hour is over, the window is still full")
	}
	if !issue(t, store, id, linkN(11, base), base.Add(time.Hour)) {
		t.Fatal("exactly an hour after the links, the window has room again")
	}
}
