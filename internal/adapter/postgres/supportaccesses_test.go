package postgres_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HU-SEC-007 part A, security spec 009: the requests of the Platform Administrator, against the real engine.

func supportSetup(t *testing.T) (*postgres.SupportAccesses, *pgxpool.Pool, string) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewSupportAccesses(pool), pool, pgtest.MustAccount(t, pool, "", "root@multitour.example", "PLATFORM_ADMINISTRATOR")
}

func asked(t *testing.T, requester string, at time.Time) supportaccess.Access {
	t.Helper()
	a, err := supportaccess.New(tenant, requester, "The cash closing does not show the transfers", []string{"CASH", "RESERVATIONS"}, 4, at)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestI_ARequestIsStoredPendingAndReadBackWithItsIdAndWhatWasAsked(t *testing.T) {
	store, _, root := supportSetup(t)
	got, created, err := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if len(got.ID) != 36 || got.Status != supportaccess.Pending || got.TenantID != tenant || got.RequestedBy != root || got.Hours != 4 ||
		!got.RequestedAt.Equal(base) || !slices.Equal(got.Scope(), []string{"CASH", "RESERVATIONS"}) || got.Reason == "" {
		t.Fatalf("request = %+v", got)
	}
}

func TestI_TheSameKeyOfTheSameAuthorReturnsTheSameRequestAndStoresNoSecondOne(t *testing.T) {
	store, pool, root := supportSetup(t)
	first, _, err := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")
	if err != nil {
		t.Fatal(err)
	}
	other := asked(t, root, base.Add(time.Hour))
	other.Hours = 8
	again, created, err := store.Create(ctx, other, "ask-0001-abcd")
	if err != nil || created || again.ID != first.ID || again.Hours != 4 {
		t.Fatalf("created=%v err=%v again=%+v", created, err, again)
	}
	if n := rows(t, pool, "support_access"); n != 1 {
		t.Fatalf("%d rows", n)
	}
	// another author with the same key is another request
	second := pgtest.MustAccount(t, pool, "", "second-root@multitour.example", "PLATFORM_ADMINISTRATOR")
	if _, created, err := store.Create(ctx, asked(t, second, base), "ask-0001-abcd"); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}

func TestI_TwoRequestsWithOneKeyAtOnceStoreOneAndBothGetIt(t *testing.T) {
	store, pool, root := supportSetup(t)
	ids := make(chan string, 2)
	for i := 0; i < 2; i++ {
		go func() {
			got, _, err := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")
			if err != nil {
				t.Errorf("Create: %v", err)
			}
			ids <- got.ID
		}()
	}
	a, b := <-ids, <-ids
	if a == "" || a != b || rows(t, pool, "support_access") != 1 {
		t.Fatalf("ids %q %q, rows %d", a, b, rows(t, pool, "support_access"))
	}
}

func TestI_TheTableRefusesHoursOrAreasTheRulesDoNot(t *testing.T) {
	store, _, root := supportSetup(t)
	bad := asked(t, root, base)
	bad.Hours = 25
	if _, _, err := store.Create(ctx, bad, "ask-0001-abcd"); err == nil {
		t.Error("25 hours were stored")
	}
	bad = asked(t, root, base)
	bad.Areas = []supportaccess.Area{"MEDICAL"}
	if _, _, err := store.Create(ctx, bad, "ask-0002-abcd"); err == nil {
		t.Error("a sensitive area was stored")
	}
}

func TestI_TheListIsOfTheRequesterNewestFirstWithItsTotalAndFilters(t *testing.T) {
	store, pool, root := supportSetup(t)
	other := pgtest.MustAccount(t, pool, "", "second-root@multitour.example", "PLATFORM_ADMINISTRATOR")
	var ids []string
	for i := 0; i < 5; i++ {
		got, _, err := store.Create(ctx, asked(t, root, base.Add(time.Duration(i)*time.Minute)), fmt.Sprintf("ask-%04d-abcd", i))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, got.ID)
	}
	if _, _, err := store.Create(ctx, asked(t, other, base), "ask-9999-abcd"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE security.support_access SET status = 'REJECTED' WHERE support_access_id = $1::uuid`, ids[0]); err != nil {
		t.Fatal(err)
	}

	page, total, err := store.ListByRequester(ctx, root, "", 2, 0)
	if err != nil || total != 5 || len(page) != 2 || page[0].ID != ids[4] || page[1].ID != ids[3] {
		t.Fatalf("page 1: total=%d err=%v %v", total, err, page)
	}
	page, _, err = store.ListByRequester(ctx, root, "", 2, 4)
	if err != nil || len(page) != 1 || page[0].ID != ids[0] {
		t.Fatalf("last page: %v %v", err, page)
	}
	rejected, total, err := store.ListByRequester(ctx, root, "REJECTED", 20, 0)
	if err != nil || total != 1 || rejected[0].ID != ids[0] || rejected[0].Status != supportaccess.Rejected {
		t.Fatalf("rejected: total=%d err=%v", total, err)
	}
	// the other administrator sees only theirs
	mine, total, err := store.ListByRequester(ctx, other, "", 20, 0)
	if err != nil || total != 1 || len(mine) != 1 || mine[0].RequestedBy != other {
		t.Fatalf("other: total=%d err=%v", total, err)
	}
	if none, total, err := store.ListByRequester(ctx, root, "CLOSED", 20, 0); err != nil || total != 0 || len(none) != 0 {
		t.Fatalf("closed: %d %v", total, err)
	}
	// a page past the end still says how many there are
	if empty, total, err := store.ListByRequester(ctx, root, "", 20, 100); err != nil || len(empty) != 0 || total != 5 {
		t.Fatalf("past the end: total=%d err=%v", total, err)
	}
}

func TestI_OnlyThePendingRequestsPast72HoursAreMarkedExpired(t *testing.T) {
	store, pool, root := supportSetup(t)
	old, _, _ := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")
	young, _, _ := store.Create(ctx, asked(t, root, base.Add(40*time.Hour)), "ask-0002-abcd")
	approved, _, _ := store.Create(ctx, asked(t, root, base), "ask-0003-abcd")
	if _, err := pool.Exec(ctx, `UPDATE security.support_access SET status = 'APPROVED', decided_at = $2, expires_at = $3 WHERE support_access_id = $1::uuid`,
		approved.ID, base.Add(time.Hour), base.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.ExpirePending(ctx, base.Add(72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	status := func(id string) string {
		var s string
		if err := pool.QueryRow(ctx, `SELECT status FROM security.support_access WHERE support_access_id = $1::uuid`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if status(old.ID) != "EXPIRED" || status(young.ID) != "PENDING" || status(approved.ID) != "APPROVED" {
		t.Fatalf("old %s young %s approved %s", status(old.ID), status(young.ID), status(approved.ID))
	}
	// again changes nothing
	if err := store.ExpirePending(ctx, base.Add(72*time.Hour)); err != nil {
		t.Fatal(err)
	}
}
