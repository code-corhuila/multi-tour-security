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
	request := asked(t, root, base)
	start := make(chan struct{})
	ids := make(chan string, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			got, _, err := store.Create(ctx, request, "ask-0001-abcd")
			if err != nil {
				got.ID = "error: " + err.Error()
			}
			ids <- got.ID
		}()
	}
	close(start)
	a, b := <-ids, <-ids
	if len(a) != 36 || a != b || rows(t, pool, "support_access") != 1 {
		t.Fatalf("ids %q %q, rows %d", a, b, rows(t, pool, "support_access"))
	}
}

func TestI_TheRequestOfAKeyIsFoundByItsAuthorAndKeyOnly(t *testing.T) {
	store, pool, root := supportSetup(t)
	made, _, err := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")
	if err != nil {
		t.Fatal(err)
	}
	found, ok, err := store.FindByKey(ctx, root, "ask-0001-abcd")
	if err != nil || !ok || found.ID != made.ID {
		t.Fatalf("found=%v ok=%v err=%v", found.ID, ok, err)
	}
	other := pgtest.MustAccount(t, pool, "", "second-root@multitour.example", "PLATFORM_ADMINISTRATOR")
	if _, ok, err := store.FindByKey(ctx, other, "ask-0001-abcd"); err != nil || ok {
		t.Fatalf("another author found it: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.FindByKey(ctx, root, "ask-0002-abcd"); err != nil || ok {
		t.Fatalf("another key found it: ok=%v err=%v", ok, err)
	}
}

func TestI_ExpiringThePendingOnesOfOneAuthorLeavesTheOthersAlone(t *testing.T) {
	store, pool, root := supportSetup(t)
	other := pgtest.MustAccount(t, pool, "", "second-root@multitour.example", "PLATFORM_ADMINISTRATOR")
	mine, _, _ := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")
	theirs, _, _ := store.Create(ctx, asked(t, other, base), "ask-0001-abcd")
	if err := store.ExpirePending(ctx, root, base.Add(100*time.Hour)); err != nil {
		t.Fatal(err)
	}
	status := func(id string) string {
		var s string
		if err := pool.QueryRow(ctx, `SELECT status FROM security.support_access WHERE support_access_id = $1::uuid`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if status(mine.ID) != "EXPIRED" || status(theirs.ID) != "PENDING" {
		t.Fatalf("mine %s theirs %s", status(mine.ID), status(theirs.ID))
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
	if err := store.ExpirePending(ctx, root, base.Add(72*time.Hour)); err != nil {
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
	if err := store.ExpirePending(ctx, root, base.Add(72*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// The Tenant Administrator sees and decides the requests that concern their tenant (HU-SEC-007 part A, RN-SEC-009-03, -04, -07).

func askedFor(t *testing.T, requester, tenantID string, at time.Time) supportaccess.Access {
	t.Helper()
	a := asked(t, requester, at)
	a.TenantID = tenantID
	return a
}

func TestI_ARequestIsFoundForItsTenantOnly(t *testing.T) {
	store, _, root := supportSetup(t)
	made, _, err := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := store.FindForTenant(ctx, tenant, made.ID); err != nil || !ok || got.ID != made.ID {
		t.Fatalf("its tenant: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.FindForTenant(ctx, otherTenant, made.ID); err != nil || ok {
		t.Fatalf("another tenant: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.FindForTenant(ctx, tenant, "66666666-6666-4666-8666-666666666666"); err != nil || ok {
		t.Fatalf("a request that is not there: ok=%v err=%v", ok, err)
	}
}

func TestI_TheTenantListShowsTheRequestsOfThatTenantNewestFirstWithFilters(t *testing.T) {
	store, pool, root := supportSetup(t)
	var ids []string
	for i := 0; i < 3; i++ {
		got, _, err := store.Create(ctx, askedFor(t, root, tenant, base.Add(time.Duration(i)*time.Minute)), fmt.Sprintf("ask-%04d-abcd", i))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, got.ID)
	}
	if _, _, err := store.Create(ctx, askedFor(t, root, otherTenant, base), "ask-9999-abcd"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE security.support_access SET status = 'REJECTED' WHERE support_access_id = $1::uuid`, ids[0]); err != nil {
		t.Fatal(err)
	}
	page, total, err := store.ListByTenant(ctx, tenant, "", 2, 0)
	if err != nil || total != 3 || len(page) != 2 || page[0].ID != ids[2] || page[1].ID != ids[1] {
		t.Fatalf("page: total=%d err=%v %v", total, err, page)
	}
	rejected, total, err := store.ListByTenant(ctx, tenant, "REJECTED", 20, 0)
	if err != nil || total != 1 || rejected[0].ID != ids[0] {
		t.Fatalf("rejected: total=%d err=%v", total, err)
	}
	if other, total, err := store.ListByTenant(ctx, otherTenant, "", 20, 0); err != nil || total != 1 || len(other) != 1 || other[0].TenantID != otherTenant {
		t.Fatalf("other tenant: total=%d err=%v", total, err)
	}
	if empty, total, err := store.ListByTenant(ctx, tenant, "", 20, 100); err != nil || len(empty) != 0 || total != 3 {
		t.Fatalf("past the end: total=%d err=%v", total, err)
	}
}

func TestI_ExpiringThePendingOnesOfATenantLeavesTheOtherTenantsAlone(t *testing.T) {
	store, pool, root := supportSetup(t)
	mine, _, _ := store.Create(ctx, askedFor(t, root, tenant, base), "ask-0001-abcd")
	theirs, _, _ := store.Create(ctx, askedFor(t, root, otherTenant, base), "ask-0002-abcd")
	if err := store.ExpirePendingOfTenant(ctx, tenant, base.Add(100*time.Hour)); err != nil {
		t.Fatal(err)
	}
	status := func(id string) string {
		var s string
		if err := pool.QueryRow(ctx, `SELECT status FROM security.support_access WHERE support_access_id = $1::uuid`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if status(mine.ID) != "EXPIRED" || status(theirs.ID) != "PENDING" {
		t.Fatalf("mine %s theirs %s", status(mine.ID), status(theirs.ID))
	}
}

func TestI_ADecisionIsStoredOnlyWhileTheRequestIsPendingSoTwoAtOnceHaveOneWinner(t *testing.T) {
	store, pool, root := supportSetup(t)
	admin := pgtest.MustAccount(t, pool, tenant, "boss@example.com", "TENANT_ADMINISTRATOR")
	other := pgtest.MustAccount(t, pool, tenant, "boss2@example.com", "TENANT_ADMINISTRATOR")
	made, _, _ := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")

	approve, err := made.Approve(admin, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	reject, err := made.Reject(other, "Nobody asked for this", base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	type outcome struct {
		won bool
		err error
	}
	results := make(chan outcome, 2)
	for _, decision := range []supportaccess.Access{approve, reject} {
		go func() {
			<-start
			ok, err := store.Decide(ctx, decision)
			results <- outcome{ok, err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("errors: %v %v", first.err, second.err)
	}
	if first.won == second.won {
		t.Fatalf("both %v: one decision must win and the other must lose", first.won)
	}
	got, _, err := store.FindForTenant(ctx, tenant, made.ID)
	if err != nil || (got.Status != supportaccess.Approved && got.Status != supportaccess.Rejected) {
		t.Fatalf("status %s err %v", got.Status, err)
	}
	if got.Status == supportaccess.Rejected && !got.ExpiresAt.IsZero() {
		t.Fatalf("a rejection stored an end: %v", got.ExpiresAt)
	}
	if got.Status == supportaccess.Approved && (got.DecidedBy != admin || !got.ExpiresAt.Equal(base.Add(5*time.Hour))) {
		t.Fatalf("approved = %+v", got)
	}
	if got.Status == supportaccess.Rejected && (got.DecidedBy != other || got.DecisionReason != "Nobody asked for this") {
		t.Fatalf("rejected = %+v", got)
	}
	// a third decision on a decided request loses
	if ok, err := store.Decide(ctx, approve); err != nil || ok {
		t.Fatalf("a third decision: ok=%v err=%v", ok, err)
	}
}

func TestI_ADecisionIsNotStoredAfterTheWindowNorForAnotherTenant(t *testing.T) {
	store, pool, root := supportSetup(t)
	admin := pgtest.MustAccount(t, pool, tenant, "boss@example.com", "TENANT_ADMINISTRATOR")
	made, _, _ := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")

	late, err := made.Approve(admin, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// the request waited 72 hours: the same decision, dated at the end of the window, is refused by the store
	late.DecidedAt = base.Add(72 * time.Hour)
	if ok, err := store.Decide(ctx, late); err != nil || ok {
		t.Fatalf("after the window: ok=%v err=%v", ok, err)
	}
	foreign, _ := made.Approve(admin, base.Add(time.Hour))
	foreign.TenantID = otherTenant
	if ok, err := store.Decide(ctx, foreign); err != nil || ok {
		t.Fatalf("another tenant: ok=%v err=%v", ok, err)
	}
	if got, _, _ := store.FindForTenant(ctx, tenant, made.ID); got.Status != supportaccess.Pending {
		t.Fatalf("the request changed: %s", got.Status)
	}
}
