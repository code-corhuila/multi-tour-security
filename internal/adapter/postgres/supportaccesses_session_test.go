package postgres_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HU-SEC-007 part A, security spec 009: opening, closing and running out of a support access, and the facts they write
// (RN-SEC-009-05, -06, -08; plan D-05, D-07, D-08).

func approvedAccess(t *testing.T, store *postgres.SupportAccesses, pool *pgxpool.Pool, root string, key string) supportaccess.Access {
	t.Helper()
	made, _, err := store.Create(ctx, asked(t, root, base), key)
	if err != nil {
		t.Fatal(err)
	}
	admin := pgtest.MustAccount(t, pool, tenant, "boss-"+key+"@example.com", "TENANT_ADMINISTRATOR")
	approved, err := made.Approve(admin, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Decide(ctx, approved); err != nil || !ok {
		t.Fatalf("decide: ok=%v err=%v", ok, err)
	}
	return approved
}

func facts(t *testing.T, pool *pgxpool.Pool, eventType string) []map[string]any {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT jsonb_build_object('tenantId', tenant_id::text, 'aggregateId', aggregate_id::text, 'actorId', COALESCE(actor_id::text, ''),
		'reason', COALESCE(reason, ''), 'correlationId', correlation_id, 'payload', payload) FROM security.outbox_event WHERE event_type = $1 ORDER BY occurred_at, outbox_event_id`, eventType)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestI_TheFirstTokenOpensTheAccessAndWritesTheFactOnceWithWhatTheAuditNeeds(t *testing.T) {
	store, pool, root := supportSetup(t)
	approved := approvedAccess(t, store, pool, root, "ask-0001-abcd")

	opened, ok, err := store.Open(ctx, root, approved.ID, base.Add(2*time.Hour), "corr-open")
	if err != nil || !ok || !opened.OpenedAt.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("open: ok=%v err=%v %+v", ok, err, opened)
	}
	// a second token changes nothing: the access opened once
	again, ok, err := store.Open(ctx, root, approved.ID, base.Add(3*time.Hour), "corr-open-2")
	if err != nil || !ok || !again.OpenedAt.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("second open: ok=%v err=%v %+v", ok, err, again)
	}
	got := facts(t, pool, "PlatformExceptionalAccessOpened")
	if len(got) != 1 {
		t.Fatalf("%d facts", len(got))
	}
	f := got[0]
	payload, _ := f["payload"].(map[string]any)
	if f["tenantId"] != tenant || f["aggregateId"] != approved.ID || f["actorId"] != root || f["correlationId"] != "corr-open" {
		t.Fatalf("envelope = %v", f)
	}
	scope, _ := payload["scope"].([]any)
	if payload["authorizationId"] != approved.ID || payload["platformAdministratorId"] != root || payload["basis"] != "TENANT_AUTHORIZATION" ||
		payload["reason"] != approved.Reason || payload["includesSensitiveData"] != false || len(scope) != 2 || scope[0] != "CASH" ||
		payload["openedAt"] != "2026-10-10T12:00:00.000000Z" || payload["expiresAt"] != "2026-10-10T15:00:00.000000Z" {
		t.Fatalf("payload = %v", payload)
	}
}

func TestI_NoTokenIsTakenBeforeTheApprovalAfterTheEndOrForAnotherAdministrator(t *testing.T) {
	store, pool, root := supportSetup(t)
	pending, _, _ := store.Create(ctx, asked(t, root, base), "ask-0001-abcd")
	approved := approvedAccess(t, store, pool, root, "ask-0002-abcd")
	other := pgtest.MustAccount(t, pool, "", "second-root@multitour.example", "PLATFORM_ADMINISTRATOR")

	if _, ok, err := store.Open(ctx, root, pending.ID, base.Add(2*time.Hour), "corr"); err != nil || ok {
		t.Errorf("pending: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.Open(ctx, other, approved.ID, base.Add(2*time.Hour), "corr"); err != nil || ok {
		t.Errorf("another administrator: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.Open(ctx, root, approved.ID, approved.ExpiresAt, "corr"); err != nil || ok {
		t.Errorf("at the end: ok=%v err=%v", ok, err)
	}
	if n := len(facts(t, pool, "PlatformExceptionalAccessOpened")); n != 0 {
		t.Errorf("%d facts for a token that was not given", n)
	}
}

func TestI_ClosingEndsTheAccessCutsTheSessionsAndWritesTheFactsTogether(t *testing.T) {
	store, pool, root := supportSetup(t)
	approved := approvedAccess(t, store, pool, root, "ask-0001-abcd")
	if _, ok, err := store.Open(ctx, root, approved.ID, base.Add(2*time.Hour), "corr-open"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	closed, err := approved.Close("The incident is solved", base.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Close(ctx, closed, "corr-close"); err != nil || !ok {
		t.Fatalf("close: ok=%v err=%v", ok, err)
	}
	got, _, _ := store.FindOwn(ctx, root, approved.ID)
	if got.Status != supportaccess.Closed || got.ClosedReason != "The incident is solved" || !got.ClosedAt.Equal(base.Add(3*time.Hour)) || !got.OpenedAt.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("closed = %+v", got)
	}
	ended := facts(t, pool, "PlatformExceptionalAccessClosed")
	if len(ended) != 1 {
		t.Fatalf("%d closing facts", len(ended))
	}
	payload, _ := ended[0]["payload"].(map[string]any)
	if ended[0]["tenantId"] != tenant || ended[0]["actorId"] != root || ended[0]["correlationId"] != "corr-close" || payload["authorizationId"] != approved.ID ||
		payload["endedBy"] != "CLOSED_EARLY" || payload["reason"] != "The incident is solved" || payload["openedAt"] != "2026-10-10T12:00:00.000000Z" ||
		payload["closedAt"] != "2026-10-10T13:00:00.000000Z" {
		t.Fatalf("closing fact = %v", ended[0])
	}
	revoked := facts(t, pool, "AccountSessionsRevoked")
	if len(revoked) != 1 || revoked[0]["aggregateId"] != root {
		t.Fatalf("sessions revoked = %v", revoked)
	}
	var cutoff time.Time
	if err := pool.QueryRow(ctx, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, root).Scan(&cutoff); err != nil || !cutoff.Equal(base.Add(3*time.Hour)) {
		t.Fatalf("cutoff = %v %v", cutoff, err)
	}
	// closing again, or after the end, does nothing
	if ok, err := store.Close(ctx, closed, "corr-close-2"); err != nil || ok {
		t.Fatalf("closing twice: ok=%v err=%v", ok, err)
	}
	if n := len(facts(t, pool, "PlatformExceptionalAccessClosed")); n != 1 {
		t.Fatalf("%d closing facts after a second close", n)
	}
}

func TestI_ClosingAnAccessThatWasNeverOpenedCutsTheSessionsButWritesNoClosingFact(t *testing.T) {
	store, pool, root := supportSetup(t)
	approved := approvedAccess(t, store, pool, root, "ask-0001-abcd")
	closed, _ := approved.Close("Not needed any more", base.Add(2*time.Hour))
	if ok, err := store.Close(ctx, closed, "corr-close"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if n := len(facts(t, pool, "PlatformExceptionalAccessClosed")); n != 0 {
		t.Errorf("%d closing facts for an access that never opened", n)
	}
	if n := len(facts(t, pool, "AccountSessionsRevoked")); n != 1 {
		t.Errorf("%d revocations", n)
	}
}

func TestI_TheApprovedAccessesThatRanOutAreMarkedExpiredAndOnlyTheOpenedOnesWriteTheClosingFact(t *testing.T) {
	store, pool, root := supportSetup(t)
	opened := approvedAccess(t, store, pool, root, "ask-0001-abcd")
	unopened := approvedAccess(t, store, pool, root, "ask-0002-abcd")
	alive := approvedAccess(t, store, pool, root, "ask-0003-abcd")
	if _, ok, err := store.Open(ctx, root, opened.ID, base.Add(2*time.Hour), "corr-open"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	// the three were approved at the same instant for 4 hours; this one is made to last longer
	if _, err := pool.Exec(ctx, `UPDATE security.support_access SET expires_at = $2 WHERE support_access_id = $1::uuid`, alive.ID, base.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	after := base.Add(6 * time.Hour)
	if err := store.ExpireApproved(ctx, root, "", after); err != nil {
		t.Fatal(err)
	}
	status := func(id string) string {
		var s string
		if err := pool.QueryRow(ctx, `SELECT status FROM security.support_access WHERE support_access_id = $1::uuid`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if status(opened.ID) != "EXPIRED" || status(unopened.ID) != "EXPIRED" || status(alive.ID) != "APPROVED" {
		t.Fatalf("opened %s unopened %s alive %s", status(opened.ID), status(unopened.ID), status(alive.ID))
	}
	ended := facts(t, pool, "PlatformExceptionalAccessClosed")
	if len(ended) != 1 || ended[0]["aggregateId"] != opened.ID {
		t.Fatalf("closing facts = %v", ended)
	}
	payload, _ := ended[0]["payload"].(map[string]any)
	if payload["endedBy"] != "EXPIRED" || payload["closedAt"] != "2026-10-10T15:00:00.000000Z" {
		t.Fatalf("payload = %v", payload)
	}
	if _, has := payload["reason"]; has {
		t.Errorf("an expiry has no reason: %v", payload)
	}
	// again writes nothing more, and the opening of an expired access is refused
	if err := store.ExpireApproved(ctx, root, "", after); err != nil {
		t.Fatal(err)
	}
	if n := len(facts(t, pool, "PlatformExceptionalAccessClosed")); n != 1 {
		t.Errorf("%d closing facts after a second expiry", n)
	}
	if _, ok, _ := store.Open(ctx, root, opened.ID, after, "corr"); ok {
		t.Error("an expired access was opened")
	}
}

func TestI_ExpiringByTenantTouchesOnlyThatTenantAndByAuthorOnlyThatAuthor(t *testing.T) {
	store, pool, root := supportSetup(t)
	other := pgtest.MustAccount(t, pool, "", "second-root@multitour.example", "PLATFORM_ADMINISTRATOR")
	mine := approvedAccess(t, store, pool, root, "ask-0001-abcd")
	theirs := approvedAccess(t, store, pool, other, "ask-0002-abcd")
	after := base.Add(6 * time.Hour)
	if err := store.ExpireApproved(ctx, "", tenant, after); err != nil {
		t.Fatal(err)
	}
	status := func(id string) string {
		var s string
		if err := pool.QueryRow(ctx, `SELECT status FROM security.support_access WHERE support_access_id = $1::uuid`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if status(mine.ID) != "EXPIRED" || status(theirs.ID) != "EXPIRED" {
		t.Fatalf("by tenant: %s %s", status(mine.ID), status(theirs.ID))
	}
	revived := approvedAccess(t, store, pool, root, "ask-0003-abcd")
	revivedOther := approvedAccess(t, store, pool, other, "ask-0004-abcd")
	if err := store.ExpireApproved(ctx, root, "", after); err != nil {
		t.Fatal(err)
	}
	if status(revived.ID) != "EXPIRED" || status(revivedOther.ID) != "APPROVED" {
		t.Fatalf("by author: %s %s", status(revived.ID), status(revivedOther.ID))
	}
}
