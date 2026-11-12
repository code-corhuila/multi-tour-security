package postgres_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HU-SEC-006, RN-SEC-005-07 to -09 and -16: assigning and removing a special permission, against the real engine.

var permAt = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)

func permStore(t *testing.T) (*postgres.UserPermissions, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewUserPermissions(pool), pool
}

func permChange(id, permission string) port.PermissionChange {
	return port.PermissionChange{TenantID: tenant, AccountID: id, Permission: permission, By: actorBy, ActorID: actorID,
		ActorRole: "TENANT_ADMINISTRATOR", CorrelationID: "corr-perm", Now: permAt}
}

func permEvents(t *testing.T, pool *pgxpool.Pool, id, eventType string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = $2`, id, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func permRow(t *testing.T, pool *pgxpool.Pool, id, permission string) (found bool, grantedBy string, revoked bool) {
	t.Helper()
	var revokedAt *time.Time
	err := pool.QueryRow(ctx, `SELECT p.granted_by, p.revoked_at FROM security.membership_permission p JOIN security.membership m USING (membership_id)
		WHERE m.identity_id = $1::uuid AND p.permission = $2`, id, permission).Scan(&grantedBy, &revokedAt)
	if err != nil {
		return false, "", false
	}
	return true, grantedBy, revokedAt != nil
}

func TestI_HolderGivesTheRoleAndTheHeldPermissionsAndAnythingThatIsNotAnInternalUserOfTheTenantIsNotFound(t *testing.T) {
	store, pool := permStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant(ctx, permChange(id, "CONSULT_SENSITIVE_DATA")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Remove(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	got, err := store.Holder(ctx, tenant, id)
	if err != nil || got.Role != "OPERATIONAL_COLLABORATOR" || len(got.Held) != 1 || got.Held[0] != "CONSULT_SENSITIVE_DATA" {
		t.Fatalf("%+v %v: a removed permission is no longer held", got, err)
	}
	other := user(t, pool, otherTenant, "other@example.com", pgtest.Options{}, "MANAGER")
	customer := user(t, pool, tenant, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	platform := user(t, pool, "", "root@example.com", pgtest.Options{}, "PLATFORM_ADMINISTRATOR")
	for name, acct := range map[string]string{"a user of another tenant": other, "a customer": customer, "the platform account": platform, "no account": missing} {
		if _, err := store.Holder(ctx, tenant, acct); !errors.Is(err, port.ErrUserNotFound) {
			t.Errorf("Holder, %s: %v", name, err)
		}
		if _, err := store.Grant(ctx, permChange(acct, "MANAGE_CASH")); !errors.Is(err, port.ErrUserNotFound) {
			t.Errorf("Grant, %s: %v", name, err)
		}
		if _, err := store.Remove(ctx, permChange(acct, "MANAGE_CASH")); !errors.Is(err, port.ErrUserNotFound) {
			t.Errorf("Remove, %s: %v", name, err)
		}
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.membership_permission p JOIN security.membership m USING (membership_id) WHERE m.identity_id <> $1::uuid`, id).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("a refusal wrote %d rows (%v)", rows, err)
	}
}

func TestI_AssigningKeepsWhoAndWhenWritesTheEventTogetherAndCutsNoSession(t *testing.T) {
	store, pool := permStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	got, err := store.Grant(ctx, permChange(id, "VALIDATE_PAYMENT_PROOFS"))
	if err != nil || got.Account.ID != id || got.Role != "OPERATIONAL_COLLABORATOR" || got.Account.PasswordHash != "" {
		t.Fatalf("%+v %v", got, err)
	}
	found, by, revoked := permRow(t, pool, id, "VALIDATE_PAYMENT_PROOFS")
	if !found || by != actorBy || revoked {
		t.Fatalf("row: found=%v by=%s revoked=%v", found, by, revoked)
	}
	var actor, correlation, payload, tenantOfEvent string
	if err := pool.QueryRow(ctx, `SELECT actor_id::text, correlation_id, payload::text, tenant_id::text FROM security.outbox_event
		WHERE aggregate_id = $1::uuid AND event_type = 'SpecialPermissionGranted'`, id).Scan(&actor, &correlation, &payload, &tenantOfEvent); err != nil ||
		actor != actorID || correlation != "corr-perm" || tenantOfEvent != tenant {
		t.Fatalf("event: actor=%s correlation=%s tenant=%s %v", actor, correlation, tenantOfEvent, err)
	}
	for _, want := range []string{id, tenant, "VALIDATE_PAYMENT_PROOFS", actorID, "TENANT_ADMINISTRATOR", "membershipId", "grantedAt"} {
		if !strings.Contains(payload, want) {
			t.Errorf("the event does not say %s: %s", want, payload)
		}
	}
	for _, secret := range []string{"hash", "Hash", "password", pgtest.ValidHash} {
		if strings.Contains(payload, secret) {
			t.Errorf("the event carries %q: %s", secret, payload)
		}
	}
	var cutoff *time.Time
	if err := pool.QueryRow(ctx, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&cutoff); err != nil || cutoff != nil ||
		permEvents(t, pool, id, "AccountSessionsRevoked") != 0 {
		t.Fatalf("assigning cut a session: cutoff=%v %v", cutoff, err)
	}
}

func TestI_AssigningAPermissionAlreadyHeldWritesNoRowAndNoEvent(t *testing.T) {
	store, pool := permStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	again := permChange(id, "MANAGE_CASH")
	again.By, again.Now = "tenant-administrator/"+missing, permAt.Add(time.Hour)
	if _, err := store.Grant(ctx, again); err != nil {
		t.Fatalf("a repeat is a no-op and not an error: %v", err)
	}
	if _, by, _ := permRow(t, pool, id, "MANAGE_CASH"); by != actorBy {
		t.Fatalf("a repeat rewrote who granted it: %s", by)
	}
	if n := permEvents(t, pool, id, "SpecialPermissionGranted"); n != 1 {
		t.Fatalf("a repeat wrote an event: %d", n)
	}
}

func TestI_RemovingKeepsWhoAndWhenCutsTheSessionsAndWritesBothEventsTogether(t *testing.T) {
	store, pool := permStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Remove(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	var revokedBy string
	var revokedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT p.revoked_by, p.revoked_at FROM security.membership_permission p JOIN security.membership m USING (membership_id)
		WHERE m.identity_id = $1::uuid AND p.permission = 'MANAGE_CASH'`, id).Scan(&revokedBy, &revokedAt); err != nil || revokedBy != actorBy || revokedAt == nil || !revokedAt.Equal(permAt) {
		t.Fatalf("revoked by=%s at=%v %v", revokedBy, revokedAt, err)
	}
	var cutoff time.Time
	if err := pool.QueryRow(ctx, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&cutoff); err != nil || !cutoff.Equal(permAt) {
		t.Fatalf("the sessions of the user must be cut from the removal: %v %v", cutoff, err)
	}
	var actor, reason, payload string
	if err := pool.QueryRow(ctx, `SELECT actor_id::text, reason, payload::text FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = 'AccountSessionsRevoked'`, id).
		Scan(&actor, &reason, &payload); err != nil || actor != actorID || reason != "special permission removed: MANAGE_CASH" || !strings.Contains(payload, "revokedFrom") {
		t.Fatalf("AccountSessionsRevoked: actor=%s reason=%q payload=%s %v", actor, reason, payload, err)
	}
	var revokedPayload string
	if err := pool.QueryRow(ctx, `SELECT actor_id::text || ' ' || payload::text FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = 'SpecialPermissionRevoked'`, id).Scan(&revokedPayload); err != nil ||
		!strings.Contains(revokedPayload, actorID) || !strings.Contains(revokedPayload, "MANAGE_CASH") || !strings.Contains(revokedPayload, "revokedAt") || strings.Contains(strings.ToLower(revokedPayload), "hash") {
		t.Fatalf("SpecialPermissionRevoked: %s %v", revokedPayload, err)
	}
}

func TestI_RemovingAPermissionNotHeldWritesNothingAndCutsNoSession(t *testing.T) {
	store, pool := permStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := store.Remove(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatalf("removing what is not held is a no-op and not an error: %v", err)
	}
	if _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Remove(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	later := permChange(id, "MANAGE_CASH")
	later.Now = permAt.Add(time.Hour)
	if _, err := store.Remove(ctx, later); err != nil {
		t.Fatalf("removing twice: %v", err)
	}
	var cutoff time.Time
	if err := pool.QueryRow(ctx, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&cutoff); err != nil || !cutoff.Equal(permAt) {
		t.Fatalf("a second removal moved the cutoff: %v %v", cutoff, err)
	}
	if n := permEvents(t, pool, id, "SpecialPermissionRevoked") + permEvents(t, pool, id, "AccountSessionsRevoked"); n != 2 {
		t.Fatalf("only the one real removal writes events: %d", n)
	}
}

func TestI_AssigningAgainAfterARemovalClearsTheRemovalAndWritesANewEvent(t *testing.T) {
	store, pool := permStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	for _, step := range []func() error{
		func() error { _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); return err },
		func() error { _, err := store.Remove(ctx, permChange(id, "MANAGE_CASH")); return err },
		func() error { _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); return err },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	if found, _, revoked := permRow(t, pool, id, "MANAGE_CASH"); !found || revoked {
		t.Fatalf("found=%v revoked=%v", found, revoked)
	}
	var cleared int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.membership_permission WHERE revoked_at IS NULL AND revoked_by IS NULL`).Scan(&cleared); err != nil || cleared != 1 {
		t.Fatalf("the removal must be cleared as a whole: %d %v", cleared, err)
	}
	if n := permEvents(t, pool, id, "SpecialPermissionGranted"); n != 2 {
		t.Fatalf("each real grant writes its event: %d", n)
	}
	held, err := store.Holder(ctx, tenant, id)
	if err != nil || len(held.Held) != 1 {
		t.Fatalf("%+v %v", held, err)
	}
}

func TestI_IfAnEventCannotBeWrittenNothingIsChanged(t *testing.T) {
	store, pool := permStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	bad := permChange(id, "MANAGE_CASH")
	bad.CorrelationID = "" // the outbox refuses an event with no correlation id
	if _, err := store.Grant(ctx, bad); err == nil {
		t.Fatal("an event that the outbox refuses must fail the grant")
	}
	if found, _, _ := permRow(t, pool, id, "MANAGE_CASH"); found {
		t.Fatal("the permission was written though its event was not")
	}
	if _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Remove(ctx, bad); err == nil {
		t.Fatal("an event that the outbox refuses must fail the removal")
	}
	if _, _, revoked := permRow(t, pool, id, "MANAGE_CASH"); revoked {
		t.Fatal("the permission was removed though its events were not written")
	}
	var cutoff *time.Time
	if err := pool.QueryRow(ctx, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&cutoff); err != nil || cutoff != nil {
		t.Fatalf("the sessions were cut though the removal failed: %v %v", cutoff, err)
	}
}

func TestI_AnInactiveUserKeepsItsPermissionsAndAnAdministratorCanStillRemoveThem(t *testing.T) {
	store, pool := permStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	held, err := store.Holder(ctx, tenant, id)
	if err != nil || len(held.Held) != 1 {
		t.Fatalf("an inactive user keeps what they held: %+v %v", held, err)
	}
	if _, err := store.Remove(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatalf("removing from an inactive user: %v", err)
	}
	if n := permEvents(t, pool, id, "SpecialPermissionRevoked"); n != 1 {
		t.Fatalf("events: %d", n)
	}
}

// two administrators doing the same change at once: one wins, the other finds it already done and writes nothing
func TestI_TwoAssignmentsOrTwoRemovalsAtOnceWriteOneEventEach(t *testing.T) {
	for round := 0; round < 10; round++ {
		store, pool := permStore(t)
		id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
		both := func(change func() error) {
			start, done := make(chan struct{}), make(chan error, 2)
			for i := 0; i < 2; i++ {
				go func() { <-start; done <- change() }()
			}
			close(start)
			for i := 0; i < 2; i++ {
				if err := <-done; err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
			}
		}
		both(func() error { _, err := store.Grant(ctx, permChange(id, "MANAGE_CASH")); return err })
		if n := permEvents(t, pool, id, "SpecialPermissionGranted"); n != 1 {
			t.Fatalf("round %d: two assignments at once wrote %d events", round, n)
		}
		both(func() error { _, err := store.Remove(ctx, permChange(id, "MANAGE_CASH")); return err })
		if a, b := permEvents(t, pool, id, "SpecialPermissionRevoked"), permEvents(t, pool, id, "AccountSessionsRevoked"); a != 1 || b != 1 {
			t.Fatalf("round %d: two removals at once wrote %d and %d events", round, a, b)
		}
	}
}
