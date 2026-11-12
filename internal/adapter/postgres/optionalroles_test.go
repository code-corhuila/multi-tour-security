package postgres_test

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HU-SEC-006, RN-SEC-005-12 to -14 and -16: the optional roles a tenant enables, against the real engine.

var roleAt = time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC)

func roleStore(t *testing.T) (*postgres.OptionalRoles, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewOptionalRoles(pool), pool
}

func roleChange(tenantID, role string) port.OptionalRoleChange {
	return port.OptionalRoleChange{TenantID: tenantID, Role: role, By: actorBy, ActorID: actorID, ActorRole: "TENANT_ADMINISTRATOR",
		CorrelationID: "corr-role", Now: roleAt}
}

func roleEvents(t *testing.T, pool *pgxpool.Pool, tenantID, eventType string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = $2`, tenantID, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func enabledRoles(t *testing.T, store *postgres.OptionalRoles, tenantID string) []string {
	t.Helper()
	states, err := store.List(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var on []string
	for _, s := range states {
		if s.Enabled {
			on = append(on, s.Role)
		}
	}
	return on
}

func TestI_ANewTenantHasTheThreeOptionalRolesInAFixedOrderAndNoneEnabled(t *testing.T) {
	store, _ := roleStore(t)
	got, err := store.List(ctx, tenant)
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	for i, role := range []string{"MANAGER", "ACCOUNTANT", "ANALYST"} {
		if got[i].Role != role || got[i].Enabled || !got[i].ChangedAt.IsZero() || got[i].ChangedBy != "" {
			t.Errorf("%d: %+v", i, got[i])
		}
	}
}

func TestI_EnablingKeepsWhoAndWhenAndWritesTheEventTogether(t *testing.T) {
	store, pool := roleStore(t)
	got, err := store.Enable(ctx, roleChange(tenant, "MANAGER"))
	if err != nil || got.Role != "MANAGER" || !got.Enabled || got.ChangedBy != actorBy || !got.ChangedAt.Equal(roleAt) {
		t.Fatalf("%+v %v", got, err)
	}
	if on := enabledRoles(t, store, tenant); !slices.Equal(on, []string{"MANAGER"}) {
		t.Fatalf("enabled: %v", on)
	}
	var actor, correlation, payload, tenantOfEvent string
	if err := pool.QueryRow(ctx, `SELECT actor_id::text, correlation_id, payload::text, tenant_id::text FROM security.outbox_event
		WHERE aggregate_id = $1::uuid AND event_type = 'OptionalRoleEnabled'`, tenant).Scan(&actor, &correlation, &payload, &tenantOfEvent); err != nil ||
		actor != actorID || correlation != "corr-role" || tenantOfEvent != tenant {
		t.Fatalf("event: actor=%s correlation=%s tenant=%s %v", actor, correlation, tenantOfEvent, err)
	}
	for _, want := range []string{tenant, "MANAGER", actorID, "TENANT_ADMINISTRATOR", "changedBy", "changedAt"} {
		if !strings.Contains(payload, want) {
			t.Errorf("the event does not say %s: %s", want, payload)
		}
	}
}

func TestI_EnablingAnEnabledRoleOrDisablingADisabledOneIsATransitionRefusedThatWritesNothing(t *testing.T) {
	store, pool := roleStore(t)
	if _, err := store.Disable(ctx, roleChange(tenant, "ANALYST")); !errors.Is(err, port.ErrStatusTransition) {
		t.Fatalf("disabling a role never enabled: %v", err)
	}
	if _, err := store.Enable(ctx, roleChange(tenant, "ANALYST")); err != nil {
		t.Fatal(err)
	}
	later := roleChange(tenant, "ANALYST")
	later.By, later.Now = "tenant-administrator/"+missing, roleAt.Add(time.Hour)
	if _, err := store.Enable(ctx, later); !errors.Is(err, port.ErrStatusTransition) {
		t.Fatalf("enabling twice: %v", err)
	}
	if _, err := store.Disable(ctx, roleChange(tenant, "ANALYST")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Disable(ctx, later); !errors.Is(err, port.ErrStatusTransition) {
		t.Fatalf("disabling twice: %v", err)
	}
	states, _ := store.List(ctx, tenant)
	if states[2].ChangedBy != actorBy || !states[2].ChangedAt.Equal(roleAt) {
		t.Fatalf("a refusal rewrote who changed it: %+v", states[2])
	}
	if a, b := roleEvents(t, pool, tenant, "OptionalRoleEnabled"), roleEvents(t, pool, tenant, "OptionalRoleDisabled"); a != 1 || b != 1 {
		t.Fatalf("events: %d enabled, %d disabled", a, b)
	}
}

func TestI_DisablingIsRefusedWhileAnActiveUserHoldsTheRoleAndAllowedWithOnlyInactiveHolders(t *testing.T) {
	store, pool := roleStore(t)
	if _, err := store.Enable(ctx, roleChange(tenant, "MANAGER")); err != nil {
		t.Fatal(err)
	}
	user(t, pool, tenant, "gone@example.com", pgtest.Options{Inactive: true}, "MANAGER")
	user(t, pool, tenant, "membership@example.com", pgtest.Options{MembershipInactive: true}, "MANAGER")
	active := user(t, pool, tenant, "boss@example.com", pgtest.Options{}, "MANAGER")
	if _, err := store.Disable(ctx, roleChange(tenant, "MANAGER")); !errors.Is(err, port.ErrRoleInUse) {
		t.Fatalf("an active manager holds the role: %v", err)
	}
	if on := enabledRoles(t, store, tenant); !slices.Equal(on, []string{"MANAGER"}) || roleEvents(t, pool, tenant, "OptionalRoleDisabled") != 0 {
		t.Fatalf("a refusal changed something: %v", on)
	}
	if _, err := pool.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, active); err != nil {
		t.Fatal(err)
	}
	got, err := store.Disable(ctx, roleChange(tenant, "MANAGER"))
	if err != nil || got.Enabled || got.ChangedBy != actorBy {
		t.Fatalf("with only inactive holders: %+v %v", got, err)
	}
	if roleEvents(t, pool, tenant, "OptionalRoleDisabled") != 1 {
		t.Fatal("the disabling wrote no event")
	}
	if _, err := store.Enable(ctx, roleChange(tenant, "MANAGER")); err != nil {
		t.Fatalf("a role can be enabled again: %v", err)
	}
	if n := roleEvents(t, pool, tenant, "OptionalRoleEnabled"); n != 2 {
		t.Fatalf("each real enabling writes its event: %d", n)
	}
}

func TestI_TheOptionalRolesOfAnotherTenantAreNeverSeenNorChanged(t *testing.T) {
	store, pool := roleStore(t)
	if _, err := store.Enable(ctx, roleChange(otherTenant, "ACCOUNTANT")); err != nil {
		t.Fatal(err)
	}
	user(t, pool, otherTenant, "other@example.com", pgtest.Options{}, "ANALYST")
	if on := enabledRoles(t, store, tenant); len(on) != 0 {
		t.Fatalf("another tenant's roles are shown: %v", on)
	}
	if _, err := store.Enable(ctx, roleChange(tenant, "ANALYST")); err != nil {
		t.Fatal(err)
	}
	// an active analyst of the other tenant does not keep this tenant from disabling its own role
	if _, err := store.Disable(ctx, roleChange(tenant, "ANALYST")); err != nil {
		t.Fatalf("a holder of another tenant counted: %v", err)
	}
	if on := enabledRoles(t, store, otherTenant); !slices.Equal(on, []string{"ACCOUNTANT"}) {
		t.Fatalf("another tenant's roles changed: %v", on)
	}
}

func TestI_IfTheEventCannotBeWrittenTheRoleIsNotChanged(t *testing.T) {
	store, pool := roleStore(t)
	bad := roleChange(tenant, "MANAGER")
	bad.CorrelationID = "" // the outbox refuses an event with no correlation id
	if _, err := store.Enable(ctx, bad); err == nil {
		t.Fatal("an event that the outbox refuses must fail the enabling")
	}
	if on := enabledRoles(t, store, tenant); len(on) != 0 {
		t.Fatalf("the role was enabled though its event was not written: %v", on)
	}
	if _, err := store.Enable(ctx, roleChange(tenant, "MANAGER")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Disable(ctx, bad); err == nil {
		t.Fatal("an event that the outbox refuses must fail the disabling")
	}
	if on := enabledRoles(t, store, tenant); !slices.Equal(on, []string{"MANAGER"}) {
		t.Fatalf("the role was disabled though its event was not written: %v", on)
	}
	_ = pool
}

func TestI_TwoEnablingsOrTwoDisablingsAtOnceWriteOneEventEach(t *testing.T) {
	for round := 0; round < 10; round++ {
		store, pool := roleStore(t)
		both := func(change func() error) {
			var wg sync.WaitGroup
			start := make(chan struct{})
			results := make(chan error, 2)
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); <-start; results <- change() }()
			}
			close(start)
			wg.Wait()
			close(results)
			done := 0
			for err := range results {
				switch {
				case err == nil:
					done++
				case !errors.Is(err, port.ErrStatusTransition):
					t.Fatalf("round %d: %v", round, err)
				}
			}
			if done != 1 {
				t.Fatalf("round %d: %d of two changes won", round, done)
			}
		}
		both(func() error { _, err := store.Enable(ctx, roleChange(tenant, "MANAGER")); return err })
		both(func() error { _, err := store.Disable(ctx, roleChange(tenant, "MANAGER")); return err })
		if a, b := roleEvents(t, pool, tenant, "OptionalRoleEnabled"), roleEvents(t, pool, tenant, "OptionalRoleDisabled"); a != 1 || b != 1 {
			t.Fatalf("round %d: events %d and %d", round, a, b)
		}
	}
}
