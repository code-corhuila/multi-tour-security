package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HU-SEC-005, RN-SEC-003-09 and -10: inactivating and reactivating an internal user, against the real engine.

const (
	actorID  = "7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	actorBy  = "tenant-administrator/" + actorID
	missing  = "11111111-2222-4333-8444-555555555555"
	whyReact = "Back from leave"
)

var at = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func statusStore(t *testing.T) (*postgres.UserStatus, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewUserStatus(pool), pool
}

func command(id string, to account.Status, reason string) port.StatusCommand {
	return port.StatusCommand{TenantID: tenant, AccountID: id, To: to, By: actorBy, ActorID: actorID, Reason: reason, CorrelationID: "corr-status", Now: at}
}

func revocations(t *testing.T, pool *pgxpool.Pool, id string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = 'AccountSessionsRevoked'`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestI_InactivatingChangesTheStatusKeepsTheTraceCutsTheSessionsAndWritesTheEventTogether(t *testing.T) {
	store, pool := statusStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{}, "MANAGER")

	got, err := store.ChangeStatus(ctx, command(id, account.Inactive, "Left the company"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Account.ID != id || got.Account.Status != account.Inactive || got.Role != "MANAGER" || got.Account.PasswordHash != "" ||
		got.Changed.By != actorBy || got.Changed.Reason != "Left the company" || !got.Changed.At.Equal(at) {
		t.Fatalf("the answer is %+v", got)
	}
	var status, by, reason string
	var cutoff time.Time
	if err := pool.QueryRow(ctx, `SELECT identity_status, status_changed_by, status_reason, sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id).
		Scan(&status, &by, &reason, &cutoff); err != nil || status != "INACTIVE" || by != actorBy || reason != "Left the company" || !cutoff.Equal(at) {
		t.Fatalf("stored %s %s %s %v %v", status, by, reason, cutoff, err)
	}
	var actor, why, correlation string
	if err := pool.QueryRow(ctx, `SELECT actor_id::text, reason, correlation_id FROM security.outbox_event
		WHERE aggregate_id = $1::uuid AND event_type = 'AccountSessionsRevoked'`, id).Scan(&actor, &why, &correlation); err != nil ||
		actor != actorID || why != "Left the company" || correlation != "corr-status" {
		t.Fatalf("event: actor=%s reason=%s correlation=%s %v", actor, why, correlation, err)
	}
	if n := revocations(t, pool, id); n != 1 {
		t.Fatalf("events = %d", n)
	}
}

func TestI_ReactivatingRestoresTheSameRecordKeepsTheCutoffAndWritesNoRevocation(t *testing.T) {
	store, pool := statusStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{}, "MANAGER")
	if _, err := store.ChangeStatus(ctx, command(id, account.Inactive, "Left")); err != nil {
		t.Fatal(err)
	}
	later := command(id, account.Active, whyReact)
	later.Now = at.Add(time.Hour)
	got, err := store.ChangeStatus(ctx, later)
	if err != nil || got.Account.ID != id || got.Account.Status != account.Active || got.Changed.Reason != whyReact || !got.Changed.At.Equal(later.Now) {
		t.Fatalf("%+v %v", got, err)
	}
	var cutoff time.Time
	if err := pool.QueryRow(ctx, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&cutoff); err != nil || !cutoff.Equal(at) {
		t.Fatalf("the credentials issued before the inactivation must stay cut: cutoff %v %v", cutoff, err)
	}
	if n := revocations(t, pool, id); n != 1 {
		t.Fatalf("reactivating wrote a revocation: %d events", n)
	}
}

func TestI_ARepeatedOrImpossibleChangeIsRefusedAndWritesNothing(t *testing.T) {
	store, pool := statusStore(t)
	active := user(t, pool, tenant, "a@example.com", pgtest.Options{}, "ANALYST")
	gone := user(t, pool, tenant, "b@example.com", pgtest.Options{Inactive: true}, "ANALYST")
	for name, c := range map[string]port.StatusCommand{
		"reactivating an active user":   command(active, account.Active, "x"),
		"inactivating an inactive user": command(gone, account.Inactive, "x"),
		"going to pending":              command(active, account.Pending, "x"),
	} {
		if _, err := store.ChangeStatus(ctx, c); !errors.Is(err, port.ErrStatusTransition) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var touched int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.identity WHERE status_changed_at IS NOT NULL OR sessions_revoked_from IS NOT NULL`).Scan(&touched); err != nil || touched != 0 {
		t.Fatalf("a refusal wrote %d rows (%v)", touched, err)
	}
	if n := revocations(t, pool, active) + revocations(t, pool, gone); n != 0 {
		t.Fatalf("a refusal wrote %d events", n)
	}
}

func TestI_OnlyAnInternalUserOfTheTenantCanBeChanged(t *testing.T) {
	store, pool := statusStore(t)
	other := user(t, pool, otherTenant, "other@example.com", pgtest.Options{}, "MANAGER")
	customer := user(t, pool, tenant, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	platform := user(t, pool, "", "root@example.com", pgtest.Options{}, "PLATFORM_ADMINISTRATOR")
	for name, id := range map[string]string{"a user of another tenant": other, "a customer": customer, "the platform account": platform, "no account": missing} {
		if _, err := store.ChangeStatus(ctx, command(id, account.Inactive, "x")); !errors.Is(err, port.ErrUserNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT identity_status FROM security.identity WHERE identity_id = $1::uuid`, other).Scan(&status); err != nil || status != "ACTIVE" {
		t.Fatalf("the user of the other tenant is %s (%v)", status, err)
	}
}

func TestI_IfTheEventCannotBeWrittenTheStatusDoesNotChange(t *testing.T) {
	store, pool := statusStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{}, "MANAGER")
	bad := command(id, account.Inactive, "x")
	bad.CorrelationID = "" // the outbox refuses an event with no correlation id
	if _, err := store.ChangeStatus(ctx, bad); err == nil {
		t.Fatal("an event that the outbox refuses must fail the change")
	}
	var status string
	var cutoff *time.Time
	if err := pool.QueryRow(ctx, `SELECT identity_status, sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&status, &cutoff); err != nil ||
		status != "ACTIVE" || cutoff != nil {
		t.Fatalf("status=%s cutoff=%v: the change and its event must be written together (%v)", status, cutoff, err)
	}
}

func TestI_TheListShowsTheLastChangeOfEachUser(t *testing.T) {
	store, pool := statusStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{}, "MANAGER")
	user(t, pool, tenant, "ana@example.com", pgtest.Options{}, "ANALYST")
	if _, err := store.ChangeStatus(ctx, command(id, account.Inactive, "Left")); err != nil {
		t.Fatal(err)
	}
	got, _, err := postgres.NewUserDirectory(pool).List(ctx, tenant, port.UserFilter{Roles: internalRoles}, 20, 0)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	for _, u := range got {
		changed := u.Account.ID == id
		if changed && (u.Changed.By != actorBy || u.Changed.Reason != "Left" || !u.Changed.At.Equal(at)) || !changed && !u.Changed.At.IsZero() {
			t.Fatalf("%s shows %+v", u.Account.EmailNormalized, u.Changed)
		}
	}
}
