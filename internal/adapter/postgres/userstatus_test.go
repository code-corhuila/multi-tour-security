package postgres_test

import (
	"errors"
	"slices"
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
	requireRevocationsCarryTheTenant(t, pool)
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

// HU-SEC-005, RN-SEC-003-11: the last active Tenant Administrator of a tenant cannot be inactivated.

func TestI_TheLastActiveAdministratorCannotBeInactivatedNotEvenByTheirOwnAccountAndNothingIsWritten(t *testing.T) {
	store, pool := statusStore(t)
	admin := user(t, pool, tenant, "admin@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	user(t, pool, tenant, "manager@example.com", pgtest.Options{}, "MANAGER")
	user(t, pool, otherTenant, "other-admin@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	if _, err := store.ChangeStatus(ctx, command(admin, account.Inactive, "x")); !errors.Is(err, port.ErrLastAdministrator) {
		t.Fatalf("the only administrator of the tenant was inactivated: %v (an administrator of another tenant does not count)", err)
	}
	var status string
	var cutoff *time.Time
	if err := pool.QueryRow(ctx, `SELECT identity_status, sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, admin).Scan(&status, &cutoff); err != nil ||
		status != "ACTIVE" || cutoff != nil || revocations(t, pool, admin) != 0 {
		t.Fatalf("a refusal wrote something: %s %v", status, cutoff)
	}
}

func TestI_AnInactiveAdministratorDoesNotCountAsActiveAndWithTwoActiveOnesOneCanBeInactivated(t *testing.T) {
	store, pool := statusStore(t)
	first := user(t, pool, tenant, "a@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	user(t, pool, tenant, "b@example.com", pgtest.Options{Inactive: true}, "TENANT_ADMINISTRATOR")
	if _, err := store.ChangeStatus(ctx, command(first, account.Inactive, "x")); !errors.Is(err, port.ErrLastAdministrator) {
		t.Fatalf("an inactive administrator was counted as active: %v", err)
	}
	second := user(t, pool, tenant, "c@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	if _, err := store.ChangeStatus(ctx, command(first, account.Inactive, "x")); err != nil {
		t.Fatalf("with two active administrators one can be inactivated: %v", err)
	}
	if _, err := store.ChangeStatus(ctx, command(second, account.Inactive, "x")); !errors.Is(err, port.ErrLastAdministrator) {
		t.Fatalf("the other one is now the last: %v", err)
	}
	// reactivating an administrator is never refused by this rule
	if _, err := store.ChangeStatus(ctx, command(first, account.Active, "back")); err != nil {
		t.Fatalf("reactivating: %v", err)
	}
}

func TestI_AUserThatIsNotAnAdministratorCanAlwaysBeInactivated(t *testing.T) {
	store, pool := statusStore(t)
	user(t, pool, tenant, "admin@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	manager := user(t, pool, tenant, "manager@example.com", pgtest.Options{}, "MANAGER")
	if _, err := store.ChangeStatus(ctx, command(manager, account.Inactive, "x")); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestI_TwoAdministratorsInactivatingEachOtherAtOnceLeaveOneActive(t *testing.T) {
	for round := 0; round < 15; round++ {
		store, pool := statusStore(t)
		a := user(t, pool, tenant, "a@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
		b := user(t, pool, tenant, "b@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
		results := make(chan error, 2)
		start := make(chan struct{})
		for _, id := range []string{a, b} {
			go func() {
				<-start
				_, err := store.ChangeStatus(ctx, command(id, account.Inactive, "x"))
				results <- err
			}()
		}
		close(start)
		var done, refused int
		for i := 0; i < 2; i++ {
			switch err := <-results; {
			case err == nil:
				done++
			case errors.Is(err, port.ErrLastAdministrator):
				refused++
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		var active int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.identity WHERE tenant_id = $1::uuid AND identity_status = 'ACTIVE'`, tenant).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if done != 1 || refused != 1 || active != 1 {
			t.Fatalf("round %d: %d inactivated, %d refused, %d still active: the tenant must keep one administrator", round, done, refused, active)
		}
	}
}

func TestI_AnAdministratorWhoseMembershipIsNotActiveCannotActAsOneSoTheyDoNotCount(t *testing.T) {
	store, pool := statusStore(t)
	active := user(t, pool, tenant, "a@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	user(t, pool, tenant, "b@example.com", pgtest.Options{MembershipInactive: true}, "TENANT_ADMINISTRATOR")
	if _, err := store.ChangeStatus(ctx, command(active, account.Inactive, "x")); !errors.Is(err, port.ErrLastAdministrator) {
		t.Fatalf("an administrator who cannot sign in as one was counted: %v", err)
	}
}

// HU-SEC-006: the answer of a change of status shows the permissions the user holds, as the list does.
func TestI_TheAnswerOfAChangeOfStatusShowsTheHeldPermissions(t *testing.T) {
	store, pool := statusStore(t)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := postgres.NewUserPermissions(pool).Grant(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	got, err := store.ChangeStatus(ctx, command(id, account.Inactive, "Left"))
	if err != nil || !slices.Equal(got.Permissions, []string{"MANAGE_CASH"}) {
		t.Fatalf("%+v %v: an inactive user keeps what it held", got.Permissions, err)
	}
}
