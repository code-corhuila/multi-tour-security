package postgres_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-008, AC3 (RN-SEC-007-07, -08, -11): a person who is customer and team member loses only the team side when the Administrator
// inactivates the internal user, and gets it back when reactivated.

func TestI_InactivatingAPersonWithBothSidesSwitchesOffTheTeamSideOnly(t *testing.T) {
	store, pool := statusStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{}, "FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR")

	got, err := store.ChangeStatus(ctx, command(id, account.Inactive, "Left the team"))
	if err != nil || got.Account.Status != account.Inactive {
		t.Fatalf("%+v %v", got, err)
	}
	var identityStatus, customer, team string
	if err := pool.QueryRow(ctx, `SELECT i.identity_status,
			(SELECT r.role_status FROM security.membership_role r JOIN security.membership m USING (membership_id) WHERE m.identity_id = i.identity_id AND r.role = 'FINAL_CUSTOMER'),
			(SELECT r.role_status FROM security.membership_role r JOIN security.membership m USING (membership_id) WHERE m.identity_id = i.identity_id AND r.role = 'OPERATIONAL_COLLABORATOR')
		FROM security.identity i WHERE i.identity_id = $1::uuid`, id).Scan(&identityStatus, &customer, &team); err != nil {
		t.Fatal(err)
	}
	if identityStatus != "ACTIVE" || customer != "ACTIVE" || team != "INACTIVE" {
		t.Fatalf("account %s customer side %s team side %s", identityStatus, customer, team)
	}
	roles, err := postgres.NewAccounts(pool).RolesOf(ctx, id)
	if err != nil || !slices.Equal(roles, []string{"FINAL_CUSTOMER"}) {
		t.Fatalf("roles %v %v", roles, err)
	}
	// the sessions end as for any inactivation, and the fact is written once
	if n := revocations(t, pool, id); n != 1 {
		t.Fatalf("%d facts", n)
	}
	var cutoff *string
	if err := pool.QueryRow(ctx, `SELECT sessions_revoked_from::text FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&cutoff); err != nil || cutoff == nil {
		t.Fatalf("the sessions were not cut: %v", err)
	}
}

func TestI_ReactivatingGivesTheTeamSideBack(t *testing.T) {
	store, pool := statusStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{}, "FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR")
	if _, err := store.ChangeStatus(ctx, command(id, account.Inactive, "Left the team")); err != nil {
		t.Fatal(err)
	}
	got, err := store.ChangeStatus(ctx, command(id, account.Active, whyReact))
	if err != nil || got.Account.Status != account.Active {
		t.Fatalf("%+v %v", got, err)
	}
	roles, err := postgres.NewAccounts(pool).RolesOf(ctx, id)
	if err != nil || !slices.Equal(roles, []string{"FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR"}) {
		t.Fatalf("roles %v %v", roles, err)
	}
	// a second inactivation and reactivation are transitions like any other
	if _, err := store.ChangeStatus(ctx, command(id, account.Active, whyReact)); !errors.Is(err, port.ErrStatusTransition) {
		t.Fatalf("%v", err)
	}
}

func TestI_TheListShowsTheStatusOfTheTeamSideAndFiltersByIt(t *testing.T) {
	store, pool := statusStore(t)
	both := user(t, pool, tenant, "luis@example.com", pgtest.Options{}, "FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR")
	plain := user(t, pool, tenant, "ana@example.com", pgtest.Options{}, "MANAGER")
	if _, err := store.ChangeStatus(ctx, command(both, account.Inactive, "Left the team")); err != nil {
		t.Fatal(err)
	}
	dir := postgres.NewUserDirectory(pool)
	all, total, err := dir.List(ctx, tenant, port.UserFilter{Roles: account.InternalRoles()}, 20, 0)
	if err != nil || total != 2 {
		t.Fatalf("%d %v", total, err)
	}
	for _, u := range all {
		want := account.Active
		if u.Account.ID == both {
			want = account.Inactive
		}
		if u.Account.Status != want {
			t.Errorf("%s has status %v", u.Account.ID, u.Account.Status)
		}
	}
	inactive, n, err := dir.List(ctx, tenant, port.UserFilter{Roles: account.InternalRoles(), Status: "INACTIVE"}, 20, 0)
	if err != nil || n != 1 || inactive[0].Account.ID != both {
		t.Fatalf("inactive: %d %v", n, err)
	}
	active, n, err := dir.List(ctx, tenant, port.UserFilter{Roles: account.InternalRoles(), Status: "ACTIVE"}, 20, 0)
	if err != nil || n != 1 || active[0].Account.ID != plain {
		t.Fatalf("active: %d %v", n, err)
	}
}

func TestI_ATeamSideThatIsOffDoesNotCountAsAnAdministrator(t *testing.T) {
	store, pool := statusStore(t)
	double := user(t, pool, tenant, "ana@example.com", pgtest.Options{}, "FINAL_CUSTOMER", "TENANT_ADMINISTRATOR")
	plain := user(t, pool, tenant, "bea@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	if _, err := store.ChangeStatus(ctx, command(double, account.Inactive, "Left the team")); err != nil {
		t.Fatalf("one administrator remains: %v", err)
	}
	if _, err := store.ChangeStatus(ctx, command(plain, account.Inactive, "Left the team")); !errors.Is(err, port.ErrLastAdministrator) {
		t.Fatalf("the last administrator: %v", err)
	}
}

func TestI_AnAccountWithOnlyTheTeamSideIsInactivatedAsBefore(t *testing.T) {
	store, pool := statusStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{}, "MANAGER")
	if _, err := store.ChangeStatus(ctx, command(id, account.Inactive, "Left the company")); err != nil {
		t.Fatal(err)
	}
	var identityStatus string
	if err := pool.QueryRow(ctx, `SELECT identity_status FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&identityStatus); err != nil || identityStatus != "INACTIVE" {
		t.Fatalf("%s %v", identityStatus, err)
	}
}
