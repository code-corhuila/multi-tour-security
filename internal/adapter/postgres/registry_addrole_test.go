package postgres_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-008, RN-SEC-007-01, -09, -10: the internal role goes to the account of the customer, and nothing else is written.

const userScope = "user:" + tenant

func added(account, role string) port.AddedRole {
	return port.AddedRole{TenantID: tenant, AccountID: account, Role: role}
}

func TestI_TheRoleIsAddedToTheCustomerAccountAndNothingElseIsWritten(t *testing.T) {
	registry, pool := registrySetup(t)
	id := pgtest.MustAccount(t, pool, tenant, "luis@example.com", "FINAL_CUSTOMER")
	identities, outbox := rows(t, pool, "identity"), rows(t, pool, "outbox_event")

	got, err := registry.AddRole(ctx, added(id, "OPERATIONAL_COLLABORATOR"), userScope, "key-0001-abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got.Account.ID != id {
		t.Fatalf("%+v", got.Account)
	}
	if !slices.Equal(got.Roles, []string{"FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR"}) {
		t.Fatalf("roles %v", got.Roles)
	}
	if rows(t, pool, "identity") != identities || rows(t, pool, "outbox_event") != outbox {
		t.Fatal("adding the role created an account or wrote a fact")
	}
	var hash string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&hash); err != nil || hash != pgtest.ValidHash {
		t.Fatalf("the password of the person changed: %v", err)
	}
}

func TestI_TheRepeatOfTheKeyFindsTheAccountWithBothRolesAndAddsNothing(t *testing.T) {
	registry, pool := registrySetup(t)
	id := pgtest.MustAccount(t, pool, tenant, "luis@example.com", "FINAL_CUSTOMER")
	if _, err := registry.AddRole(ctx, added(id, "OPERATIONAL_COLLABORATOR"), userScope, "key-0001-abcd"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AddRole(ctx, added(id, "OPERATIONAL_COLLABORATOR"), userScope, "key-0001-abcd"); !errors.Is(err, port.ErrKeyTaken) {
		t.Fatalf("the repeat of the key: %v", err)
	}
	found, ok, err := registry.FindKey(ctx, userScope, "key-0001-abcd")
	if err != nil || !ok || found.Account.ID != id || !slices.Equal(found.Roles, []string{"FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR"}) {
		t.Fatalf("%+v %v %v", found, ok, err)
	}
}

func TestI_AnAccountThatIsNotAnActiveVerifiedCustomerOfTheTenantIsRefused(t *testing.T) {
	registry, pool := registrySetup(t)
	pending, _ := pgtest.AccountWith(ctx, pool, tenant, "pending@example.com", pgtest.ValidHash, pgtest.Options{Pending: true}, "FINAL_CUSTOMER")
	inactive, _ := pgtest.AccountWith(ctx, pool, tenant, "inactive@example.com", pgtest.ValidHash, pgtest.Options{Inactive: true}, "FINAL_CUSTOMER")
	staff := pgtest.MustAccount(t, pool, tenant, "staff@example.com", "FINAL_CUSTOMER", "MANAGER")
	other := pgtest.MustAccount(t, pool, "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b", "other@example.com", "FINAL_CUSTOMER")
	for name, id := range map[string]string{"pending": pending, "inactive": inactive, "already staff": staff, "another tenant": other} {
		if _, err := registry.AddRole(ctx, added(id, "OPERATIONAL_COLLABORATOR"), userScope, "key-"+name+"-abcd"); !errors.Is(err, port.ErrEmailTaken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.membership_role WHERE role = 'OPERATIONAL_COLLABORATOR'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a role was added: %d %v", n, err)
	}
	if rows(t, pool, "idempotency_key") != 0 {
		t.Fatal("a refusal remembered its key")
	}
}

func TestI_AnOptionalRoleTheTenantHasNotEnabledIsRefused(t *testing.T) {
	registry, pool := registrySetup(t)
	id := pgtest.MustAccount(t, pool, tenant, "luis@example.com", "FINAL_CUSTOMER")
	if _, err := registry.AddRole(ctx, added(id, "ANALYST"), userScope, "key-0001-abcd"); !errors.Is(err, port.ErrRoleNotEnabled) {
		t.Fatalf("%v", err)
	}
}

// Two requests with different keys for one customer never leave two internal roles on the account: the second finds it staff already.
func TestI_TwoRolesAtOnceForOneCustomerLeaveOneAndTheLoserIsRefused(t *testing.T) {
	registry, pool := registrySetup(t)
	for round := 0; round < 15; round++ {
		id := pgtest.MustAccount(t, pool, tenant, "luis"+string(rune('a'+round))+"@example.com", "FINAL_CUSTOMER")
		roles := []string{"OPERATIONAL_COLLABORATOR", "TENANT_ADMINISTRATOR"}
		errs := make(chan error, 2)
		for i, role := range roles {
			go func() {
				_, err := registry.AddRole(ctx, added(id, role), userScope, "key-"+string(rune('a'+round))+string(rune('0'+i))+"-abcd")
				errs <- err
			}()
		}
		var won, lost int
		for range roles {
			if err := <-errs; err == nil {
				won++
			} else if errors.Is(err, port.ErrEmailTaken) {
				lost++
			} else {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		var held int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.membership_role r JOIN security.membership m USING (membership_id)
			WHERE m.identity_id = $1::uuid AND r.role <> 'FINAL_CUSTOMER'`, id).Scan(&held); err != nil {
			t.Fatal(err)
		}
		if won != 1 || lost != 1 || held != 1 {
			t.Fatalf("round %d: won %d lost %d internal roles held %d", round, won, lost, held)
		}
	}
}
