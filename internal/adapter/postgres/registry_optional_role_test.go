package postgres_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-006, RN-SEC-005-12 and -13: the registration refuses an optional role that the tenant did not enable, inside its own transaction.

func internalAccount(email, role string) port.NewAccount {
	n := newAccount(email)
	n.Role, n.CreatedBy = role, "tenant-administrator/"+actorID
	return n
}

func TestI_ARoleThatIsOptionalAndNotEnabledIsRefusedAndWritesNothingWhileTheOthersNeedNoSwitch(t *testing.T) {
	registry, pool := registrySetup(t)
	roles := postgres.NewOptionalRoles(pool)
	for _, role := range []string{"MANAGER", "ACCOUNTANT", "ANALYST"} {
		if _, err := registry.Create(ctx, internalAccount(role+"@example.com", role), "user:"+tenant, "key-"+role+"-0001"); !errors.Is(err, port.ErrRoleNotEnabled) {
			t.Errorf("%s with nothing enabled: %v", role, err)
		}
	}
	if rows(t, pool, "identity") != 0 || rows(t, pool, "membership") != 0 || rows(t, pool, "idempotency_key") != 0 {
		t.Fatalf("a refusal wrote something: %d identities", rows(t, pool, "identity"))
	}
	// a collaborator, an administrator and a customer need no switch
	for i, role := range []string{"OPERATIONAL_COLLABORATOR", "TENANT_ADMINISTRATOR", "FINAL_CUSTOMER"} {
		if _, err := registry.Create(ctx, internalAccount(fmt.Sprintf("u%d@example.com", i), role), "user:"+tenant, fmt.Sprintf("key-other-%04d", i)); err != nil {
			t.Errorf("%s: %v", role, err)
		}
	}
	// and once the tenant enables the role it can register users with it, only that role, only that tenant
	if _, err := roles.Enable(ctx, roleChange(tenant, "MANAGER")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Create(ctx, internalAccount("boss@example.com", "MANAGER"), "user:"+tenant, "key-manager-0002"); err != nil {
		t.Fatalf("after enabling: %v", err)
	}
	if _, err := registry.Create(ctx, internalAccount("acc@example.com", "ACCOUNTANT"), "user:"+tenant, "key-accountant-0002"); !errors.Is(err, port.ErrRoleNotEnabled) {
		t.Fatalf("enabling one role enables no other: %v", err)
	}
	other := internalAccount("other@example.com", "MANAGER")
	other.TenantID = otherTenant
	if _, err := registry.Create(ctx, other, "user:"+otherTenant, "key-other-tenant"); !errors.Is(err, port.ErrRoleNotEnabled) {
		t.Fatalf("what a tenant enabled is not enabled for another: %v", err)
	}
}

// the day it matters: a registration and a disabling at once never leave an active user in a role that is disabled
func TestI_ARegistrationAndADisablingAtOnceNeverLeaveAnActiveHolderInADisabledRole(t *testing.T) {
	for round := 0; round < 25; round++ {
		registry, pool := registrySetup(t)
		roles := postgres.NewOptionalRoles(pool)
		if _, err := roles.Enable(ctx, roleChange(tenant, "MANAGER")); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		var registered, disabled error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, registered = registry.Create(ctx, internalAccount("boss@example.com", "MANAGER"), "user:"+tenant, "key-manager-0001")
		}()
		go func() {
			defer wg.Done()
			<-start
			_, disabled = roles.Disable(ctx, roleChange(tenant, "MANAGER"))
		}()
		close(start)
		wg.Wait()
		on := enabledRoles(t, roles, tenant)
		var active int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.identity i JOIN security.membership m USING (identity_id)
			JOIN security.membership_role r USING (membership_id) WHERE i.identity_status = 'ACTIVE' AND r.role = 'MANAGER'`).Scan(&active); err != nil {
			t.Fatal(err)
		}
		switch {
		case registered == nil && errors.Is(disabled, port.ErrRoleInUse) && len(on) == 1 && active == 1: // the registration won
		case disabled == nil && errors.Is(registered, port.ErrRoleNotEnabled) && len(on) == 0 && active == 0: // the disabling won
		default:
			t.Fatalf("round %d: registered=%v disabled=%v enabled=%v active managers=%d: an active manager must never hold a disabled role", round, registered, disabled, on, active)
		}
	}
}
