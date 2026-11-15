package account_test

import (
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

// The roles of the tenant's staff, written once (HU-SEC-005, RN-SEC-003-02).

func TestD_TheInternalRolesAreTheFiveOfTheTenantInAFixedOrder(t *testing.T) {
	want := []string{"TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "MANAGER", "ACCOUNTANT", "ANALYST"}
	if got := account.InternalRoles(); !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	if account.RoleTenantAdministrator != "TENANT_ADMINISTRATOR" || account.RolePlatformAdministrator != "PLATFORM_ADMINISTRATOR" {
		t.Fatal("the names of the two administrator roles")
	}
}

func TestD_TheAuthorOfAChangeNamesTheAdministratorRoleAndTheId(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	if got := account.By(account.RoleTenantAdministrator, id); got != "tenant-administrator/"+id {
		t.Fatalf("By(tenant administrator) = %q", got)
	}
	if got := account.By(account.RolePlatformAdministrator, id); got != "platform-administrator/"+id {
		t.Fatalf("By(platform administrator) = %q", got)
	}
}

func TestD_TheListOfInternalRolesIsACopyThatNobodyCanUseToChangeIt(t *testing.T) {
	first := account.InternalRoles()
	first[0] = "SUPERUSER"
	slices.Sort(first)
	if account.InternalRoles()[0] != "TENANT_ADMINISTRATOR" {
		t.Fatal("a caller changed the roles of everyone")
	}
}

func TestD_OnlyAnInternalRoleIsOne(t *testing.T) {
	for _, role := range account.InternalRoles() {
		if !account.IsInternalRole(role) {
			t.Errorf("%s is internal", role)
		}
	}
	for _, role := range []string{"", "FINAL_CUSTOMER", "PLATFORM_ADMINISTRATOR", "SERVICE", "manager", "MANAGER ", "SUPERUSER"} {
		if account.IsInternalRole(role) {
			t.Errorf("%q is not internal", role)
		}
	}
}
