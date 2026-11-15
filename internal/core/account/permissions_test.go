package account_test

import (
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

// HU-SEC-006, RN-SEC-005-02 to -06: the four special permissions and who may hold each (spec 005, plan D-01 and D-02).

var fourPermissions = []string{"VALIDATE_PAYMENT_PROOFS", "MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "CONSULT_SENSITIVE_DATA"}

func TestD_OnlyTheFourSpecialPermissionsExistAndTheListIsACopyNobodyCanChange(t *testing.T) {
	if got := account.SpecialPermissions(); !slices.Equal(got, fourPermissions) {
		t.Fatalf("%v", got)
	}
	first := account.SpecialPermissions()
	first[0] = "SUPERUSER"
	if account.SpecialPermissions()[0] != "VALIDATE_PAYMENT_PROOFS" {
		t.Fatal("a caller changed the permissions of everyone")
	}
	for _, p := range fourPermissions {
		if !account.IsSpecialPermission(p) {
			t.Errorf("%s is one of the four", p)
		}
	}
	for _, p := range []string{"", "SUPERUSER", "manage_cash", "MANAGE_CASH ", "Gestionar caja", "MANAGE_DEPARTURES", "CUSTOM_PERMISSION"} {
		if account.IsSpecialPermission(p) {
			t.Errorf("%q is not a special permission", p)
		}
	}
}

func TestD_TheLiteralsAreTheOnesTheOtherServicesRead(t *testing.T) {
	if account.PermissionValidateProofs != "VALIDATE_PAYMENT_PROOFS" || account.PermissionConsultSensitiveData != "CONSULT_SENSITIVE_DATA" ||
		account.PermissionManageCash != "MANAGE_CASH" || account.PermissionManageDepartureExecution != "MANAGE_DEPARTURE_EXECUTION" {
		t.Fatal("the commercial service compares the first and the last as they are")
	}
}

func TestD_ATenantAdministratorHoldsTheThreeProfilePermissionsAndNobodyElseHoldsAny(t *testing.T) {
	want := []string{"MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "VALIDATE_PAYMENT_PROOFS"}
	if got := account.ProfilePermissions([]string{account.RoleTenantAdministrator}); !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	for _, roles := range [][]string{nil, {}, {"OPERATIONAL_COLLABORATOR"}, {"MANAGER"}, {"ACCOUNTANT"}, {"ANALYST"}, {"FINAL_CUSTOMER"}, {account.RolePlatformAdministrator}} {
		if got := account.ProfilePermissions(roles); len(got) != 0 {
			t.Errorf("%v holds %v by profile", roles, got)
		}
	}
}

// every cell of the table of plan D-02
func TestD_EachRoleMayReceiveExactlyTheCellsOfTheTable(t *testing.T) {
	assignable := map[string][]string{
		"TENANT_ADMINISTRATOR":     {"CONSULT_SENSITIVE_DATA"},
		"OPERATIONAL_COLLABORATOR": fourPermissions,
		"MANAGER":                  nil,
		"ACCOUNTANT":               nil,
		"ANALYST":                  nil,
		"FINAL_CUSTOMER":           nil,
		"PLATFORM_ADMINISTRATOR":   nil,
		"":                         nil,
		"SUPERUSER":                nil,
	}
	for role, allowed := range assignable {
		for _, p := range fourPermissions {
			if got := account.Assignable(role, p); got != slices.Contains(allowed, p) {
				t.Errorf("Assignable(%q, %s) = %v", role, p, got)
			}
		}
		if account.Assignable(role, "SUPERUSER") || account.Assignable(role, "") {
			t.Errorf("%q may receive a permission outside the four", role)
		}
	}
}

func TestD_APermissionOfTheProfileIsNeverAssignedToTheAdministrator(t *testing.T) {
	for _, p := range account.ProfilePermissions([]string{account.RoleTenantAdministrator}) {
		if account.Assignable(account.RoleTenantAdministrator, p) {
			t.Errorf("%s is the Administrator's by profile: it is neither assigned nor removed", p)
		}
	}
}

func TestD_TheEffectivePermissionsAreTheProfileAndTheAssignedOnesSortedWithoutRepeats(t *testing.T) {
	admin := []string{account.RoleTenantAdministrator}
	cases := []struct {
		name     string
		roles    []string
		assigned []string
		want     []string
	}{
		{"an administrator with nothing assigned", admin, nil, []string{"MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "VALIDATE_PAYMENT_PROOFS"}},
		{"an administrator who assigned sensitive data to themselves", admin, []string{"CONSULT_SENSITIVE_DATA"}, fourPermissionsSorted()},
		{"a collaborator with two", []string{"OPERATIONAL_COLLABORATOR"}, []string{"MANAGE_CASH", "CONSULT_SENSITIVE_DATA"}, []string{"CONSULT_SENSITIVE_DATA", "MANAGE_CASH"}},
		{"a collaborator with none", []string{"OPERATIONAL_COLLABORATOR"}, nil, []string{}},
		{"repeats are one", []string{"OPERATIONAL_COLLABORATOR"}, []string{"MANAGE_CASH", "MANAGE_CASH"}, []string{"MANAGE_CASH"}},
		{"a profile permission also assigned is one", admin, []string{"MANAGE_CASH"}, []string{"MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "VALIDATE_PAYMENT_PROOFS"}},
		{"a permission outside the four is ignored", []string{"OPERATIONAL_COLLABORATOR"}, []string{"SUPERUSER", "MANAGE_CASH"}, []string{"MANAGE_CASH"}},
		{"a manager holds none though one was written", []string{"MANAGER"}, []string{"MANAGE_CASH", "CONSULT_SENSITIVE_DATA"}, []string{}},
		{"an accountant holds none", []string{"ACCOUNTANT"}, []string{"VALIDATE_PAYMENT_PROOFS"}, []string{}},
		{"an analyst holds none", []string{"ANALYST"}, []string{"CONSULT_SENSITIVE_DATA"}, []string{}},
		{"a customer holds none", []string{"FINAL_CUSTOMER"}, []string{"MANAGE_CASH"}, []string{}},
		{"the platform holds none", []string{account.RolePlatformAdministrator}, []string{"MANAGE_CASH"}, []string{}},
		{"no role holds none", nil, []string{"MANAGE_CASH"}, []string{}},
		{"a customer who is also a collaborator holds what the collaborator may", []string{"FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR"}, []string{"MANAGE_CASH"}, []string{"MANAGE_CASH"}},
		{"a customer who is also a manager holds none", []string{"FINAL_CUSTOMER", "MANAGER"}, []string{"MANAGE_CASH"}, []string{}},
	}
	for _, c := range cases {
		got := account.PermissionsFor(c.roles, c.assigned)
		if got == nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v (never nil, so that the claim is [] and not null)", c.name, got, c.want)
		}
	}
}

func TestD_TheInputOfTheEffectivePermissionsIsNeverChanged(t *testing.T) {
	assigned := []string{"MANAGE_CASH", "CONSULT_SENSITIVE_DATA"}
	account.PermissionsFor([]string{"OPERATIONAL_COLLABORATOR"}, assigned)
	if !slices.Equal(assigned, []string{"MANAGE_CASH", "CONSULT_SENSITIVE_DATA"}) {
		t.Fatalf("the caller's list was sorted in place: %v", assigned)
	}
}

func TestD_TheOptionalRolesAreTheThreeAndOnlyThoseAreOptional(t *testing.T) {
	if got := account.OptionalRoles(); !slices.Equal(got, []string{"MANAGER", "ACCOUNTANT", "ANALYST"}) {
		t.Fatalf("%v", got)
	}
	first := account.OptionalRoles()
	first[0] = "SUPERUSER"
	if account.OptionalRoles()[0] != "MANAGER" {
		t.Fatal("a caller changed the optional roles of everyone")
	}
	for _, r := range []string{"MANAGER", "ACCOUNTANT", "ANALYST"} {
		if !account.IsOptionalRole(r) {
			t.Errorf("%s is optional", r)
		}
	}
	for _, r := range []string{"", "TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "FINAL_CUSTOMER", "PLATFORM_ADMINISTRATOR", "manager", "MANAGER "} {
		if account.IsOptionalRole(r) {
			t.Errorf("%q is not optional", r)
		}
	}
}

func TestD_EveryOptionalRoleIsAnInternalRoleAndNoneIsTheAdministratorOrTheCollaborator(t *testing.T) {
	for _, r := range account.OptionalRoles() {
		if !account.IsInternalRole(r) || r == account.RoleTenantAdministrator || r == account.RoleOperationalCollaborator {
			t.Errorf("%s must be an internal role that a tenant may enable or not", r)
		}
	}
}

func fourPermissionsSorted() []string {
	s := slices.Clone(fourPermissions)
	slices.Sort(s)
	return s
}
