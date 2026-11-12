package main

import (
	"net/http"
	"strings"
	"testing"
)

// End to end against PostgreSQL, through HTTP: a tenant registers users with an optional role only after enabling it (HU-SEC-006, AC5,
// RN-SEC-005-12 and -13). Every answer is validated against the tested contract.

func TestC_RegisteringAManagerInATenantThatDidNotEnableTheRoleIs422AndAfterEnablingItIs201(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	before := s.accountCount(t)
	rec := s.registerUser(t, admin, "manager-key-0001", userFields("boss@example.com", "MANAGER"))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "BUSINESS_RULE_VIOLATION") || !strings.Contains(rec.Body.String(), "not enabled") ||
		strings.Contains(rec.Body.String(), "MANAGER") {
		t.Fatalf("a role the tenant did not enable: %d %s", rec.Code, rec.Body)
	}
	if got := s.accountCount(t); got != before {
		t.Fatalf("the refusal created %d accounts", got-before)
	}
	if rec, _ := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/enablement"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.registerUser(t, admin, "manager-key-0002", userFields("boss@example.com", "MANAGER")); rec.Code != http.StatusCreated {
		t.Fatalf("after enabling: %d %s", rec.Code, rec.Body)
	}
	if rec := s.registerUser(t, admin, "accountant-key-001", userFields("acc@example.com", "ACCOUNTANT")); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("enabling one role enables no other: %d %s", rec.Code, rec.Body)
	}
}

func TestC_ACollaboratorAndAnAdministratorNeedNoSwitchAndAnotherTenantsSwitchIsNotMine(t *testing.T) {
	s := newStack(t)
	adminA := s.administrator(t, tenantA, "admin@example.com")
	adminB := s.administrator(t, tenantB, "admin@example.com")
	for i, role := range []string{"OPERATIONAL_COLLABORATOR", "TENANT_ADMINISTRATOR"} {
		if rec := s.registerUser(t, adminA, "needs-no-switch-"+string(rune('a'+i))+"-001", userFields("u"+string(rune('a'+i))+"@example.com", role)); rec.Code != http.StatusCreated {
			t.Errorf("%s: %d %s", role, rec.Code, rec.Body)
		}
	}
	if rec, _ := s.optionalRoles(t, adminB, http.MethodPost, "/ANALYST/enablement"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.registerUser(t, adminA, "analyst-key-0001", userFields("an@example.com", "ANALYST")); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a role enabled by another tenant: %d %s", rec.Code, rec.Body)
	}
}

func TestC_ARepeatOfAKeyAnswersItsFirstUserEvenAfterTheRoleWasDisabled(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	if rec, _ := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/enablement"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	fields := userFields("boss@example.com", "MANAGER")
	first := s.registerUser(t, admin, "repeat-key-000001", fields)
	if first.Code != http.StatusCreated {
		t.Fatalf("%d %s", first.Code, first.Body)
	}
	// the manager is inactivated so that the role can be disabled; the key still answers the user that it made
	managerID := s.idOf(t, "boss@example.com")
	if rec, _ := s.changeStatus(t, admin, managerID, "inactivation", why); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/disablement"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	repeat := s.registerUser(t, admin, "repeat-key-000001", fields)
	if repeat.Code != http.StatusOK || repeat.Body.String() == "" {
		t.Fatalf("a repeat is the user already created, not a new refusal: %d %s", repeat.Code, repeat.Body)
	}
	if rec := s.registerUser(t, admin, "repeat-key-000002", userFields("other@example.com", "MANAGER")); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a new registration with the role disabled: %d %s", rec.Code, rec.Body)
	}
}
