package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// End to end against PostgreSQL, through HTTP: an Administrator sees, enables and disables the optional roles of their tenant (HU-SEC-006,
// AC5 and AC8, RN-SEC-005-02 and -12 to -14). Every answer is validated against the tested contract.

const rolesURL = "/api/v1/security/optional-roles"

func (s *stack) optionalRoles(t *testing.T, token, method, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, rolesURL+path, nil)
	req.Header.Set("X-Correlation-Id", "e2e-roles")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	validateAgainstContract(t, req, rec)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (s *stack) enabledRoles(t *testing.T, token string) []string {
	t.Helper()
	rec, out := s.optionalRoles(t, token, http.MethodGet, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var on []string
	data, _ := out["data"].([]any)
	if len(data) != 3 {
		t.Fatalf("the list is always the three: %s", rec.Body)
	}
	for _, d := range data {
		if role, _ := d.(map[string]any); role["enabled"] == true {
			on = append(on, role["role"].(string))
		}
	}
	return on
}

func TestC_ATenantStartsWithNoOptionalRoleAndItsAdministratorEnablesAndDisablesThem(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	adminID := s.idOf(t, "admin@example.com")
	if on := s.enabledRoles(t, admin); len(on) != 0 {
		t.Fatalf("a new tenant has %v enabled", on)
	}
	rec, out := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/enablement")
	if rec.Code != http.StatusOK || out["role"] != "MANAGER" || out["enabled"] != true || out["changedBy"] != "tenant-administrator/"+adminID || out["changedAt"] == nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if on := s.enabledRoles(t, admin); len(on) != 1 || on[0] != "MANAGER" {
		t.Fatalf("after enabling: %v", on)
	}
	if rec, out := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/enablement"); rec.Code != http.StatusUnprocessableEntity || out["error"] != "INVALID_STATUS_TRANSITION" {
		t.Fatalf("enabling twice: %d %s", rec.Code, rec.Body)
	}
	var events int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = 'OptionalRoleEnabled'`, tenantA).Scan(&events); err != nil || events != 1 {
		t.Fatalf("one enabling wrote %d events (%v)", events, err)
	}
	if rec, out := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/disablement"); rec.Code != http.StatusOK || out["enabled"] != false {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec, out := s.optionalRoles(t, admin, http.MethodPost, "/ANALYST/disablement"); rec.Code != http.StatusUnprocessableEntity || out["error"] != "INVALID_STATUS_TRANSITION" {
		t.Fatalf("disabling a role never enabled: %d %s", rec.Code, rec.Body)
	}
}

func TestC_ARoleThatAnActiveUserHoldsCannotBeDisabledUntilThatUserIsInactive(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	managerID := s.account(t, tenantA, "manager@example.com", pgtest.Options{}, "MANAGER")
	if rec, _ := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/enablement"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec, out := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/disablement"); rec.Code != http.StatusUnprocessableEntity || out["error"] != "BUSINESS_RULE_VIOLATION" {
		t.Fatalf("an active manager holds the role: %d %s", rec.Code, rec.Body)
	}
	if on := s.enabledRoles(t, admin); len(on) != 1 {
		t.Fatalf("a refusal changed the role: %v", on)
	}
	if rec, _ := s.changeStatus(t, admin, managerID, "inactivation", why); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.optionalRoles(t, admin, http.MethodPost, "/MANAGER/disablement"); rec.Code != http.StatusOK {
		t.Fatalf("with only an inactive holder the role can be disabled: %d %s", rec.Code, rec.Body)
	}
}

func TestC_NoRouteCreatesARoleAndTheOptionalRolesOfAnotherTenantAreNeverSeenNorChanged(t *testing.T) {
	s := newStack(t)
	adminA := s.administrator(t, tenantA, "admin@example.com")
	adminB := s.administrator(t, tenantB, "admin@example.com")
	for _, role := range []string{"TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "FINAL_CUSTOMER", "PLATFORM_ADMINISTRATOR", "SUPERUSER", "manager"} {
		for _, action := range []string{"enablement", "disablement"} {
			rec, out := s.optionalRoles(t, adminA, http.MethodPost, "/"+role+"/"+action)
			if rec.Code != http.StatusBadRequest || out["error"] != "VALIDATION_ERROR" || !strings.Contains(rec.Body.String(), `"field":"role"`) {
				t.Errorf("%s %s: %d %s", action, role, rec.Code, rec.Body)
			}
			// the value of the path is never repeated, whatever it is
			if strings.Contains(rec.Body.String(), role) {
				t.Errorf("%s %s: the answer repeats the role: %s", action, role, rec.Body)
			}
		}
	}
	if rec, _ := s.optionalRoles(t, adminA, http.MethodPost, "/ACCOUNTANT/enablement"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if on := s.enabledRoles(t, adminB); len(on) != 0 {
		t.Fatalf("another tenant's roles are shown: %v", on)
	}
	// and the other way round: the same role in another tenant is its own setting
	if rec, _ := s.optionalRoles(t, adminB, http.MethodPost, "/ACCOUNTANT/enablement"); rec.Code != http.StatusOK {
		t.Fatalf("another tenant enables the same role: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.optionalRoles(t, adminB, http.MethodPost, "/ACCOUNTANT/disablement"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if on := s.enabledRoles(t, adminA); len(on) != 1 || on[0] != "ACCOUNTANT" {
		t.Fatalf("what another tenant did changed this tenant's roles: %v", on)
	}
}

func TestC_OnlyAnAdministratorSeesOrChangesTheOptionalRoles(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	colab := s.claimsOf(t, "colab@example.com")
	for _, route := range []struct{ method, path string }{{http.MethodGet, ""}, {http.MethodPost, "/MANAGER/enablement"}, {http.MethodPost, "/MANAGER/disablement"}} {
		if rec, _ := s.optionalRoles(t, colab, route.method, route.path); rec.Code != http.StatusForbidden {
			t.Errorf("a collaborator, %s %s: %d %s", route.method, route.path, rec.Code, rec.Body)
		}
		if rec, _ := s.optionalRoles(t, "", route.method, route.path); rec.Code != http.StatusUnauthorized {
			t.Errorf("no token, %s %s: %d", route.method, route.path, rec.Code)
		}
	}
}
