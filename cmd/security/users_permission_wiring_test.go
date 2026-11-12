package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// End to end against PostgreSQL, through HTTP: an Administrator assigns and removes a special permission (HU-SEC-006, AC3, AC4, AC7 and
// AC8, RN-SEC-005-01 to -10 and -16). Every answer is validated against the tested contract.

func (s *stack) changePermission(t *testing.T, token, id, action, permission string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"permission": permission})
	req := httptest.NewRequest(http.MethodPost, usersURL+"/"+id+"/permission-"+action, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-permission")
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

func (s *stack) permissionEvents(t *testing.T, id, eventType string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = $2`, id, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestC_AssigningAPermissionCutsNoSessionAndRemovingItCutsEveryOneOfTheUser(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	adminID := s.idOf(t, "admin@example.com")
	colabID := s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	session := s.signedIn(t, "colab@example.com")

	rec, out := s.changePermission(t, admin, colabID, "grant", "MANAGE_CASH")
	if rec.Code != http.StatusOK || out["accountId"] != colabID || strings.Contains(strings.ToLower(rec.Body.String()), "hash") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var by string
	if err := s.pool.QueryRow(ctx, `SELECT p.granted_by FROM security.membership_permission p JOIN security.membership m USING (membership_id) WHERE m.identity_id = $1::uuid`, colabID).
		Scan(&by); err != nil || by != "tenant-administrator/"+adminID {
		t.Fatalf("who granted it: %s %v", by, err)
	}
	if next := s.refresh(session.RefreshToken); next.Code != http.StatusOK {
		t.Fatalf("an assignment must not cut the sessions of the user: %d %s", next.Code, next.Body)
	}

	if n := s.permissionEvents(t, colabID, "SpecialPermissionGranted"); n != 1 {
		t.Fatalf("the assignment wrote %d events", n)
	}
	// a repeat is the same 200 with nothing new
	if rec, _ := s.changePermission(t, admin, colabID, "grant", "MANAGE_CASH"); rec.Code != http.StatusOK || s.permissionEvents(t, colabID, "SpecialPermissionGranted") != 1 {
		t.Fatalf("a repeat of the assignment: %d", rec.Code)
	}

	session = s.signedIn(t, "colab@example.com")
	if rec, _ := s.changePermission(t, admin, colabID, "removal", "MANAGE_CASH"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.refresh(session.RefreshToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after the removal the session of the user cannot renew: %d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "colab@example.com", password); rec.Code != http.StatusOK {
		t.Fatalf("the user signs in again after the removal: %d %s", rec.Code, rec.Body)
	}
	var actor, reason string
	if err := s.pool.QueryRow(ctx, `SELECT actor_id::text, reason FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = 'AccountSessionsRevoked'`, colabID).
		Scan(&actor, &reason); err != nil || actor != adminID || !strings.Contains(reason, "MANAGE_CASH") {
		t.Fatalf("AccountSessionsRevoked: actor=%s reason=%q %v", actor, reason, err)
	}
	if s.permissionEvents(t, colabID, "SpecialPermissionRevoked") != 1 {
		t.Fatal("the removal wrote no SpecialPermissionRevoked")
	}

	// removing again, or removing what the user never held, is the same 200 and cuts nothing more
	fresh := s.signedIn(t, "colab@example.com")
	for _, p := range []string{"MANAGE_CASH", "VALIDATE_PAYMENT_PROOFS"} {
		if rec, _ := s.changePermission(t, admin, colabID, "removal", p); rec.Code != http.StatusOK {
			t.Fatalf("removing %s again: %d %s", p, rec.Code, rec.Body)
		}
	}
	if rec := s.refresh(fresh.RefreshToken); rec.Code != http.StatusOK {
		t.Fatalf("a removal that changes nothing must not cut the sessions: %d %s", rec.Code, rec.Body)
	}
	if a, b := s.permissionEvents(t, colabID, "SpecialPermissionRevoked"), s.permissionEvents(t, colabID, "AccountSessionsRevoked"); a != 1 || b != 1 {
		t.Fatalf("a removal that changes nothing wrote events: %d and %d", a, b)
	}
}

func TestC_AnAdministratorAssignsSensitiveDataToThemselvesButNeverTheirProfilePermissions(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	adminID := s.idOf(t, "admin@example.com")
	if rec, _ := s.changePermission(t, admin, adminID, "grant", "CONSULT_SENSITIVE_DATA"); rec.Code != http.StatusOK {
		t.Fatalf("an administrator assigns sensitive data to themselves: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"VALIDATE_PAYMENT_PROOFS", "MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION"} {
		for _, action := range []string{"grant", "removal"} {
			if rec, out := s.changePermission(t, admin, adminID, action, p); rec.Code != http.StatusUnprocessableEntity || out["error"] != "BUSINESS_RULE_VIOLATION" {
				t.Errorf("%s of the profile permission %s: %d %s", action, p, rec.Code, rec.Body)
			}
		}
	}
}

func TestC_AnOptionalRoleACustomerAndAnotherTenantsUserNeverReceiveAPermission(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	manager := s.account(t, tenantA, "manager@example.com", pgtest.Options{}, "MANAGER")
	customer := s.account(t, tenantA, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	other := s.account(t, tenantB, "otro@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	for _, p := range []string{"VALIDATE_PAYMENT_PROOFS", "MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "CONSULT_SENSITIVE_DATA"} {
		if rec, _ := s.changePermission(t, admin, manager, "grant", p); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("a manager received %s: %d %s", p, rec.Code, rec.Body)
		}
	}
	for name, id := range map[string]string{"a customer": customer, "a user of another tenant": other, "an id that does not exist": "11111111-2222-4333-8444-555555555555"} {
		if rec, _ := s.changePermission(t, admin, id, "grant", "MANAGE_CASH"); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	var rows int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.membership_permission`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("a refusal wrote %d rows (%v)", rows, err)
	}
}

func TestC_APermissionOutsideTheFourIsA400ThatNeverRepeatsItAndNoRouteCreatesOne(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	colab := s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	for _, p := range []string{"SUPERUSER", "", "manage_cash", "Gestionar caja", "MANAGE_DEPARTURES", "CUSTOM_PERMISSION"} {
		rec, out := s.changePermission(t, admin, colab, "grant", p)
		if rec.Code != http.StatusBadRequest || out["error"] != "VALIDATION_ERROR" || !strings.Contains(rec.Body.String(), `"field":"permission"`) ||
			(p != "" && strings.Contains(rec.Body.String(), p)) {
			t.Errorf("%q: %d %s", p, rec.Code, rec.Body)
		}
	}
	if rec, _ := s.changePermission(t, admin, "not-an-id", "grant", "MANAGE_CASH"); rec.Code != http.StatusBadRequest {
		t.Errorf("a path that is not an id: %d", rec.Code)
	}
}

func TestC_OnlyAnAdministratorChangesPermissions(t *testing.T) {
	s := newStack(t)
	colab := s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	token := s.claimsOf(t, "colab@example.com")
	if rec, _ := s.changePermission(t, token, colab, "grant", "MANAGE_CASH"); rec.Code != http.StatusForbidden {
		t.Fatalf("a collaborator assigning to themselves: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.changePermission(t, "", colab, "grant", "MANAGE_CASH"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
}

func (s *stack) claimsOf(t *testing.T, email string) string {
	t.Helper()
	a, _ := s.claims(t, s.signIn(tenantURL, email, password))
	return a.AccessToken
}

// HU-SEC-006, RN-SEC-005-08: the list shows the permissions that each user holds, through the real stack.
func TestC_TheListShowsTheThreeOfTheAdministratorWhatWasAssignedAndNothingAfterARemoval(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	colabID := s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	s.account(t, tenantA, "manager@example.com", pgtest.Options{}, "MANAGER")
	held := func() map[string][]string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, usersURL, nil)
		req.Header.Set("Authorization", "Bearer "+admin)
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		validateAgainstContract(t, req, rec)
		var page struct {
			Data []struct {
				Email       string   `json:"email"`
				Permissions []string `json:"permissions"`
			}
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		out := map[string][]string{}
		for _, u := range page.Data {
			out[u.Email] = u.Permissions
		}
		return out
	}
	got := held()
	if len(got["admin@example.com"]) != 3 || len(got["colab@example.com"]) != 0 || got["manager@example.com"] == nil || len(got["manager@example.com"]) != 0 {
		t.Fatalf("before: %v", got)
	}
	if rec, _ := s.changePermission(t, admin, colabID, "grant", "CONSULT_SENSITIVE_DATA"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"permissions":["CONSULT_SENSITIVE_DATA"]`) {
		t.Fatalf("the answer of the assignment shows the permissions: %d %s", rec.Code, rec.Body)
	}
	if got := held(); len(got["colab@example.com"]) != 1 || got["colab@example.com"][0] != "CONSULT_SENSITIVE_DATA" {
		t.Fatalf("after the assignment: %v", got)
	}
	if rec, _ := s.changePermission(t, admin, colabID, "removal", "CONSULT_SENSITIVE_DATA"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"permissions":[]`) {
		t.Fatalf("the answer of the removal shows none: %d %s", rec.Code, rec.Body)
	}
	if got := held(); len(got["colab@example.com"]) != 0 {
		t.Fatalf("after the removal: %v", got)
	}
}
