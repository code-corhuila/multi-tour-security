package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// End to end against PostgreSQL, through HTTP: a Tenant Administrator inactivates and reactivates a user of their tenant
// (HU-SEC-005, AC4, AC5 and AC8, RN-SEC-003-09, -10 and -12). Every answer is validated against the tested contract.

func (s *stack) changeStatus(t *testing.T, token, id, action, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, usersURL+"/"+id+"/"+action, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-status")
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

const (
	why     = `{"reason":"Left the company"}`
	whyBack = `{"reason":"Back from leave"}`
)

func TestC_InactivatingCutsTheAccessAndTheSessionsAndReactivatingGivesAccessBackButNotTheOldSessions(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	adminID := s.idOf(t, "admin@example.com")
	userID := s.account(t, tenantA, "luis@example.com", pgtest.Options{}, "MANAGER")
	before := s.signedIn(t, "luis@example.com")

	rec, out := s.changeStatus(t, admin, userID, "inactivation", why)
	if rec.Code != http.StatusOK || out["accountStatus"] != "INACTIVE" || out["accountId"] != userID || out["statusReason"] != "Left the company" ||
		out["statusChangedBy"] != "tenant-administrator/"+adminID || out["statusChangedAt"] == nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "luis@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an inactive user signs in: %d %s", rec.Code, rec.Body)
	}
	if rec := s.refresh(before.RefreshToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session of an inactive user renews: %d %s", rec.Code, rec.Body)
	}
	var actor, reason string
	if err := s.pool.QueryRow(ctx, `SELECT actor_id::text, reason FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = 'AccountSessionsRevoked'`, userID).
		Scan(&actor, &reason); err != nil || actor != adminID || reason != "Left the company" {
		t.Fatalf("the revocation event: actor=%s reason=%s %v", actor, reason, err)
	}
	if _, page := s.listUsers(t, admin, "?status=INACTIVE"); page.Meta.Total != 1 || page.Data[0].Email != "luis@example.com" {
		t.Fatalf("the list does not show the inactive user: %+v", page)
	}

	rec, out = s.changeStatus(t, admin, userID, "reactivation", whyBack)
	if rec.Code != http.StatusOK || out["accountStatus"] != "ACTIVE" || out["accountId"] != userID || out["statusReason"] != "Back from leave" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "luis@example.com", password); rec.Code != http.StatusOK {
		t.Fatalf("a reactivated user does not sign in: %d %s", rec.Code, rec.Body)
	}
	if rec := s.refresh(before.RefreshToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the credentials issued before the inactivation must stay cut: %d %s", rec.Code, rec.Body)
	}
}

func TestC_AChangeThatCannotBeMadeOrIsNotValidIsRefusedAndAnotherTenantsUserIsNotFound(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	userID := s.account(t, tenantA, "luis@example.com", pgtest.Options{}, "MANAGER")
	otherID := s.account(t, tenantB, "otro@example.com", pgtest.Options{}, "MANAGER")
	customerID := s.account(t, tenantA, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER")

	if rec, _ := s.changeStatus(t, admin, userID, "reactivation", whyBack); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("reactivating an active user: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.changeStatus(t, admin, userID, "inactivation", why); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec, out := s.changeStatus(t, admin, userID, "inactivation", why); rec.Code != http.StatusUnprocessableEntity || out["error"] != "INVALID_STATUS_TRANSITION" {
		t.Fatalf("inactivating twice: %d %s", rec.Code, rec.Body)
	}
	for name, id := range map[string]string{"a user of another tenant": otherID, "a customer": customerID, "an id that does not exist": "11111111-2222-4333-8444-555555555555"} {
		if rec, _ := s.changeStatus(t, admin, id, "inactivation", why); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	for body, name := range map[string]string{`{"reason":""}`: "no reason", `{"reason":"   "}`: "only spaces", `{}`: "no field", `{"reason":"x","tenantId":"` + tenantB + `"}`: "a field that is not in the contract"} {
		if rec, _ := s.changeStatus(t, admin, otherID, "inactivation", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec, _ := s.changeStatus(t, admin, "not-an-id", "inactivation", why); rec.Code != http.StatusBadRequest {
		t.Errorf("a path that is not an id: %d %s", rec.Code, rec.Body)
	}
	var status string
	if err := s.pool.QueryRow(ctx, `SELECT identity_status FROM security.identity WHERE identity_id = $1::uuid`, otherID).Scan(&status); err != nil || status != "ACTIVE" {
		t.Fatalf("the user of the other tenant is %s (%v)", status, err)
	}
	s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	colab, _ := s.claims(t, s.signIn(tenantURL, "colab@example.com", password))
	if rec, _ := s.changeStatus(t, colab.AccessToken, userID, "reactivation", whyBack); rec.Code != http.StatusForbidden {
		t.Fatalf("a collaborator: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.changeStatus(t, "", userID, "reactivation", whyBack); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
}

func TestC_AUserInactivatedByHandStaysInactiveWhenTheTenantIsStoppedAndStartedAgain(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	userID := s.account(t, tenantA, "luis@example.com", pgtest.Options{}, "MANAGER")
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	before := s.signedIn(t, "luis@example.com")
	if rec, _ := s.changeStatus(t, admin, userID, "inactivation", why); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	tenants := postgres.NewTenants(s.pool)
	now := time.Now()
	for i, status := range []coretenant.Status{coretenant.Inactive, coretenant.Active} {
		if _, err := tenants.Apply(ctx, coretenant.Copy{TenantID: tenantA, Identifier: "travesia-natural", Status: status, OccurredAt: now.Add(time.Duration(i+1) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	if rec := s.signIn(tenantURL, "luis@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the user inactivated by hand signs in after the tenant came back: %d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "ana@example.com", password); rec.Code != http.StatusOK {
		t.Fatalf("the other users of the tenant must sign in again: %d %s", rec.Code, rec.Body)
	}
	if rec := s.refresh(before.RefreshToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the sessions of the user inactivated by hand must stay cut: %d %s", rec.Code, rec.Body)
	}
	// the tenant coming back touches nothing of the individual inactivation: its actor and reason are still the ones of the Administrator
	var by, reason, status string
	if err := s.pool.QueryRow(ctx, `SELECT identity_status, status_changed_by, status_reason FROM security.identity WHERE identity_id = $1::uuid`, userID).Scan(&status, &by, &reason); err != nil ||
		status != "INACTIVE" || by != "tenant-administrator/"+s.idOf(t, "admin@example.com") || reason != "Left the company" {
		t.Fatalf("the trace changed with the tenant: %s %s %s %v", status, by, reason, err)
	}
}

func (s *stack) idOf(t *testing.T, email string) string {
	t.Helper()
	var id string
	if err := s.pool.QueryRow(ctx, `SELECT identity_id::text FROM security.identity WHERE email_normalized = $1 AND tenant_id = $2::uuid`, email, tenantA).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// RN-SEC-003-11: the only Administrator cannot cut their own access, and a second one can be inactivated by the first.
func TestC_TheLastAdministratorCannotBeInactivatedByAnyoneNotEvenByThemselvesAndStillSignsIn(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	adminID := s.idOf(t, "admin@example.com")
	rec, out := s.changeStatus(t, admin, adminID, "inactivation", why)
	if rec.Code != http.StatusUnprocessableEntity || out["error"] != "BUSINESS_RULE_VIOLATION" {
		t.Fatalf("the only administrator inactivated themselves: %d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "admin@example.com", password); rec.Code != http.StatusOK {
		t.Fatalf("the administrator was locked out: %d %s", rec.Code, rec.Body)
	}
	second := s.account(t, tenantA, "second@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	if rec, _ := s.changeStatus(t, admin, second, "inactivation", why); rec.Code != http.StatusOK {
		t.Fatalf("with two administrators one can be inactivated: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.changeStatus(t, admin, adminID, "inactivation", why); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("the administrator is the last one again: %d %s", rec.Code, rec.Body)
	}
}
