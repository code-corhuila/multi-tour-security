package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// End to end against PostgreSQL, through HTTP: an administrator gives a user a new temporary credential (HU-SEC-005, AC7,
// RN-SEC-003-14 and -15). Every answer is validated against the tested contract.

const newTemporary = "Nueva-Temporal-26!"

func (s *stack) issueCredential(t *testing.T, token, id, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, usersURL+"/"+id+"/temporary-credential", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-credential")
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

func credential(password, confirmation string) string {
	body, _ := json.Marshal(map[string]string{"password": password, "passwordConfirmation": confirmation})
	return string(body)
}

// expired is a temporary credential that ran out before the first sign-in; its password is the one of every test account.
var expired = pgtest.Options{TemporaryUntil: time.Now().Add(-time.Hour)}

func (s *stack) platformToken(t *testing.T) string {
	t.Helper()
	s.account(t, "", "root@example.com", pgtest.Options{}, "PLATFORM_ADMINISTRATOR")
	a, claims := s.claims(t, s.signIn(rootURL, "root@example.com", password))
	if _, restricted := claims["access"]; restricted {
		t.Fatalf("the platform administrator signs in normally: %v", claims)
	}
	return a.AccessToken
}

func (s *stack) madeByAService(t *testing.T, id string) {
	t.Helper()
	if _, err := s.pool.Exec(ctx, `UPDATE security.membership SET created_by = 'service/workflow-onboard-tenant' WHERE identity_id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
}

func TestC_ANewCredentialReplacesTheExpiredOneLastsSeventyTwoHoursAndOnlyAllowsChoosingAPassword(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	adminID := s.idOf(t, "admin@example.com")
	userID := s.account(t, tenantA, "luis@example.com", expired, "MANAGER")
	if rec := s.signIn(tenantURL, "luis@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an expired credential must not sign in: %d %s", rec.Code, rec.Body)
	}

	rec, out := s.issueCredential(t, admin, userID, credential(newTemporary, newTemporary))
	until, _ := time.Parse(time.RFC3339, out["temporaryCredentialUntil"].(string))
	if rec.Code != http.StatusOK || out["accountId"] != userID || time.Until(until) < 71*time.Hour || time.Until(until) > 73*time.Hour ||
		strings.Contains(rec.Body.String(), newTemporary) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "luis@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the earlier credential still works: %d %s", rec.Code, rec.Body)
	}
	a, claims := s.claims(t, s.signIn(tenantURL, "luis@example.com", newTemporary))
	if claims["access"] != "password-change" {
		t.Fatalf("the new credential only allows choosing a password: %v", claims)
	}
	if rec := s.changePassword(a.AccessToken, chosen); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if _, claims := s.claims(t, s.signIn(tenantURL, "luis@example.com", chosen)); claims["access"] != nil {
		t.Fatalf("after choosing a password the access is ordinary: %v", claims)
	}

	var by, actor, payload string
	if err := s.pool.QueryRow(ctx, `SELECT i.temporary_issued_by, e.actor_id::text, e.payload::text FROM security.identity i
		JOIN security.outbox_event e ON e.aggregate_id = i.identity_id AND e.event_type = 'AccountTemporaryCredentialIssued'
		WHERE i.identity_id = $1::uuid`, userID).Scan(&by, &actor, &payload); err != nil || by != "tenant-administrator/"+adminID || actor != adminID ||
		!strings.Contains(payload, "TENANT_ADMINISTRATOR") || strings.Contains(payload, newTemporary) {
		t.Fatalf("trace by=%s actor=%s payload=%s %v", by, actor, payload, err)
	}
}

func TestC_ThePlatformAdministratorIssuesToTheFirstAdministratorAndATenantAdministratorCannot(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	platform := s.platformToken(t)
	firstID := s.account(t, tenantA, "first@example.com", expired, "TENANT_ADMINISTRATOR")
	s.madeByAService(t, firstID)

	if rec, out := s.issueCredential(t, admin, firstID, credential(newTemporary, newTemporary)); rec.Code != http.StatusUnprocessableEntity || out["error"] != "BUSINESS_RULE_VIOLATION" {
		t.Fatalf("a tenant administrator issued to the first administrator: %d %s", rec.Code, rec.Body)
	}
	if rec, out := s.issueCredential(t, platform, firstID, credential(newTemporary, newTemporary)); rec.Code != http.StatusOK || out["tenantId"] != tenantA {
		t.Fatalf("the platform administrator was refused: %d %s", rec.Code, rec.Body)
	}
	var tenantOfEvent string
	if err := s.pool.QueryRow(ctx, `SELECT tenant_id::text FROM security.outbox_event WHERE aggregate_id = $1::uuid AND event_type = 'AccountTemporaryCredentialIssued'`, firstID).
		Scan(&tenantOfEvent); err != nil || tenantOfEvent != tenantA {
		t.Fatalf("the event of the platform administrator must name the tenant of the user: %s %v", tenantOfEvent, err)
	}
	if _, claims := s.claims(t, s.signIn(tenantURL, "first@example.com", newTemporary)); claims["access"] != "password-change" {
		t.Fatalf("%v", claims)
	}
}

func TestC_ThePlatformAdministratorReachesOtherAdministratorsOnlyWhenNoneCanSignIn(t *testing.T) {
	s := newStack(t)
	platform := s.platformToken(t)
	locked := s.account(t, tenantA, "locked@example.com", expired, "TENANT_ADMINISTRATOR")
	collaborator := s.account(t, tenantA, "colab@example.com", expired, "OPERATIONAL_COLLABORATOR")
	able := s.account(t, tenantA, "able@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")

	if rec, _ := s.issueCredential(t, platform, locked, credential(newTemporary, newTemporary)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("with an administrator able to sign in the platform issues only to the first: %d %s", rec.Code, rec.Body)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, able); err != nil {
		t.Fatal(err)
	}
	if rec, _ := s.issueCredential(t, platform, collaborator, credential(newTemporary, newTemporary)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("the platform never issues to a collaborator: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.issueCredential(t, platform, locked, credential(newTemporary, newTemporary)); rec.Code != http.StatusOK {
		t.Fatalf("with no administrator able to sign in the platform issues to any active one: %d %s", rec.Code, rec.Body)
	}
}

func TestC_ARefusedIssueWritesNothingAndTheFieldsAreChecked(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	userID := s.account(t, tenantA, "luis@example.com", expired, "MANAGER")
	own := s.account(t, tenantA, "own@example.com", pgtest.Options{}, "MANAGER")
	other := s.account(t, tenantB, "otro@example.com", expired, "MANAGER")
	customer := s.account(t, tenantA, "customer@example.com", expired, "FINAL_CUSTOMER")
	missing := "11111111-2222-4333-8444-555555555555"

	for name, c := range map[string]struct {
		id, body string
		want     int
	}{
		"a user who chose their password": {own, credential(newTemporary, newTemporary), http.StatusUnprocessableEntity},
		"a user of another tenant":        {other, credential(newTemporary, newTemporary), http.StatusNotFound},
		"a customer":                      {customer, credential(newTemporary, newTemporary), http.StatusNotFound},
		"no user":                         {missing, credential(newTemporary, newTemporary), http.StatusNotFound},
		"an id that is not an id":         {"not-an-id", credential(newTemporary, newTemporary), http.StatusBadRequest},
		"a weak password":                 {userID, credential("weak", "weak"), http.StatusBadRequest},
		"a confirmation that differs":     {userID, credential(newTemporary, newTemporary+"x"), http.StatusBadRequest},
		"a field of the contract only":    {userID, `{"password":"` + newTemporary + `","passwordConfirmation":"` + newTemporary + `","tenantId":"` + tenantB + `"}`, http.StatusBadRequest},
	} {
		if rec, _ := s.issueCredential(t, admin, c.id, c.body); rec.Code != c.want {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	var events, touched int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountTemporaryCredentialIssued'`).Scan(&events); err != nil || events != 0 {
		t.Fatalf("a refusal wrote %d events (%v)", events, err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.identity WHERE temporary_issued_at IS NOT NULL`).Scan(&touched); err != nil || touched != 0 {
		t.Fatalf("a refusal left a trace on %d accounts (%v)", touched, err)
	}
	s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	colab, _ := s.claims(t, s.signIn(tenantURL, "colab@example.com", password))
	if rec, _ := s.issueCredential(t, colab.AccessToken, userID, credential(newTemporary, newTemporary)); rec.Code != http.StatusForbidden {
		t.Fatalf("a collaborator: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := s.issueCredential(t, "", userID, credential(newTemporary, newTemporary)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
}

// RN-SEC-003-14 "it invalidates any earlier one": here the earlier credential still works until the new one is issued
func TestC_ACredentialStillInForceStopsWorkingTheMomentANewOneIsIssued(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	userID := s.account(t, tenantA, "luis@example.com", pgtest.Options{TemporaryUntil: time.Now().Add(time.Hour)}, "MANAGER")
	if _, claims := s.claims(t, s.signIn(tenantURL, "luis@example.com", password)); claims["access"] != "password-change" {
		t.Fatalf("the earlier credential works before: %v", claims)
	}
	if rec, _ := s.issueCredential(t, admin, userID, credential(newTemporary, newTemporary)); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "luis@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the earlier credential still works after the new one: %d %s", rec.Code, rec.Body)
	}
	if _, claims := s.claims(t, s.signIn(tenantURL, "luis@example.com", newTemporary)); claims["access"] != "password-change" {
		t.Fatalf("%v", claims)
	}
}

// the schema documents 8 to 72 and the policy explains: a password at the edge reaches the policy and is told why
func TestC_APasswordAtTheEdgeOfThePolicyIsToldWhyAndNotRefusedByTheSchema(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	userID := s.account(t, tenantA, "luis@example.com", expired, "MANAGER")
	for name, pw := range map[string]string{"seven characters": "Aa1!xyz", "over 72 bytes": "Aa1!" + strings.Repeat("x", 70)} {
		rec, out := s.issueCredential(t, admin, userID, credential(pw, pw))
		if rec.Code != http.StatusBadRequest || out["error"] != "VALIDATION_ERROR" || !strings.Contains(rec.Body.String(), `"field":"password"`) || strings.Contains(rec.Body.String(), pw) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}
