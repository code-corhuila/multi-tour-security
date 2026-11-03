package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// End to end against PostgreSQL, through HTTP: a Tenant Administrator registers an internal user (HU-SEC-005,
// RN-SEC-003-01 to -06 and -08). Every answer is validated against the tested contract.

const (
	usersURL      = "/api/v1/security/users"
	temporaryPass = "Temporal-2026!"
)

// administrator is the access token of an active Tenant Administrator of tenant A, signed in the ordinary way.
func (s *stack) administrator(t *testing.T, tenantID, email string) string {
	t.Helper()
	s.account(t, tenantID, email, pgtest.Options{}, "TENANT_ADMINISTRATOR")
	url := tenantURL
	if tenantID == tenantB {
		url = otherURL
	}
	a, claims := s.claims(t, s.signIn(url, email, password))
	if _, restricted := claims["access"]; restricted {
		t.Fatalf("the administrator signs in normally: %v", claims)
	}
	return a.AccessToken
}

func userFields(email, role string) map[string]string {
	return map[string]string{"fullName": "Carlos Gómez", "email": email, "role": role, "password": temporaryPass, "passwordConfirmation": temporaryPass}
}

func (s *stack) registerUser(t *testing.T, token, key string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(fields)
	req := httptest.NewRequest(http.MethodPost, usersURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-usr")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	validateAgainstContract(t, req, rec)
	return rec
}

func (s *stack) countWhere(t *testing.T, where string, args ...any) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.identity i WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestC_AnAdministratorRegistersAUserWhoSignsInOnlyToChooseAPasswordAndThenHoldsTheirRoleAndNoOther(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	rec := s.registerUser(t, admin, "register-0000001", userFields(" Carlos.Gomez@Example.com ", "OPERATIONAL_COLLABORATOR"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var u map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &u); err != nil {
		t.Fatal(err)
	}
	until, _ := time.Parse(time.RFC3339, u["temporaryCredentialUntil"].(string))
	if u["tenantId"] != tenantA || u["email"] != "carlos.gomez@example.com" || u["accountStatus"] != "ACTIVE" || u["fullName"] != "Carlos Gómez" ||
		time.Until(until) < 71*time.Hour || time.Until(until) > 73*time.Hour {
		t.Fatalf("the user is %v", u)
	}
	if strings.Contains(rec.Body.String(), temporaryPass) || strings.Contains(strings.ToLower(rec.Body.String()), "hash") {
		t.Fatalf("the answer shows a secret: %s", rec.Body)
	}

	// the first sign-in only allows choosing a password
	_, first := s.claims(t, s.signIn(tenantURL, "carlos.gomez@example.com", temporaryPass))
	if first["access"] != "password-change" {
		t.Fatalf("the first sign-in is only to choose a password: %v", first)
	}
	a, _ := s.claims(t, s.signIn(tenantURL, "carlos.gomez@example.com", temporaryPass))
	if rec := s.changePassword(a.AccessToken, chosen); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	collaborator, claims := s.claims(t, s.signIn(tenantURL, "carlos.gomez@example.com", chosen))
	roles, _ := claims["roles"].([]any)
	if _, restricted := claims["access"]; restricted || len(roles) != 1 || roles[0] != "OPERATIONAL_COLLABORATOR" || claims["tenantId"] != tenantA {
		t.Fatalf("the user holds their role and no other: %v", claims)
	}

	// and a collaborator never manages users
	if rec := s.registerUser(t, collaborator.AccessToken, "register-0000002", userFields("otro@example.com", "ANALYST")); rec.Code != http.StatusForbidden {
		t.Fatalf("a collaborator registers a user: %d %s", rec.Code, rec.Body)
	}

	// who registered them is recorded with the account
	var createdBy string
	if err := s.pool.QueryRow(ctx, `SELECT m.created_by FROM security.membership m JOIN security.identity i USING (identity_id)
		WHERE i.email_normalized = 'carlos.gomez@example.com'`).Scan(&createdBy); err != nil || !strings.HasPrefix(createdBy, "tenant-administrator/") {
		t.Fatalf("created_by = %q %v", createdBy, err)
	}
}

func TestC_EachOfTheFiveRolesCanBeGivenAndAnythingElseIsRefusedWithNothingCreated(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	before := s.accountCount(t)
	for i, role := range []string{"TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "MANAGER", "ACCOUNTANT", "ANALYST"} {
		email := strings.ToLower(role) + "@example.com"
		if rec := s.registerUser(t, admin, "role-key-00000"+string(rune('1'+i)), userFields(email, role)); rec.Code != http.StatusCreated {
			t.Fatalf("%s: %d %s", role, rec.Code, rec.Body)
		}
		_, claims := s.claims(t, s.signIn(tenantURL, email, temporaryPass))
		if claims["access"] != "password-change" {
			t.Fatalf("%s: %v", role, claims)
		}
	}
	for _, role := range []string{"FINAL_CUSTOMER", "PLATFORM_ADMINISTRATOR", "SUPERUSER", ""} {
		if rec := s.registerUser(t, admin, "bad-role-key-01", userFields("x@example.com", role)); rec.Code != http.StatusBadRequest {
			t.Errorf("role %q: %d %s", role, rec.Code, rec.Body)
		}
	}
	if got := s.accountCount(t); got != before+5 {
		t.Fatalf("accounts = %d, want %d: a refusal created something", got, before+5)
	}
}

func TestC_TheTenantIsAlwaysTheCredentialsAndARepeatOfTheKeyCreatesNothingNew(t *testing.T) {
	s := newStack(t)
	adminA := s.administrator(t, tenantA, "admin@example.com")
	adminB := s.administrator(t, tenantB, "admin@example.com")
	fields := userFields("luis@example.com", "MANAGER")
	first := s.registerUser(t, adminA, "same-key-000001", fields)
	repeat := s.registerUser(t, adminA, "same-key-000001", fields)
	if first.Code != http.StatusCreated || repeat.Code != http.StatusOK || first.Body.String() != repeat.Body.String() {
		t.Fatalf("%d %d\n%s\n%s", first.Code, repeat.Code, first.Body, repeat.Body)
	}
	if n := s.countWhere(t, `i.email_normalized = 'luis@example.com'`); n != 1 {
		t.Fatalf("the repeat created %d accounts", n)
	}
	// the same e-mail in another tenant is another account of that tenant
	other := s.registerUser(t, adminB, "other-key-00001", fields)
	var out struct{ TenantID string }
	_ = json.Unmarshal(other.Body.Bytes(), &out)
	if other.Code != http.StatusCreated || out.TenantID != tenantB {
		t.Fatalf("%d %s", other.Code, other.Body)
	}
	// a body that names a tenant is refused: the contract has no such field
	body := userFields("zoe@example.com", "ANALYST")
	body["tenantId"] = tenantB
	if rec := s.registerUser(t, adminA, "tenant-key-0001", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_ATakenEmailIsRefusedSayingWhoseItIsAndCreatesNothing(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	s.account(t, tenantA, "active@example.com", pgtest.Options{}, "ANALYST")
	s.account(t, tenantA, "inactive@example.com", pgtest.Options{Inactive: true}, "ACCOUNTANT")
	s.account(t, tenantA, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	s.account(t, tenantA, "pending@example.com", pgtest.Options{Pending: true}, "FINAL_CUSTOMER")
	before := s.accountCount(t)
	for email, word := range map[string]string{"active@example.com": "internal user", "inactive@example.com": "reactivated",
		"customer@example.com": "customer", "pending@example.com": "customer", "ACTIVE@example.com": "internal user"} {
		rec := s.registerUser(t, admin, "taken-key-"+email[:6]+"1", userFields(email, "MANAGER"))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(strings.ToLower(rec.Body.String()), word) {
			t.Errorf("%s: %d %s", email, rec.Code, rec.Body)
		}
	}
	if got := s.accountCount(t); got != before {
		t.Fatalf("a refusal created %d accounts", got-before)
	}
}

func TestC_ATenantThatIsNotActiveRegistersNobodyAndTheCredentialsOfOthersAreRefused(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	tenants := postgres.NewTenants(s.pool)
	if _, err := tenants.Apply(ctx, coretenant.Copy{TenantID: tenantA, Identifier: "travesia-natural", Status: coretenant.Inactive, OccurredAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	before := s.accountCount(t)
	if rec := s.registerUser(t, admin, "inactive-key-001", userFields("a@example.com", "MANAGER")); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.registerUser(t, "", "no-token-key-001", userFields("a@example.com", "MANAGER")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if got := s.accountCount(t); got != before {
		t.Fatalf("created %d accounts", got-before)
	}
}
