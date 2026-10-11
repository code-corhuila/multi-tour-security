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

// End to end against PostgreSQL, through HTTP, as the saga onboard-tenant calls it: the first Administrator of a tenant
// is made with a temporary credential and lands in the password change at the first sign-in. Every answer is validated
// against the tested contract.

const (
	adminURL      = "/api/v1/security/internal/tenants/" + tenantA + "/administrators"
	unknownTenant = "8e1f2a3b-4c5d-4e6f-9a7b-0c1d2e3f4a5b"
	adminPass     = "Temporal-2026!"
)

func adminFields() map[string]string {
	return map[string]string{"fullName": "Laura Perez", "email": " Laura.Perez@Example.com ", "password": adminPass}
}

func (s *stack) createAdmin(t *testing.T, url, token, key string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(fields)
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-adm")
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

func TestC_TheFirstAdministratorIsCreatedWithATemporaryCredentialAndFirstSignInIsAPasswordChange(t *testing.T) {
	s := newStack(t)
	rec := s.createAdmin(t, adminURL, s.serviceToken(t), "onboard-1:create-admin", adminFields())
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	roles, _ := got["roles"].([]any)
	if got["tenantId"] != tenantA || got["email"] != "laura.perez@example.com" || got["fullName"] != "Laura Perez" || got["accountStatus"] != "ACTIVE" ||
		len(roles) != 1 || roles[0] != "TENANT_ADMINISTRATOR" || got["temporaryCredentialUntil"] == nil {
		t.Fatalf("the account is the Administrator of the tenant with a temporary credential: %v", got)
	}
	if strings.Contains(rec.Body.String(), adminPass) || strings.Contains(rec.Body.String(), "$2") {
		t.Fatalf("the answer carries a credential: %s", rec.Body)
	}
	_, claims := s.claims(t, s.signIn(tenantURL, "laura.perez@example.com", adminPass))
	if claims["sub"] != got["accountId"] || claims["access"] != "password-change" {
		t.Fatalf("the first sign-in lands in the password change: %v", claims)
	}
}

func TestC_ARepeatOfTheKeyIsA200WithTheSameAdministratorWhateverTheBodySays(t *testing.T) {
	s := newStack(t)
	svc := s.serviceToken(t)
	first := decodeCreated(t, s.createAdmin(t, adminURL, svc, "onboard-1:create-admin", adminFields()))
	changed := adminFields()
	changed["email"] = "someone.else@example.com"
	rec := s.createAdmin(t, adminURL, svc, "onboard-1:create-admin", changed)
	if rec.Code != http.StatusOK || decodeCreated(t, rec).AccountID != first.AccountID || s.accountCount(t) != 1 {
		t.Fatalf("%d %s (%d accounts)", rec.Code, rec.Body, s.accountCount(t))
	}
}

func TestC_ATakenEmailInTheTenantIs422AndTheSameEmailInAnotherTenantIsAnotherAccount(t *testing.T) {
	s := newStack(t)
	svc := s.serviceToken(t)
	s.createAdmin(t, adminURL, svc, "onboard-1:create-admin", adminFields())
	shout := adminFields()
	shout["email"] = "LAURA.PEREZ@example.com"
	rec := s.createAdmin(t, adminURL, svc, "onboard-2:create-admin", shout)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"details":[{"field":"email","message":"already in use"}]`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	other := s.createAdmin(t, "/api/v1/security/internal/tenants/"+tenantB+"/administrators", svc, "onboard-3:create-admin", adminFields())
	if other.Code != http.StatusCreated || s.accountCount(t) != 2 {
		t.Fatalf("%d %s (%d accounts)", other.Code, other.Body, s.accountCount(t))
	}
}

func TestC_TheSagaIsTheAuthorityThatTheTenantExistsSoNoCopyIsNeeded(t *testing.T) {
	s := newStack(t)
	rec := s.createAdmin(t, "/api/v1/security/internal/tenants/"+unknownTenant+"/administrators", s.serviceToken(t), "onboard-1:create-admin", adminFields())
	if rec.Code != http.StatusCreated || decodeCreated(t, rec).TenantID != unknownTenant {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_EachMissingOrMalformedFieldOfTheFirstAdministratorIs400NamingItAndNothingIsCreated(t *testing.T) {
	cases := []struct {
		field  string
		change func(map[string]string)
	}{
		{"fullName", func(f map[string]string) { delete(f, "fullName") }},
		{"fullName", func(f map[string]string) { f["fullName"] = strings.Repeat("a", 101) }},
		{"email", func(f map[string]string) { delete(f, "email") }},
		{"email", func(f map[string]string) { f["email"] = "not-an-email" }},
		{"password", func(f map[string]string) { delete(f, "password") }},
		{"password", func(f map[string]string) { f["password"] = "weak" }},
		{"password", func(f map[string]string) { f["password"] = "Password1!" }},
	}
	s := newStack(t)
	svc := s.serviceToken(t)
	for i, c := range cases {
		f := adminFields()
		c.change(f)
		rec := s.createAdmin(t, adminURL, svc, "onboard-"+string(rune('a'+i))+":create-admin", f)
		var env struct {
			Error   string `json:"error"`
			Details []struct {
				Field string `json:"field"`
			} `json:"details"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != http.StatusBadRequest || env.Error != "VALIDATION_ERROR" || len(env.Details) != 1 || env.Details[0].Field != c.field {
			t.Errorf("case %d (%s): %d %s", i, c.field, rec.Code, rec.Body)
		}
		for _, secret := range []string{adminPass, "Password1!"} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("case %d: the answer quotes a password: %s", i, rec.Body)
			}
		}
	}
	if n := s.accountCount(t); n != 0 {
		t.Fatalf("a refused form creates nothing: %d accounts", n)
	}
}

func TestC_WithoutAValidIdempotencyKeyTheFirstAdministratorIs400(t *testing.T) {
	s := newStack(t)
	svc := s.serviceToken(t)
	for _, key := range []string{"", "short", strings.Repeat("k", 129)} {
		if rec := s.createAdmin(t, adminURL, svc, key, adminFields()); rec.Code != http.StatusBadRequest {
			t.Errorf("key %q: %d %s", key, rec.Code, rec.Body)
		}
	}
	if n := s.accountCount(t); n != 0 {
		t.Fatalf("%d accounts", n)
	}
}

func TestC_OnlyAServiceTokenCreatesTheFirstAdministrator(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "boss@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	if rec := s.createAdmin(t, adminURL, "", "onboard-1:create-admin", adminFields()); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec := s.createAdmin(t, adminURL, "garbage", "onboard-1:create-admin", adminFields()); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", rec.Code)
	}
	a, _ := s.claims(t, s.signIn(tenantURL, "boss@example.com", password))
	if rec := s.createAdmin(t, adminURL, a.AccessToken, "onboard-1:create-admin", adminFields()); rec.Code != http.StatusForbidden {
		t.Errorf("a person's token: %d %s", rec.Code, rec.Body)
	}
	if n := s.accountCount(t); n != 1 {
		t.Fatalf("only the fixture exists: %d accounts", n)
	}
}

func TestC_TheLogsOfTheFirstAdministratorCarryNoPasswordAndNoEmail(t *testing.T) {
	s := newStack(t)
	svc := s.serviceToken(t)
	s.createAdmin(t, adminURL, svc, "onboard-1:create-admin", adminFields())
	s.createAdmin(t, adminURL, svc, "onboard-2:create-admin", adminFields()) // the e-mail is taken
	for _, leak := range []string{adminPass, "laura.perez@example.com", "Laura.Perez@Example.com"} {
		if strings.Contains(s.logs.String(), leak) {
			t.Fatalf("the log shows %q: %s", leak, s.logs)
		}
	}
}
