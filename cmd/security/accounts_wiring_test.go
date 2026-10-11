package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// End to end against PostgreSQL, through HTTP: a Final Customer creates their account in the tenant of a link
// (RN-SEC-002-01 to -04, -06 to -09). Every answer is validated against the tested contract.

const (
	accountsURL  = "/api/v1/security/public/tenants/travesia-natural/accounts"
	otherAccount = "/api/v1/security/public/tenants/otra-agencia/accounts"
	customerPass = "Viaje-2026!"
)

func customerFields() map[string]string {
	return map[string]string{"firstName": "Laura", "lastName": "Pérez", "email": " Laura.Perez@Example.com ", "phone": "+57 300 123 4567",
		"password": customerPass, "passwordConfirmation": customerPass}
}

func (s *stack) register(t *testing.T, url, key string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(fields)
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-acc")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	validateAgainstContract(t, req, rec)
	return rec
}

func validateAgainstContract(t *testing.T, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	router, err := legacy.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}
	route, params, err := router.FindRoute(req)
	if err != nil {
		t.Fatalf("%s is not in the contract: %v", req.URL.Path, err)
	}
	response := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route},
		Status:                 rec.Code, Header: rec.Header(), Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	response.SetBodyBytes(rec.Body.Bytes())
	if err := openapi3filter.ValidateResponse(ctx, response); err != nil {
		t.Errorf("the answer %d breaks the contract: %v (%s)", rec.Code, err, rec.Body)
	}
}

type created struct {
	AccountID     string   `json:"accountId"`
	TenantID      string   `json:"tenantId"`
	Email         string   `json:"email"`
	FullName      string   `json:"fullName"`
	Roles         []string `json:"roles"`
	AccountStatus string   `json:"accountStatus"`
	EmailVerified bool     `json:"emailVerified"`
	CreatedAt     string   `json:"createdAt"`
}

func decodeCreated(t *testing.T, rec *httptest.ResponseRecorder) created {
	t.Helper()
	var c created
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func (s *stack) accountCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.identity`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestC_TheCustomerBelongsToTheTenantOfTheLinkAndSignsInWithThePasswordTheyChose(t *testing.T) {
	s := newStack(t)
	rec := s.register(t, accountsURL, "customer-key-0001", customerFields())
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	c := decodeCreated(t, rec)
	if c.TenantID != tenantA || c.Email != "laura.perez@example.com" || c.FullName != "Laura Pérez" || c.AccountStatus != "ACTIVE" ||
		c.EmailVerified || len(c.Roles) != 1 || c.Roles[0] != "FINAL_CUSTOMER" || c.CreatedAt == "" {
		t.Fatalf("the account is active in the tenant of the link: %+v", c)
	}
	_, claims := s.claims(t, s.signIn(tenantURL, "laura.perez@example.com", customerPass))
	if claims["sub"] != c.AccountID || claims["tenantId"] != tenantA {
		t.Fatalf("the customer signs in as the account that was created: %v", claims)
	}
	if roles, _ := claims["roles"].([]any); len(roles) != 1 || roles[0] != "FINAL_CUSTOMER" {
		t.Fatalf("roles = %v", claims["roles"])
	}
	if _, restricted := claims["access"]; restricted {
		t.Fatalf("the password is ordinary, not temporary: %v", claims)
	}
	if rec := s.signIn(otherURL, "laura.perez@example.com", customerPass); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the account does not exist in the other tenant: %d", rec.Code)
	}
}

func TestC_TheSameEmailInAnotherTenantIsAnotherAccountAndInTheSameTenantIsRefused(t *testing.T) {
	s := newStack(t)
	first := decodeCreated(t, s.register(t, accountsURL, "customer-key-0001", customerFields()))
	other := s.register(t, otherAccount, "customer-key-0002", customerFields())
	if other.Code != http.StatusCreated || decodeCreated(t, other).AccountID == first.AccountID {
		t.Fatalf("another tenant, another account: %d %s", other.Code, other.Body)
	}
	for _, email := range []string{"laura.perez@example.com", "LAURA.PEREZ@EXAMPLE.COM"} {
		f := customerFields()
		f["email"] = email
		rec := s.register(t, accountsURL, "customer-key-0003", f)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "BUSINESS_RULE_VIOLATION") ||
			!strings.Contains(rec.Body.String(), `"details":[{"field":"email","message":"already in use"}]`) {
			t.Errorf("%s: %d %s", email, rec.Code, rec.Body)
		}
	}
	if n := s.accountCount(t); n != 2 {
		t.Fatalf("a refusal creates nothing: %d accounts", n)
	}
}

func TestC_ARepeatWithTheSameKeyIsA200WithTheSameAccountWhateverTheBodySays(t *testing.T) {
	s := newStack(t)
	first := decodeCreated(t, s.register(t, accountsURL, "customer-key-0001", customerFields()))
	changed := customerFields()
	changed["email"], changed["firstName"] = "someone.else@example.com", "Otra"
	rec := s.register(t, accountsURL, "customer-key-0001", changed)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if again := decodeCreated(t, rec); again.AccountID != first.AccountID || again.CreatedAt != first.CreatedAt || again.Email != first.Email {
		t.Fatalf("the repeat answers the account of the first request: %+v vs %+v", again, first)
	}
	if n := s.accountCount(t); n != 1 {
		t.Fatalf("a repeat creates nothing: %d accounts", n)
	}
}

func TestC_EachMissingOrMalformedFieldIsA400NamingItAndNothingIsCreated(t *testing.T) {
	cases := []struct {
		field  string
		change func(map[string]string)
	}{
		{"firstName", func(f map[string]string) { delete(f, "firstName") }},
		{"firstName", func(f map[string]string) { f["firstName"] = strings.Repeat("a", 51) }},
		{"lastName", func(f map[string]string) { delete(f, "lastName") }},
		{"email", func(f map[string]string) { delete(f, "email") }},
		{"email", func(f map[string]string) { f["email"] = "not-an-email" }},
		{"phone", func(f map[string]string) { delete(f, "phone") }},
		{"phone", func(f map[string]string) { f["phone"] = "call me" }},
		{"password", func(f map[string]string) { delete(f, "password"); delete(f, "passwordConfirmation") }},
		{"password", func(f map[string]string) { f["password"], f["passwordConfirmation"] = "weak", "weak" }},
		{"password", func(f map[string]string) { f["password"], f["passwordConfirmation"] = "Password1!", "Password1!" }},
		{"passwordConfirmation", func(f map[string]string) { delete(f, "passwordConfirmation") }},
		{"passwordConfirmation", func(f map[string]string) { f["passwordConfirmation"] = "Viaje-2026?" }},
	}
	s := newStack(t)
	for i, c := range cases {
		f := customerFields()
		c.change(f)
		rec := s.register(t, accountsURL, "customer-key-"+string(rune('a'+i))+"-0001", f)
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
		for _, secret := range []string{customerPass, "Viaje-2026?", "Password1!"} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("case %d: the answer quotes a password: %s", i, rec.Body)
			}
		}
	}
	if n := s.accountCount(t); n != 0 {
		t.Fatalf("a refused form creates nothing: %d accounts", n)
	}
}

func TestC_WithoutAValidIdempotencyKeyTheAnswerIs400AndNothingIsCreated(t *testing.T) {
	s := newStack(t)
	for _, key := range []string{"", "short", strings.Repeat("k", 129)} {
		if rec := s.register(t, accountsURL, key, customerFields()); rec.Code != http.StatusBadRequest {
			t.Errorf("key %q: %d %s", key, rec.Code, rec.Body)
		}
	}
	if n := s.accountCount(t); n != 0 {
		t.Fatalf("%d accounts", n)
	}
}

func TestC_AnUnknownTenantIs404AndAnInactiveOneIs422AndNeitherCreatesAnything(t *testing.T) {
	s := newStack(t)
	if rec := s.register(t, "/api/v1/security/public/tenants/nowhere/accounts", "customer-key-0001", customerFields()); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d %s", rec.Code, rec.Body)
	}
	copyOf := coretenant.Copy{TenantID: tenantB, Identifier: "otra-agencia", Status: coretenant.Inactive, OccurredAt: time.Now()}
	if _, err := postgres.NewTenants(s.pool).Apply(ctx, copyOf); err != nil {
		t.Fatal(err)
	}
	rec := s.register(t, otherAccount, "customer-key-0002", customerFields())
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "BUSINESS_RULE_VIOLATION") || strings.Contains(rec.Body.String(), "details") {
		t.Fatalf("inactive: %d %s", rec.Code, rec.Body)
	}
	if n := s.accountCount(t); n != 0 {
		t.Fatalf("%d accounts", n)
	}
}

func TestC_TheLogsOfACreationCarryNoPasswordAndNoEmail(t *testing.T) {
	s := newStack(t)
	s.register(t, accountsURL, "customer-key-0001", customerFields())
	s.register(t, accountsURL, "customer-key-0002", customerFields()) // the e-mail is taken
	weak := customerFields()
	weak["password"], weak["passwordConfirmation"] = "weak", "weak"
	s.register(t, accountsURL, "customer-key-0003", weak)
	for _, leak := range []string{customerPass, "laura.perez@example.com", "Laura.Perez@Example.com"} {
		if strings.Contains(s.logs.String(), leak) {
			t.Fatalf("the log shows %q: %s", leak, s.logs)
		}
	}
}
