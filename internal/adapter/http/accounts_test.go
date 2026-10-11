package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

const (
	accountsRoute = "/api/v1/security/public/tenants/travesia-natural/accounts"
	accountsKey   = "customer-key-0001"
	accountTenant = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	accountID     = "7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	customerBody  = `{"firstName":"Laura","lastName":"Pérez","email":"Laura.Perez@Example.com","phone":"+57 300 123 4567","password":"Viaje-2026!","passwordConfirmation":"Viaje-2026!"}`
)

type fakeCreator struct {
	commands []createaccount.Command
	reg      port.Registered
	created  bool
	err      error
}

func (f *fakeCreator) Create(_ context.Context, c createaccount.Command) (port.Registered, bool, error) {
	f.commands = append(f.commands, c)
	return f.reg, f.created, f.err
}

type fakeTenantFinder struct {
	asked []string
	found bool
	err   error
}

func (f *fakeTenantFinder) FindByIdentifier(_ context.Context, identifier string) (tenant.Copy, bool, error) {
	f.asked = append(f.asked, identifier)
	return tenant.Copy{TenantID: accountTenant, Identifier: identifier, Status: tenant.Active}, f.found, f.err
}

func registered() port.Registered {
	return port.Registered{
		Account:   account.Account{ID: accountID, TenantID: accountTenant, EmailNormalized: "laura.perez@example.com", PasswordHash: "must-never-show"},
		Role:      "FINAL_CUSTOMER",
		FullName:  "Laura Pérez",
		Phone:     "+57 300 123 4567",
		CreatedAt: time.Date(2026, 10, 11, 15, 4, 5, 0, time.UTC),
	}
}

func accountsHandler(svc httpadapter.AccountCreator, tenants httpadapter.TenantFinder, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithCreateAccount(svc, tenants))
}

func postAccount(h http.Handler, path, contentType, body, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Correlation-Id", "acc-1")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestC_TheCustomerRouteHandsTheUseCaseTheTenantOfTheLinkAndTheBodyAndAnswers201WithoutCredentials(t *testing.T) {
	svc, tenants := &fakeCreator{reg: registered(), created: true}, &fakeTenantFinder{found: true}
	rec := postAccount(accountsHandler(svc, tenants, io.Discard), accountsRoute, "application/json", customerBody, accountsKey)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "acc-1" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	want := createaccount.Command{Kind: createaccount.Customer, TenantID: accountTenant, FirstName: "Laura", LastName: "Pérez",
		Email: "Laura.Perez@Example.com", Phone: "+57 300 123 4567", Password: "Viaje-2026!", Confirmation: "Viaje-2026!", IdempotencyKey: accountsKey}
	if len(svc.commands) != 1 || svc.commands[0] != want || len(tenants.asked) != 1 || tenants.asked[0] != "travesia-natural" {
		t.Fatalf("the use case got %+v, the tenant asked %v", svc.commands, tenants.asked)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	roles, _ := got["roles"].([]any)
	if len(got) != 9 || got["accountId"] != accountID || got["tenantId"] != accountTenant || got["email"] != "laura.perez@example.com" ||
		got["fullName"] != "Laura Pérez" || got["phone"] != "+57 300 123 4567" || got["accountStatus"] != "ACTIVE" ||
		got["emailVerified"] != false || got["createdAt"] != "2026-10-11T15:04:05Z" || len(roles) != 1 || roles[0] != "FINAL_CUSTOMER" {
		t.Fatalf("the answer is exactly the nine fields of the contract: %v", got)
	}
	for _, secret := range []string{"Viaje-2026!", "must-never-show"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the answer carries a credential: %s", rec.Body)
		}
	}
}

func TestC_ARepeatIsA200WithTheSameAccount(t *testing.T) {
	svc := &fakeCreator{reg: registered(), created: false}
	rec := postAccount(accountsHandler(svc, &fakeTenantFinder{found: true}, io.Discard), accountsRoute, "application/json", customerBody, accountsKey)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), accountID) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_EveryRefusalOfTheUseCaseIsTranslatedInOnePlace(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
		kind string
	}{
		{"field", &createaccount.FieldError{Field: "password", Err: errors.New("the password does not meet the policy")}, 400, "VALIDATION_ERROR"},
		{"e-mail in use", port.ErrEmailTaken, 422, "BUSINESS_RULE_VIOLATION"},
		{"tenant gone", createaccount.ErrTenantNotFound, 404, "NOT_FOUND"},
		{"tenant not active", createaccount.ErrTenantNotActive, 422, "BUSINESS_RULE_VIOLATION"},
		{"not wired", createaccount.ErrNotWired, 500, "INTERNAL_ERROR"},
		{"driver", errors.New("connection refused to 10.0.0.5"), 500, "INTERNAL_ERROR"},
	}
	for _, c := range cases {
		rec := postAccount(accountsHandler(&fakeCreator{err: c.err}, &fakeTenantFinder{found: true}, io.Discard), accountsRoute, "application/json", customerBody, accountsKey)
		var env struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			TraceID string `json:"traceId"`
			Details []struct {
				Field   string `json:"field"`
				Message string `json:"message"`
			} `json:"details"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != c.code || env.Error != c.kind || env.TraceID != "acc-1" || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
		if c.code == 400 && (len(env.Details) != 1 || env.Details[0].Field != "password" || strings.Contains(rec.Body.String(), "Viaje-2026!")) {
			t.Errorf("%s: details must name the field and never the value: %s", c.name, rec.Body)
		}
	}
}

func TestC_AnUnknownIdentifierIsA404AndAFailureOfTheCopyIsA500WithoutReachingTheUseCase(t *testing.T) {
	cases := map[string]struct {
		tenants *fakeTenantFinder
		want    int
	}{
		"unknown": {&fakeTenantFinder{found: false}, http.StatusNotFound},
		"failure": {&fakeTenantFinder{err: errors.New("down")}, http.StatusInternalServerError},
	}
	for name, c := range cases {
		svc := &fakeCreator{}
		rec := postAccount(accountsHandler(svc, c.tenants, io.Discard), accountsRoute, "application/json", customerBody, accountsKey)
		if rec.Code != c.want || len(svc.commands) != 0 {
			t.Errorf("%s: %d, reached the use case: %v", name, rec.Code, svc.commands)
		}
	}
}

func TestC_ABadBodyATypeAndASizeAreRefusedBeforeTheUseCase(t *testing.T) {
	cases := []struct {
		name, contentType, body string
		status                  int
		code                    string
	}{
		{"bad JSON", "application/json", `{"firstName":`, 400, "VALIDATION_ERROR"},
		{"unknown field", "application/json", `{"firstName":"A","tenantId":"` + accountTenant + `"}`, 400, "VALIDATION_ERROR"},
		{"wrong JSON type", "application/json", `{"firstName":7}`, 400, "VALIDATION_ERROR"},
		{"two documents", "application/json", customerBody + customerBody, 400, "VALIDATION_ERROR"},
		{"wrong content type", "text/plain", customerBody, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"over the limit", "application/json", `{"firstName":"` + strings.Repeat("a", 4200) + `"}`, 413, "PAYLOAD_TOO_LARGE"},
	}
	for _, c := range cases {
		svc := &fakeCreator{}
		rec := postAccount(accountsHandler(svc, &fakeTenantFinder{found: true}, io.Discard), accountsRoute, c.contentType, c.body, accountsKey)
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != c.status || env.Error != c.code || len(svc.commands) != 0 {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
	}
}

func TestC_TheRouteIsPublicAndOnlyAnswersPost(t *testing.T) {
	h := accountsHandler(&fakeCreator{reg: registered(), created: true}, &fakeTenantFinder{found: true}, io.Discard)
	req := httptest.NewRequest(http.MethodPost, accountsRoute, strings.NewReader(customerBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer garbage.not.ajwt")
	req.Header.Set("Idempotency-Key", accountsKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("no token is needed, and a bad one is ignored: %d", rec.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, accountsRoute, nil))
		if rec.Code == http.StatusCreated || rec.Code == http.StatusOK {
			t.Errorf("%s answered %d", method, rec.Code)
		}
	}
}

func TestC_LogsShowNoCredentialNorEmailWhateverTheOutcome(t *testing.T) {
	var logs bytes.Buffer
	for _, c := range []struct {
		contentType, body string
		svc               *fakeCreator
	}{
		{"application/json", customerBody, &fakeCreator{reg: registered(), created: true}},
		{"application/json", customerBody, &fakeCreator{err: port.ErrEmailTaken}},
		{"application/json", customerBody, &fakeCreator{err: errors.New("boom")}},
		{"application/json", strings.Replace(customerBody, `"phone"`, `"x":1,"phone"`, 1), &fakeCreator{}},
		{"text/plain", customerBody, &fakeCreator{}},
		{"application/json", customerBody + strings.Repeat(" ", 5000), &fakeCreator{}},
	} {
		postAccount(accountsHandler(c.svc, &fakeTenantFinder{found: true}, &logs), accountsRoute, c.contentType, c.body, accountsKey)
	}
	for _, leak := range []string{"Viaje-2026!", "Laura.Perez@Example.com", "laura.perez@example.com"} {
		if strings.Contains(logs.String(), leak) {
			t.Fatalf("the log shows %q: %s", leak, logs.String())
		}
	}
}
