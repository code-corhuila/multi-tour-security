package httpadapter_test

import (
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
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

const (
	usersRoute = "/api/v1/security/users"
	usersKey   = "register-user-0001"
	// the Administrator types the temporary password and its confirmation (HU-SEC-005, RN-SEC-003-03)
	userBody = `{"fullName":"Carlos Gómez","email":"Carlos.Gomez@Example.com","role":"OPERATIONAL_COLLABORATOR","password":"Temporal-2026!","passwordConfirmation":"Temporal-2026!"}`
)

func usersHandler(svc httpadapter.AccountCreator, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithCreateInternalUser(svc))
}

func postUser(h http.Handler, token, contentType, body, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, usersRoute, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Correlation-Id", "usr-1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// administrator is the credential that may manage users: the role, a tenant and no access mark.
func administrator(t *testing.T) string {
	t.Helper()
	return tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "")
}

func registeredUser() port.Registered {
	reg := registered()
	reg.Role = "OPERATIONAL_COLLABORATOR"
	reg.FullName = "Carlos Gómez"
	reg.Account.EmailNormalized = "carlos.gomez@example.com"
	reg.Account.TemporaryUntil = time.Date(2026, 10, 14, 15, 4, 5, 0, time.UTC)
	return reg
}

func TestC_AnAdministratorRegistersAUserAndTheUseCaseGetsTheTenantOfTheTokenAndTheAdministratorAsActor(t *testing.T) {
	svc := &fakeCreator{reg: registeredUser(), created: true}
	rec := postUser(usersHandler(svc, io.Discard), administrator(t), "application/json", userBody, usersKey)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	want := createaccount.Command{Kind: createaccount.InternalUser, TenantID: accountTenant, FullName: "Carlos Gómez",
		Email: "Carlos.Gomez@Example.com", Role: "OPERATIONAL_COLLABORATOR", Password: "Temporal-2026!", Confirmation: "Temporal-2026!",
		Actor: "worker-event-relay", IdempotencyKey: usersKey}
	if len(svc.commands) != 1 || svc.commands[0] != want {
		t.Fatalf("the use case got %+v", svc.commands)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if roles, _ := out["roles"].([]any); len(roles) != 1 || roles[0] != "OPERATIONAL_COLLABORATOR" || out["temporaryCredentialUntil"] == nil {
		t.Fatalf("the answer is %v", out)
	}
}

func TestC_TheAnswerCarriesNoSecret(t *testing.T) {
	rec := postUser(usersHandler(&fakeCreator{reg: registeredUser(), created: true}, io.Discard), administrator(t), "application/json", userBody, usersKey)
	for _, secret := range []string{"must-never-show", "Temporal-2026!", "password", "Hash"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the answer shows %q: %s", secret, rec.Body)
		}
	}
}

func TestC_ARepeatOfTheKeyIs200WithTheUserAlreadyCreated(t *testing.T) {
	rec := postUser(usersHandler(&fakeCreator{reg: registeredUser()}, io.Discard), administrator(t), "application/json", userBody, usersKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_OnlyATenantAdministratorWithAnOrdinaryCredentialIsLetIn(t *testing.T) {
	tokens := map[string]string{
		"a collaborator":                        tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""),
		"a manager":                             tokenWith(t, []string{"MANAGER"}, accountTenant, ""),
		"a customer":                            tokenWith(t, []string{"FINAL_CUSTOMER"}, accountTenant, ""),
		"the Platform Administrator":            tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""),
		"a token with no role":                  tokenWith(t, nil, accountTenant, ""),
		"an Administrator with no tenant":       tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, "", ""),
		"a temporary credential":                tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "password-change"),
		"a restricted access":                   tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "restricted"),
		"a customer who is also a collaborator": tokenWith(t, []string{"FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR"}, accountTenant, ""),
	}
	for who, token := range tokens {
		svc := &fakeCreator{reg: registeredUser(), created: true}
		rec := postUser(usersHandler(svc, io.Discard), token, "application/json", userBody, usersKey)
		if rec.Code != http.StatusForbidden || len(svc.commands) != 0 {
			t.Errorf("%s: %d, the use case was asked %d times: %s", who, rec.Code, len(svc.commands), rec.Body)
		}
	}
	svc := &fakeCreator{}
	if rec := postUser(usersHandler(svc, io.Discard), "", "application/json", userBody, usersKey); rec.Code != http.StatusUnauthorized || len(svc.commands) != 0 {
		t.Fatalf("no token: %d", rec.Code)
	}
}

func TestC_NothingInTheBodyCanNameAnotherTenantOrAnotherActor(t *testing.T) {
	svc := &fakeCreator{reg: registeredUser(), created: true}
	for _, extra := range []string{`"tenantId":"` + otherTenantID + `"`, `"actor":"someone"`, `"createdBy":"someone"`, `"roles":["MANAGER"]`} {
		body := strings.Replace(userBody, `"role":`, extra+`,"role":`, 1)
		if rec := postUser(usersHandler(svc, io.Discard), administrator(t), "application/json", body, usersKey); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", extra, rec.Code, rec.Body)
		}
	}
	if len(svc.commands) != 0 {
		t.Fatalf("the use case was asked with a body that names more than the contract: %+v", svc.commands)
	}
}

const otherTenantID = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"

func TestC_AMissingFieldIsRefusedByTheUseCaseNamingIt(t *testing.T) {
	svc := &fakeCreator{err: &createaccount.FieldError{Field: "role", Err: errors.New("is not valid")}}
	rec := postUser(usersHandler(svc, io.Discard), administrator(t), "application/json", `{"fullName":"Carlos"}`, usersKey)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"role"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// RN-SEC-003-05: the Administrator is told whose the e-mail is, so that they know what to do.
func TestC_ARefusedEmailSaysWhoseItIs(t *testing.T) {
	cases := map[createaccount.TakenReason]string{
		createaccount.TakenByInternalUser:         "internal user",
		createaccount.TakenByInactiveInternalUser: "reactivated",
		createaccount.TakenByCustomer:             "customer",
	}
	seen := map[string]bool{}
	for reason, word := range cases {
		svc := &fakeCreator{err: &createaccount.EmailTakenError{Reason: reason}}
		rec := postUser(usersHandler(svc, io.Discard), administrator(t), "application/json", userBody, usersKey)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("reason %d: %d %s", reason, rec.Code, rec.Body)
		}
		var out struct {
			Error   string `json:"error"`
			Details []struct{ Field, Message string }
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Error != "BUSINESS_RULE_VIOLATION" || len(out.Details) != 1 || out.Details[0].Field != "email" {
			t.Fatalf("reason %d: %s", reason, rec.Body)
		}
		if !strings.Contains(strings.ToLower(out.Details[0].Message), word) {
			t.Errorf("reason %d: the message %q does not say %q", reason, out.Details[0].Message, word)
		}
		if seen[out.Details[0].Message] {
			t.Errorf("two reasons share the message %q", out.Details[0].Message)
		}
		seen[out.Details[0].Message] = true
	}
}

// HU-SEC-006, RN-SEC-005-12: an optional role the tenant has not enabled is a rule of the business, not a mistake of the caller.
func TestC_ARoleTheTenantHasNotEnabledIs422AndDoesNotRepeatTheRole(t *testing.T) {
	rec := postUser(usersHandler(&fakeCreator{err: port.ErrRoleNotEnabled}, io.Discard), administrator(t), "application/json", strings.Replace(userBody, "OPERATIONAL_COLLABORATOR", "MANAGER", 1), usersKey)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"error":"BUSINESS_RULE_VIOLATION"`) || !strings.Contains(rec.Body.String(), "not enabled") ||
		strings.Contains(rec.Body.String(), "MANAGER") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_ATakenEmailWithNoReasonKeepsThePlainRefusal(t *testing.T) {
	rec := postUser(usersHandler(&fakeCreator{err: port.ErrEmailTaken}, io.Discard), administrator(t), "application/json", userBody, usersKey)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "already in use") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_TheTenantThatIsNotActiveIs422AndAFailureNeverLeaksItsCause(t *testing.T) {
	if rec := postUser(usersHandler(&fakeCreator{err: createaccount.ErrTenantNotActive}, io.Discard), administrator(t), "application/json", userBody, usersKey); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var logs strings.Builder
	rec := postUser(usersHandler(&fakeCreator{err: errors.New("pq: password=hunter2 for carlos")}, &logs), administrator(t), "application/json", userBody, usersKey)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(logs.String(), "hunter2") {
		t.Fatalf("%d %s | %s", rec.Code, rec.Body, logs.String())
	}
}

func TestC_TheBodyIsJSONAndSmall(t *testing.T) {
	h := usersHandler(&fakeCreator{reg: registeredUser(), created: true}, io.Discard)
	if rec := postUser(h, administrator(t), "text/plain", userBody, usersKey); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", rec.Code)
	}
	if rec := postUser(h, administrator(t), "application/json", `{"fullName":"`+strings.Repeat("a", 5000)+`"}`, usersKey); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large: %d", rec.Code)
	}
	if rec := postUser(h, administrator(t), "application/json", `{"fullName":`, usersKey); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed: %d", rec.Code)
	}
}
