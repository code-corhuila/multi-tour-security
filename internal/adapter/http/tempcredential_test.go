package httpadapter_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/issuetemp"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-005, RN-SEC-003-14 and -15: the route where an administrator gives a user a new temporary credential.

const (
	credentialPath = "/api/v1/security/users/" + statusUser + "/temporary-credential"
	credentialBody = `{"password":"Temporal-2026!","passwordConfirmation":"Temporal-2026!"}`
)

type fakeIssuer struct {
	requests []issuetemp.Request
	reg      port.Registered
	err      error
}

func (f *fakeIssuer) Issue(_ context.Context, r issuetemp.Request) (port.Registered, error) {
	f.requests = append(f.requests, r)
	return f.reg, f.err
}

func issuerHandler(svc httpadapter.CredentialIssuer, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithIssueTemporaryCredential(svc))
}

func postCredential(h http.Handler, token, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, credentialPath, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-Correlation-Id", "cred-1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func issued() port.Registered {
	reg := registeredUser()
	reg.Account.TemporaryUntil = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	return reg
}

func TestC_ATenantAdministratorAsksWithTheirRoleAndTenantAndThePlatformAdministratorWithNoTenant(t *testing.T) {
	for who, c := range map[string]struct {
		token string
		want  issuetemp.Request
	}{
		"a tenant administrator": {tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, ""),
			issuetemp.Request{ActorID: "worker-event-relay", ActorRole: "TENANT_ADMINISTRATOR", ActorTenantID: accountTenant, AccountID: statusUser,
				Password: "Temporal-2026!", Confirmation: "Temporal-2026!", CorrelationID: "cred-1"}},
		"the platform administrator": {tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""),
			issuetemp.Request{ActorID: "worker-event-relay", ActorRole: "PLATFORM_ADMINISTRATOR", AccountID: statusUser,
				Password: "Temporal-2026!", Confirmation: "Temporal-2026!", CorrelationID: "cred-1"}},
	} {
		svc := &fakeIssuer{reg: issued()}
		rec := postCredential(issuerHandler(svc, io.Discard), c.token, "application/json", credentialBody)
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || len(svc.requests) != 1 || svc.requests[0] != c.want {
			t.Errorf("%s: %d %v asked %+v", who, rec.Code, rec.Header(), svc.requests)
		}
	}
}

func TestC_TheAnswerShowsTheEndOfTheNewCredentialAndNeverTheCredential(t *testing.T) {
	rec := postCredential(issuerHandler(&fakeIssuer{reg: issued()}, io.Discard), administrator(t), "application/json", credentialBody)
	if !strings.Contains(rec.Body.String(), `"temporaryCredentialUntil":"2026-11-07T09:00:00Z"`) {
		t.Fatalf("%s", rec.Body)
	}
	for _, secret := range []string{"Temporal-2026!", "must-never-show", "Hash", "assword"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the answer shows %q: %s", secret, rec.Body)
		}
	}
}

func TestC_OnlyAnAdministratorWithAnOrdinaryCredentialIsLetIn(t *testing.T) {
	for who, token := range map[string]string{
		"a collaborator":               tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""),
		"a manager":                    tokenWith(t, []string{"MANAGER"}, accountTenant, ""),
		"a customer":                   tokenWith(t, []string{"FINAL_CUSTOMER"}, accountTenant, ""),
		"a service":                    tokenWith(t, []string{"SERVICE"}, "", ""),
		"a tenant administrator, none": tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, "", ""),
		"a temporary credential":       tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "password-change"),
		"a restricted platform access": tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", "restricted"),
		"a platform token with tenant": tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, accountTenant, ""),
		"no role":                      tokenWith(t, nil, accountTenant, ""),
	} {
		svc := &fakeIssuer{reg: issued()}
		if rec := postCredential(issuerHandler(svc, io.Discard), token, "application/json", credentialBody); rec.Code != http.StatusForbidden || len(svc.requests) != 0 {
			t.Errorf("%s: %d, asked %d times", who, rec.Code, len(svc.requests))
		}
	}
	if rec := postCredential(issuerHandler(&fakeIssuer{}, io.Discard), "", "application/json", credentialBody); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
}

func TestC_TheBodyIsJSONSmallAndHasNothingButThePasswordAndItsConfirmation(t *testing.T) {
	h := issuerHandler(&fakeIssuer{reg: issued()}, io.Discard)
	if rec := postCredential(h, administrator(t), "text/plain", credentialBody); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", rec.Code)
	}
	if rec := postCredential(h, administrator(t), "application/json", `{"password":"`+strings.Repeat("a", 5000)+`"}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large: %d", rec.Code)
	}
	for _, body := range []string{`{"password":`, `{"password":"x","passwordConfirmation":"x","tenantId":"` + otherTenantID + `"}`, `{"password":"x","passwordConfirmation":"x","role":"MANAGER"}`,
		`{"password":"x","passwordConfirmation":"x","temporaryCredentialUntil":"2030-01-01T00:00:00Z"}`} {
		svc := &fakeIssuer{reg: issued()}
		if rec := postCredential(issuerHandler(svc, io.Discard), administrator(t), "application/json", body); rec.Code != http.StatusBadRequest || len(svc.requests) != 0 {
			t.Errorf("%s: %d, asked %d times", body, rec.Code, len(svc.requests))
		}
	}
}

func TestC_EachRefusalOfTheUseCaseIsItsOwnStatusAndNeverALeak(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"a weak password":               {&issuetemp.FieldError{Field: "password", Err: errors.New("at least 8 characters")}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"a confirmation that differs":   {&issuetemp.FieldError{Field: "passwordConfirmation", Err: errors.New("does not match the password")}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"an account id that is not one": {&issuetemp.FieldError{Field: "accountId", Err: errors.New("is not valid")}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"an actor that is not an id":    {&issuetemp.FieldError{Field: "actorId", Err: errors.New("is not valid")}, http.StatusInternalServerError, "INTERNAL_ERROR"},
		"a user that is not there":      {port.ErrUserNotFound, http.StatusNotFound, "NOT_FOUND"},
		"an issuer without authority":   {issuetemp.ErrNotAuthorized, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION"},
		"an account with its password":  {port.ErrNotTemporary, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION"},
		"a failure of ours":             {errors.New("pq: password=hunter2"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	} {
		var logs strings.Builder
		rec := postCredential(issuerHandler(&fakeIssuer{err: c.err}, &logs), administrator(t), "application/json", credentialBody)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), `"error":"`+c.code+`"`) || strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(logs.String(), "hunter2") {
			t.Errorf("%s: %d %s | %s", name, rec.Code, rec.Body, logs.String())
		}
	}
}

func TestC_ARefusalNamesTheFieldAndSaysWhatIsWrongWithoutTheValue(t *testing.T) {
	rec := postCredential(issuerHandler(&fakeIssuer{err: &issuetemp.FieldError{Field: "password", Err: errors.New("at least 8 characters")}}, io.Discard), administrator(t), "application/json", credentialBody)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"password"`) || !strings.Contains(rec.Body.String(), "at least 8 characters") || strings.Contains(rec.Body.String(), "Temporal-2026!") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
