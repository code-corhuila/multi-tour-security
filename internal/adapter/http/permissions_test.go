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

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/changepermission"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-006, RN-SEC-005-01, -02, -09 and -16: the routes where an Administrator assigns and removes a special permission.

const (
	grantPath      = "/api/v1/security/users/" + statusUser + "/permission-grant"
	removalPath    = "/api/v1/security/users/" + statusUser + "/permission-removal"
	permissionBody = `{"permission":"MANAGE_CASH"}`
)

type fakePermissions struct {
	requests []changepermission.Request
	actions  []string
	reg      port.Registered
	err      error
}

func (f *fakePermissions) Grant(_ context.Context, r changepermission.Request) (port.Registered, error) {
	f.requests, f.actions = append(f.requests, r), append(f.actions, "grant")
	return f.reg, f.err
}

func (f *fakePermissions) Remove(_ context.Context, r changepermission.Request) (port.Registered, error) {
	f.requests, f.actions = append(f.requests, r), append(f.actions, "remove")
	return f.reg, f.err
}

func permissionsHandler(svc httpadapter.PermissionChanger, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithChangePermission(svc))
}

func postPermission(h http.Handler, token, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-Correlation-Id", "perm-1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestC_TheRoutesAskTheUseCaseWithTheTenantAndTheActorOfTheTokenTheUserOfThePathAndThePermissionOfTheBody(t *testing.T) {
	for path, action := range map[string]string{grantPath: "grant", removalPath: "remove"} {
		svc := &fakePermissions{reg: registeredUser()}
		rec := postPermission(permissionsHandler(svc, io.Discard), administrator(t), path, "application/json", permissionBody)
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %v %s", action, rec.Code, rec.Header(), rec.Body)
		}
		want := changepermission.Request{TenantID: accountTenant, AccountID: statusUser, ActorID: "worker-event-relay", Permission: "MANAGE_CASH", CorrelationID: "perm-1"}
		if len(svc.requests) != 1 || svc.requests[0] != want || svc.actions[0] != action {
			t.Fatalf("%s: the use case was asked %+v %v", action, svc.requests, svc.actions)
		}
	}
}

func TestC_TheAnswerIsTheUserAndCarriesNoSecret(t *testing.T) {
	rec := postPermission(permissionsHandler(&fakePermissions{reg: registeredUser()}, io.Discard), administrator(t), grantPath, "application/json", permissionBody)
	if !strings.Contains(rec.Body.String(), `"email":"carlos.gomez@example.com"`) {
		t.Fatalf("%s", rec.Body)
	}
	for _, secret := range []string{"must-never-show", "Hash", "assword"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the answer shows %q: %s", secret, rec.Body)
		}
	}
}

func TestC_OnlyATenantAdministratorWithAnOrdinaryCredentialAssignsAndRemovesPermissions(t *testing.T) {
	for _, path := range []string{grantPath, removalPath} {
		for who, token := range map[string]string{
			"a collaborator":             tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""),
			"a manager":                  tokenWith(t, []string{"MANAGER"}, accountTenant, ""),
			"an accountant":              tokenWith(t, []string{"ACCOUNTANT"}, accountTenant, ""),
			"an analyst":                 tokenWith(t, []string{"ANALYST"}, accountTenant, ""),
			"a customer":                 tokenWith(t, []string{"FINAL_CUSTOMER"}, accountTenant, ""),
			"the Platform Administrator": tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""),
			"a temporary credential":     tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "password-change"),
			"a restricted credential":    tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "restricted"),
			"a token with no role":       tokenWith(t, nil, accountTenant, ""),
		} {
			svc := &fakePermissions{reg: registeredUser()}
			if rec := postPermission(permissionsHandler(svc, io.Discard), token, path, "application/json", permissionBody); rec.Code != http.StatusForbidden || len(svc.requests) != 0 {
				t.Errorf("%s, %s: %d, asked %d times", who, path, rec.Code, len(svc.requests))
			}
		}
		if rec := postPermission(permissionsHandler(&fakePermissions{}, io.Discard), "", path, "application/json", permissionBody); rec.Code != http.StatusUnauthorized {
			t.Fatalf("no token: %d", rec.Code)
		}
	}
}

func TestC_TheBodyIsJSONSmallAndHasNothingButThePermission(t *testing.T) {
	h := permissionsHandler(&fakePermissions{reg: registeredUser()}, io.Discard)
	if rec := postPermission(h, administrator(t), grantPath, "text/plain", permissionBody); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", rec.Code)
	}
	if rec := postPermission(h, administrator(t), grantPath, "application/json", `{"permission":"`+strings.Repeat("a", 5000)+`"}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large: %d", rec.Code)
	}
	for _, body := range []string{`{"permission":`, `{"permission":"MANAGE_CASH","tenantId":"` + otherTenantID + `"}`, `{"permission":"MANAGE_CASH","role":"MANAGER"}`,
		`{"permission":"MANAGE_CASH","reason":"x"}`, `{"permission":"MANAGE_CASH","permissions":["MANAGE_CASH"]}`} {
		svc := &fakePermissions{reg: registeredUser()}
		if rec := postPermission(permissionsHandler(svc, io.Discard), administrator(t), grantPath, "application/json", body); rec.Code != http.StatusBadRequest || len(svc.requests) != 0 {
			t.Errorf("%s: %d, asked %d times", body, rec.Code, len(svc.requests))
		}
	}
}

func TestC_EachRefusalOfThePermissionUseCaseIsItsOwnStatusAndNeverALeak(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"a permission outside the four": {&changepermission.FieldError{Field: "permission"}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"an account id that is not one": {&changepermission.FieldError{Field: "accountId"}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"a tenant that is not an id":    {&changepermission.FieldError{Field: "tenantId"}, http.StatusInternalServerError, "INTERNAL_ERROR"},
		"an actor that is not an id":    {&changepermission.FieldError{Field: "actorId"}, http.StatusInternalServerError, "INTERNAL_ERROR"},
		"a user that is not there":      {port.ErrUserNotFound, http.StatusNotFound, "NOT_FOUND"},
		"a profile permission":          {changepermission.ErrProfilePermission, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION"},
		"a role that may not hold it":   {changepermission.ErrNotAssignable, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION"},
		"a failure of ours":             {errors.New("pq: password=hunter2"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	} {
		var logs strings.Builder
		rec := postPermission(permissionsHandler(&fakePermissions{err: c.err}, &logs), administrator(t), grantPath, "application/json", permissionBody)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), `"error":"`+c.code+`"`) || strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(logs.String(), "hunter2") {
			t.Errorf("%s: %d %s | %s", name, rec.Code, rec.Body, logs.String())
		}
	}
}

func TestC_TheTwoUnprocessableRefusalsSayDifferentThingsAndNameNoValue(t *testing.T) {
	seen := map[string]bool{}
	for _, err := range []error{changepermission.ErrProfilePermission, changepermission.ErrNotAssignable} {
		rec := postPermission(permissionsHandler(&fakePermissions{err: err}, io.Discard), administrator(t), grantPath, "application/json", permissionBody)
		if seen[rec.Body.String()] || strings.Contains(rec.Body.String(), "MANAGE_CASH") {
			t.Fatalf("the same message for two reasons, or it repeats the value: %s", rec.Body)
		}
		seen[rec.Body.String()] = true
	}
}

func TestC_ARefusalNamesTheFieldAndSaysNothingOfTheValue(t *testing.T) {
	rec := postPermission(permissionsHandler(&fakePermissions{err: &changepermission.FieldError{Field: "permission"}}, io.Discard), administrator(t), grantPath,
		"application/json", `{"permission":"SUPERUSER"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"permission"`) || strings.Contains(rec.Body.String(), "SUPERUSER") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
