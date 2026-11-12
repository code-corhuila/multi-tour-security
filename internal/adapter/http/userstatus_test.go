package httpadapter_test

import (
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
	"github.com/code-corhuila/multi-tour-security/internal/core/changestatus"
	"github.com/code-corhuila/multi-tour-security/internal/core/listusers"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-005, RN-SEC-003-09 and -10: the routes that inactivate and reactivate an internal user of the tenant.

const (
	statusUser = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	inactivate = "/api/v1/security/users/" + statusUser + "/inactivation"
	reactivate = "/api/v1/security/users/" + statusUser + "/reactivation"
	reasonBody = `{"reason":"Left the company"}`
)

type fakeStatus struct {
	requests []changestatus.Request
	actions  []string
	reg      port.Registered
	err      error
}

func (f *fakeStatus) Inactivate(_ context.Context, r changestatus.Request) (port.Registered, error) {
	f.requests, f.actions = append(f.requests, r), append(f.actions, "inactivate")
	return f.reg, f.err
}

func (f *fakeStatus) Reactivate(_ context.Context, r changestatus.Request) (port.Registered, error) {
	f.requests, f.actions = append(f.requests, r), append(f.actions, "reactivate")
	return f.reg, f.err
}

func statusHandler(svc httpadapter.UserStatusChanger, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithChangeUserStatus(svc))
}

func postStatus(h http.Handler, token, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-Correlation-Id", "status-1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestC_TheRoutesAskTheUseCaseWithTheTenantAndTheActorOfTheTokenAndTheIdOfThePath(t *testing.T) {
	for path, action := range map[string]string{inactivate: "inactivate", reactivate: "reactivate"} {
		svc := &fakeStatus{reg: registeredUser()}
		rec := postStatus(statusHandler(svc, io.Discard), administrator(t), path, "application/json", reasonBody)
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %v %s", action, rec.Code, rec.Header(), rec.Body)
		}
		want := changestatus.Request{TenantID: accountTenant, AccountID: statusUser, ActorID: "worker-event-relay", Reason: "Left the company", CorrelationID: "status-1"}
		if len(svc.requests) != 1 || svc.requests[0] != want || svc.actions[0] != action {
			t.Fatalf("%s: the use case was asked %+v %v", action, svc.requests, svc.actions)
		}
	}
}

func TestC_TheAnswerIsTheUserAsItIsNowWithTheLastChangeAndNoSecret(t *testing.T) {
	reg := registeredUser()
	reg.Changed = port.StatusChange{At: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), By: "tenant-administrator/" + statusUser, Reason: "Left the company"}
	rec := postStatus(statusHandler(&fakeStatus{reg: reg}, io.Discard), administrator(t), inactivate, "application/json", reasonBody)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["statusChangedAt"] != "2026-11-03T12:00:00Z" || out["statusChangedBy"] != "tenant-administrator/"+statusUser || out["statusReason"] != "Left the company" {
		t.Fatalf("the answer is %s", rec.Body)
	}
	for _, secret := range []string{"must-never-show", "Hash", "password"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the answer shows %q", secret)
		}
	}
}

func TestC_AUserThatNeverChangedShowsNoTrace(t *testing.T) {
	rec := postStatus(statusHandler(&fakeStatus{reg: registeredUser()}, io.Discard), administrator(t), inactivate, "application/json", reasonBody)
	for _, field := range []string{"statusChangedAt", "statusChangedBy", "statusReason"} {
		if strings.Contains(rec.Body.String(), field) {
			t.Fatalf("a user that never changed shows %s: %s", field, rec.Body)
		}
	}
}

func TestC_TheListShowsTheLastChangeOfEachUser(t *testing.T) {
	reg := registeredUser()
	reg.Changed = port.StatusChange{At: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), By: "tenant-administrator/" + statusUser, Reason: "Left"}
	rec := getUsers(listHandler(&fakeLister{page: listusers.Page{Data: []port.Registered{reg}, Page: 1, Limit: 20, Total: 1, TotalPages: 1}}, io.Discard), administrator(t), "")
	if !strings.Contains(rec.Body.String(), `"statusReason":"Left"`) {
		t.Fatalf("%s", rec.Body)
	}
}

func TestC_ARefusalOfTheUseCaseIsItsOwnStatusAndNeverALeak(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"a reason that is not valid":   {&changestatus.FieldError{Field: "reason"}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"an account id not valid":      {&changestatus.FieldError{Field: "accountId"}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"a tenant that is not an id":   {&changestatus.FieldError{Field: "tenantId"}, http.StatusInternalServerError, "INTERNAL_ERROR"},
		"an actor that is not an id":   {&changestatus.FieldError{Field: "actorId"}, http.StatusInternalServerError, "INTERNAL_ERROR"},
		"a user that is not there":     {port.ErrUserNotFound, http.StatusNotFound, "NOT_FOUND"},
		"a status that cannot be made": {port.ErrStatusTransition, http.StatusUnprocessableEntity, "INVALID_STATUS_TRANSITION"},
		"the last administrator":       {port.ErrLastAdministrator, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION"},
		"a failure of ours":            {errors.New("pq: password=hunter2"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	} {
		var logs strings.Builder
		rec := postStatus(statusHandler(&fakeStatus{err: c.err}, &logs), administrator(t), inactivate, "application/json", reasonBody)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), `"error":"`+c.code+`"`) || strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(logs.String(), "hunter2") {
			t.Errorf("%s: %d %s | %s", name, rec.Code, rec.Body, logs.String())
		}
	}
}

func TestC_ARefusalNamesTheFieldOfTheUseCase(t *testing.T) {
	rec := postStatus(statusHandler(&fakeStatus{err: &changestatus.FieldError{Field: "reason"}}, io.Discard), administrator(t), inactivate, "application/json", `{"reason":""}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"reason"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_OnlyATenantAdministratorWithAnOrdinaryCredentialChangesAStatus(t *testing.T) {
	for _, path := range []string{inactivate, reactivate} {
		for who, token := range map[string]string{
			"a collaborator":             tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""),
			"a customer":                 tokenWith(t, []string{"FINAL_CUSTOMER"}, accountTenant, ""),
			"the Platform Administrator": tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""),
			"a temporary credential":     tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "password-change"),
		} {
			svc := &fakeStatus{reg: registeredUser()}
			if rec := postStatus(statusHandler(svc, io.Discard), token, path, "application/json", reasonBody); rec.Code != http.StatusForbidden || len(svc.requests) != 0 {
				t.Errorf("%s %s: %d, asked %d times", who, path, rec.Code, len(svc.requests))
			}
		}
		if rec := postStatus(statusHandler(&fakeStatus{}, io.Discard), "", path, "application/json", reasonBody); rec.Code != http.StatusUnauthorized {
			t.Fatalf("no token: %d", rec.Code)
		}
	}
}

func TestC_TheBodyIsJSONSmallAndHasNothingButTheReason(t *testing.T) {
	h := statusHandler(&fakeStatus{reg: registeredUser()}, io.Discard)
	if rec := postStatus(h, administrator(t), inactivate, "text/plain", reasonBody); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", rec.Code)
	}
	if rec := postStatus(h, administrator(t), inactivate, "application/json", `{"reason":"`+strings.Repeat("a", 5000)+`"}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large: %d", rec.Code)
	}
	for _, body := range []string{`{"reason":`, `{"reason":"x","actor":"someone"}`, `{"reason":"x","tenantId":"` + otherTenantID + `"}`, `{"reason":"x","status":"ACTIVE"}`} {
		svc := &fakeStatus{reg: registeredUser()}
		if rec := postStatus(statusHandler(svc, io.Discard), administrator(t), inactivate, "application/json", body); rec.Code != http.StatusBadRequest || len(svc.requests) != 0 {
			t.Errorf("%s: %d, asked %d times", body, rec.Code, len(svc.requests))
		}
	}
}
