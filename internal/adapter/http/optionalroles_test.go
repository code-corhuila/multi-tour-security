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
	"github.com/code-corhuila/multi-tour-security/internal/core/optionalrole"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-006, RN-SEC-005-01, -02, -12 and -13: the routes of the optional roles of a tenant.

const (
	rolesPath   = "/api/v1/security/optional-roles"
	enablePath  = rolesPath + "/MANAGER/enablement"
	disablePath = rolesPath + "/MANAGER/disablement"
)

type fakeRoles struct {
	queries  []optionalrole.Query
	requests []optionalrole.Request
	actions  []string
	states   []port.OptionalRoleState
	state    port.OptionalRoleState
	err      error
}

func (f *fakeRoles) List(_ context.Context, q optionalrole.Query) ([]port.OptionalRoleState, error) {
	f.queries = append(f.queries, q)
	return f.states, f.err
}

func (f *fakeRoles) Enable(_ context.Context, r optionalrole.Request) (port.OptionalRoleState, error) {
	f.requests, f.actions = append(f.requests, r), append(f.actions, "enable")
	return f.state, f.err
}

func (f *fakeRoles) Disable(_ context.Context, r optionalrole.Request) (port.OptionalRoleState, error) {
	f.requests, f.actions = append(f.requests, r), append(f.actions, "disable")
	return f.state, f.err
}

func rolesHandler(svc httpadapter.OptionalRoleManager, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithOptionalRoles(svc))
}

func callRoles(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Correlation-Id", "roles-1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func threeRoles() []port.OptionalRoleState {
	return []port.OptionalRoleState{
		{Role: "MANAGER", Enabled: true, ChangedAt: time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC), ChangedBy: "tenant-administrator/" + statusUser},
		{Role: "ACCOUNTANT"}, {Role: "ANALYST"},
	}
}

func TestC_TheListAnswersTheThreeRolesInOrderForTheTenantOfTheTokenAndNoOtherField(t *testing.T) {
	svc := &fakeRoles{states: threeRoles()}
	rec := callRoles(rolesHandler(svc, io.Discard), http.MethodGet, rolesPath, administrator(t))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "roles-1" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if len(svc.queries) != 1 || svc.queries[0] != (optionalrole.Query{TenantID: accountTenant}) {
		t.Fatalf("the use case was asked %+v", svc.queries)
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Data) != 3 {
		t.Fatalf("%s %v", rec.Body, err)
	}
	if out.Data[0]["role"] != "MANAGER" || out.Data[0]["enabled"] != true || out.Data[0]["changedAt"] != "2026-11-05T11:00:00Z" ||
		out.Data[1]["role"] != "ACCOUNTANT" || out.Data[1]["enabled"] != false || out.Data[2]["role"] != "ANALYST" {
		t.Fatalf("%s", rec.Body)
	}
	if _, has := out.Data[1]["changedAt"]; has {
		t.Fatalf("a role that never changed shows no change: %s", rec.Body)
	}
	for _, query := range []string{"?tenantId=" + otherTenantID} {
		if rec := callRoles(rolesHandler(&fakeRoles{states: threeRoles()}, io.Discard), http.MethodGet, rolesPath+query, administrator(t)); rec.Code != http.StatusOK {
			t.Errorf("the list takes no parameter and the tenant is the token's: %d", rec.Code)
		}
	}
}

func TestC_EnablingAndDisablingAskTheUseCaseWithTheTenantAndTheActorOfTheTokenAndTheRoleOfThePath(t *testing.T) {
	for path, action := range map[string]string{enablePath: "enable", disablePath: "disable"} {
		svc := &fakeRoles{state: threeRoles()[0]}
		rec := callRoles(rolesHandler(svc, io.Discard), http.MethodPost, path, administrator(t))
		want := optionalrole.Request{TenantID: accountTenant, ActorID: "worker-event-relay", Role: "MANAGER", CorrelationID: "roles-1"}
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || len(svc.requests) != 1 || svc.requests[0] != want || svc.actions[0] != action {
			t.Fatalf("%s: %d %v asked %+v", action, rec.Code, rec.Header(), svc.requests)
		}
		if !strings.Contains(rec.Body.String(), `"role":"MANAGER"`) || !strings.Contains(rec.Body.String(), `"enabled":true`) {
			t.Fatalf("%s: %s", action, rec.Body)
		}
	}
}

func TestC_OnlyATenantAdministratorWithAnOrdinaryCredentialSeesAndChangesTheOptionalRoles(t *testing.T) {
	for _, route := range []struct{ method, path string }{{http.MethodGet, rolesPath}, {http.MethodPost, enablePath}, {http.MethodPost, disablePath}} {
		for who, token := range map[string]string{
			"a collaborator":             tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""),
			"a manager":                  tokenWith(t, []string{"MANAGER"}, accountTenant, ""),
			"a customer":                 tokenWith(t, []string{"FINAL_CUSTOMER"}, accountTenant, ""),
			"the Platform Administrator": tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""),
			"a temporary credential":     tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "password-change"),
			"a restricted credential":    tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "restricted"),
			"a token with no role":       tokenWith(t, nil, accountTenant, ""),
		} {
			svc := &fakeRoles{states: threeRoles(), state: threeRoles()[0]}
			if rec := callRoles(rolesHandler(svc, io.Discard), route.method, route.path, token); rec.Code != http.StatusForbidden || len(svc.queries)+len(svc.requests) != 0 {
				t.Errorf("%s, %s %s: %d", who, route.method, route.path, rec.Code)
			}
		}
		if rec := callRoles(rolesHandler(&fakeRoles{}, io.Discard), route.method, route.path, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("no token, %s: %d", route.path, rec.Code)
		}
	}
}

func TestC_EachRefusalOfTheOptionalRoleUseCaseIsItsOwnStatusAndNeverALeak(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"a role outside the three":     {&optionalrole.FieldError{Field: "role"}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"a tenant that is not an id":   {&optionalrole.FieldError{Field: "tenantId"}, http.StatusInternalServerError, "INTERNAL_ERROR"},
		"an actor that is not an id":   {&optionalrole.FieldError{Field: "actorId"}, http.StatusInternalServerError, "INTERNAL_ERROR"},
		"a change that cannot be made": {port.ErrStatusTransition, http.StatusUnprocessableEntity, "INVALID_STATUS_TRANSITION"},
		"a role with an active holder": {port.ErrRoleInUse, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION"},
		"a failure of ours":            {errors.New("pq: password=hunter2"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	} {
		for _, path := range []string{enablePath, disablePath} {
			var logs strings.Builder
			rec := callRoles(rolesHandler(&fakeRoles{err: c.err}, &logs), http.MethodPost, path, administrator(t))
			if rec.Code != c.status || !strings.Contains(rec.Body.String(), `"error":"`+c.code+`"`) || strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(logs.String(), "hunter2") {
				t.Errorf("%s, %s: %d %s | %s", name, path, rec.Code, rec.Body, logs.String())
			}
		}
	}
	var logs strings.Builder
	if rec := callRoles(rolesHandler(&fakeRoles{err: errors.New("pq: password=hunter2")}, &logs), http.MethodGet, rolesPath, administrator(t)); rec.Code != http.StatusInternalServerError ||
		strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(logs.String(), "hunter2") {
		t.Errorf("the list: %d %s | %s", rec.Code, rec.Body, logs.String())
	}
}

func TestC_ARoleOutsideTheThreeIsA400NamingTheFieldAndNeverTheValue(t *testing.T) {
	rec := callRoles(rolesHandler(&fakeRoles{err: &optionalrole.FieldError{Field: "role"}}, io.Discard), http.MethodPost, rolesPath+"/SUPERUSER/enablement", administrator(t))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"role"`) || strings.Contains(rec.Body.String(), "SUPERUSER") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_TheTwoUnprocessableRefusalsOfARoleSayDifferentThings(t *testing.T) {
	seen := map[string]bool{}
	for _, err := range []error{port.ErrStatusTransition, port.ErrRoleInUse} {
		rec := callRoles(rolesHandler(&fakeRoles{err: err}, io.Discard), http.MethodPost, disablePath, administrator(t))
		if seen[rec.Body.String()] {
			t.Fatalf("the same answer for two reasons: %s", rec.Body)
		}
		seen[rec.Body.String()] = true
	}
}
