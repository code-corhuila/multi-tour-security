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
	adminRoute = "/api/v1/security/internal/tenants/" + accountTenant + "/administrators"
	adminKey   = "onboard-1:create-admin"
	adminBody  = `{"fullName":"Laura Perez","email":"Laura.Perez@Example.com","password":"Viaje-2026!"}`
)

func adminHandler(svc httpadapter.AccountCreator, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithCreateFirstAdministrator(svc))
}

func postAdmin(h http.Handler, path, token, contentType, body, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Correlation-Id", "adm-1")
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

func temporaryAdmin() port.Registered {
	reg := registered()
	reg.Role = "TENANT_ADMINISTRATOR"
	reg.Account.TemporaryUntil = time.Date(2026, 10, 14, 15, 4, 5, 0, time.UTC)
	return reg
}

func TestC_TheFirstAdministratorRouteHandsTheUseCaseTheTenantOfThePathAndTheServiceAsActor(t *testing.T) {
	svc := &fakeCreator{reg: temporaryAdmin(), created: true}
	rec := postAdmin(adminHandler(svc, io.Discard), adminRoute, serviceBearer(t), "application/json", adminBody, adminKey)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	want := createaccount.Command{Kind: createaccount.FirstAdministrator, TenantID: accountTenant, FullName: "Laura Perez",
		Email: "Laura.Perez@Example.com", Password: "Viaje-2026!", Actor: "worker-event-relay", IdempotencyKey: adminKey}
	if len(svc.commands) != 1 || svc.commands[0] != want {
		t.Fatalf("the use case got %+v", svc.commands)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	roles, _ := got["roles"].([]any)
	if got["temporaryCredentialUntil"] != "2026-10-14T15:04:05Z" || len(roles) != 1 || roles[0] != "TENANT_ADMINISTRATOR" || got["tenantId"] != accountTenant {
		t.Fatalf("the answer shows the role and when the temporary credential ends: %v", got)
	}
	for _, secret := range []string{"Viaje-2026!", "must-never-show"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the answer carries a credential: %s", rec.Body)
		}
	}
}

func TestC_ARepeatOfTheFirstAdministratorIsA200(t *testing.T) {
	rec := postAdmin(adminHandler(&fakeCreator{reg: temporaryAdmin()}, io.Discard), adminRoute, serviceBearer(t), "application/json", adminBody, adminKey)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), accountID) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_OnlyTheTokenOfAServiceCreatesTheFirstAdministrator(t *testing.T) {
	for name, token := range map[string]string{
		"no token":      "",
		"bad token":     "not-a-jwt",
		"person":        tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, ""),
		"platform":      tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""),
		"service+extra": tokenWith(t, []string{"SERVICE", "ANALYST"}, "", ""),
	} {
		svc := &fakeCreator{reg: temporaryAdmin(), created: true}
		rec := postAdmin(adminHandler(svc, io.Discard), adminRoute, token, "application/json", adminBody, adminKey)
		want := http.StatusForbidden
		if token == "" || token == "not-a-jwt" {
			want = http.StatusUnauthorized
		}
		if rec.Code != want || len(svc.commands) != 0 {
			t.Errorf("%s: %d, %d commands", name, rec.Code, len(svc.commands))
		}
	}
}

func TestC_ATenantIdThatIsNotAUUIDIs400AndReachesNoStore(t *testing.T) {
	svc := &fakeCreator{}
	rec := postAdmin(adminHandler(svc, io.Discard), "/api/v1/security/internal/tenants/not-a-uuid/administrators", serviceBearer(t), "application/json", adminBody, adminKey)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenantId") || len(svc.commands) != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_TheBodyOfTheFirstAdministratorIsStrict(t *testing.T) {
	for name, c := range map[string]struct {
		contentType, body string
		code              int
	}{
		"malformed":     {"application/json", `{"fullName":`, 400},
		"unknown field": {"application/json", `{"fullName":"A","email":"a@b.co","password":"Viaje-2026!","role":"MANAGER"}`, 400},
		"wrong media":   {"text/plain", adminBody, 415},
		"too large":     {"application/json", `{"fullName":"` + strings.Repeat("a", 4200) + `"}`, 413},
	} {
		svc := &fakeCreator{}
		rec := postAdmin(adminHandler(svc, io.Discard), adminRoute, serviceBearer(t), c.contentType, c.body, adminKey)
		if rec.Code != c.code || len(svc.commands) != 0 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestC_EveryRefusalOfTheUseCaseOnTheFirstAdministratorIsTranslated(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		code int
		kind string
	}{
		{"field", &createaccount.FieldError{Field: "fullName", Err: errors.New("is required")}, 400, "VALIDATION_ERROR"},
		{"e-mail in use", port.ErrEmailTaken, 422, "BUSINESS_RULE_VIOLATION"},
		{"driver", errors.New("connection refused to 10.0.0.5"), 500, "INTERNAL_ERROR"},
	} {
		rec := postAdmin(adminHandler(&fakeCreator{err: c.err}, io.Discard), adminRoute, serviceBearer(t), "application/json", adminBody, adminKey)
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.kind) || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
		if c.code == 422 && !strings.Contains(rec.Body.String(), `"details":[{"field":"email","message":"already in use"}]`) {
			t.Errorf("%s: the 422 names the e-mail: %s", c.name, rec.Body)
		}
	}
}
