package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportemergency"
)

// HU-SEC-007 part B, security spec 010: the route where the Platform Administrator opens an emergency access.

const (
	emergencyRoute = "/api/v1/security/platform-emergency-accesses"
	emergencyKey   = "emergency-key-0001"
	emergencyBody  = `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"Every cash of today shows a negative balance","statement":"No Administrator can sign in","areas":["CASH"],"hours":4}`
)

type fakeEmergency struct {
	opened  []supportemergency.Command
	access  supportaccess.Access
	created bool
	err     error
}

func (f *fakeEmergency) Open(_ context.Context, c supportemergency.Command) (supportaccess.Access, bool, error) {
	f.opened = append(f.opened, c)
	return f.access, f.created, f.err
}

func emergencyHandler(svc httpadapter.EmergencyOpener, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithEmergencyAccess(svc))
}

func openedEmergency(sensitive bool) supportaccess.Access {
	reason := ""
	if sensitive {
		reason = "The incident is about a passenger's medical record"
	}
	a, _ := supportaccess.NewEmergency("3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", "44444444-4444-4444-8444-444444444444", "Every cash of today shows a negative balance",
		"No Administrator can sign in", []string{"CASH"}, 4, sensitive, reason, time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC))
	a.ID = "55555555-5555-4555-8555-555555555555"
	return a
}

func TestC_AnEmergencyIsOpenedWithTheCallerNotTheBodyAndTheAnswerShowsItsBasis(t *testing.T) {
	svc := &fakeEmergency{access: openedEmergency(true), created: true}
	body := `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"Every cash of today shows a negative balance","statement":"No Administrator can sign in","areas":["CASH"],"hours":4,"sensitive":true,"sensitiveReason":"The incident is about a passenger's medical record"}`
	rec := supportCall(emergencyHandler(svc, io.Discard), http.MethodPost, emergencyRoute, platformAdminToken(t), "application/json", body, emergencyKey)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if len(svc.opened) != 1 {
		t.Fatalf("the use case got %+v", svc.opened)
	}
	got := svc.opened[0]
	if got.ActorID != "worker-event-relay" || got.TenantID != "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f" || got.Statement != "No Administrator can sign in" ||
		!got.Sensitive || got.SensitiveReason == "" || got.Hours != 4 || strings.Join(got.Areas, ",") != "CASH" || got.IdempotencyKey != emergencyKey || got.CorrelationID != "sup-1" {
		t.Fatalf("the use case got %+v", got)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["basis"] != "EMERGENCY" || out["status"] != "APPROVED" || out["sensitive"] != true || out["statement"] != "No Administrator can sign in" ||
		out["expiresAt"] != "2026-11-10T14:00:00Z" || out["openedAt"] != "2026-11-10T10:00:00Z" {
		t.Fatalf("the answer is %v", out)
	}
	if areas, _ := out["areas"].([]any); len(areas) != 1 || areas[0] != "CASH" {
		t.Errorf("the areas are the closed list without the sensitive word: %v", out["areas"])
	}
}

func TestC_AnAuthorizedAccessShowsItsBasisToo(t *testing.T) {
	svc := &fakeSupport{access: askedAccess(), created: true}
	rec := supportCall(supportHandler(svc, io.Discard), http.MethodPost, supportRoute, platformAdminToken(t), "application/json", supportBody, supportKey)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["basis"] != "TENANT_AUTHORIZATION" {
		t.Errorf("an access without a basis reads as the authorization: %v", out)
	}
	if _, has := out["statement"]; has {
		t.Errorf("only an emergency has a statement: %v", out)
	}
}

func TestC_TheSameKeyAnswersTheSameEmergencyWith200(t *testing.T) {
	svc := &fakeEmergency{access: openedEmergency(false)}
	rec := supportCall(emergencyHandler(svc, io.Discard), http.MethodPost, emergencyRoute, platformAdminToken(t), "application/json", emergencyBody, emergencyKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_OnlyThePlatformAdministratorWithoutAnAccessMarkOpensAnEmergency(t *testing.T) {
	for name, c := range map[string]struct {
		token string
		want  int
	}{
		"no credential":        {"", http.StatusUnauthorized},
		"tenant administrator": {adminOfTenant(t), http.StatusForbidden},
		"with an access mark":  {tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", "exceptional"), http.StatusForbidden},
	} {
		svc := &fakeEmergency{access: openedEmergency(false), created: true}
		rec := supportCall(emergencyHandler(svc, io.Discard), http.MethodPost, emergencyRoute, c.token, "application/json", emergencyBody, emergencyKey)
		if rec.Code != c.want || len(svc.opened) != 0 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestC_ABadEmergencyBodyIsRefusedBeforeTheUseCase(t *testing.T) {
	cases := map[string]struct {
		contentType, body string
		status            int
	}{
		"not json":              {"text/plain", emergencyBody, http.StatusUnsupportedMediaType},
		"broken json":           {"application/json", `{"tenantId":`, http.StatusBadRequest},
		"unknown field":         {"application/json", `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"x","statement":"y","areas":["CASH"],"hours":1,"actorId":"x"}`, http.StatusBadRequest},
		"sensitive not boolean": {"application/json", `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"x","statement":"y","areas":["CASH"],"hours":1,"sensitive":"yes"}`, http.StatusBadRequest},
	}
	for name, c := range cases {
		svc := &fakeEmergency{}
		rec := supportCall(emergencyHandler(svc, io.Discard), http.MethodPost, emergencyRoute, platformAdminToken(t), c.contentType, c.body, emergencyKey)
		if rec.Code != c.status || len(svc.opened) != 0 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestC_WhatTheUseCaseRefusesIsNamedAndTheOpenPairIs422(t *testing.T) {
	svc := &fakeEmergency{err: &supportemergency.FieldError{Field: "sensitiveReason", Err: errors.New("is not valid")}}
	rec := supportCall(emergencyHandler(svc, io.Discard), http.MethodPost, emergencyRoute, platformAdminToken(t), "application/json", emergencyBody, emergencyKey)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"sensitiveReason"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	svc = &fakeEmergency{err: supportemergency.ErrTenantNotFound}
	if rec := supportCall(emergencyHandler(svc, io.Discard), http.MethodPost, emergencyRoute, platformAdminToken(t), "application/json", emergencyBody, emergencyKey); rec.Code != http.StatusNotFound {
		t.Fatalf("not found: %d %s", rec.Code, rec.Body)
	}
	svc = &fakeEmergency{err: supportaccess.ErrOpenAccessExists}
	rec = supportCall(emergencyHandler(svc, io.Discard), http.MethodPost, emergencyRoute, platformAdminToken(t), "application/json", emergencyBody, emergencyKey)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "BUSINESS_RULE_VIOLATION") {
		t.Fatalf("open pair: %d %s", rec.Code, rec.Body)
	}
}

func TestC_AFailureOfTheEmergencyUseCaseIsAnInternalErrorWithNoDetail(t *testing.T) {
	var logs strings.Builder
	svc := &fakeEmergency{err: errors.New("pq: connection refused at db-host-9")}
	rec := supportCall(emergencyHandler(svc, &logs), http.MethodPost, emergencyRoute, platformAdminToken(t), "application/json", emergencyBody, emergencyKey)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "db-host-9") || strings.Contains(logs.String(), "db-host-9") ||
		!strings.Contains(logs.String(), "opening an emergency access failed") {
		t.Fatalf("%d %s / log %s", rec.Code, rec.Body, logs.String())
	}
}
