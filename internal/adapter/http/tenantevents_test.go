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
	"github.com/code-corhuila/multi-tour-security/internal/core/tenantevent"
)

const (
	eventTenant = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	eventKey    = "6b9f2c1e-7a3d-4c58-9e10-2f4a8b7c6d5e"
	eventsPath  = "/api/v1/security/internal/tenants/" + eventTenant + "/events"
)

func envelopeJSON(kind, status string) string {
	return `{"eventId":"` + eventKey + `","eventType":"` + kind + `","eventVersion":1,"tenantId":"` + eventTenant + `","aggregateId":"` + eventTenant +
		`","actorId":"acc-9","reason":"payment overdue","correlationId":"c-1","occurredAt":"2026-10-10T10:00:00.5Z",` +
		`"payload":{"tenantId":"` + eventTenant + `","identifier":"travesia-natural","commercialName":"Travesía Natural SAS","tenantStatus":"` + status + `","country":"CO"}}`
}

type fakeTenantEvents struct {
	got     []tenantevent.Event
	applied bool
	err     error
}

func (f *fakeTenantEvents) Receive(_ context.Context, e tenantevent.Event) (bool, error) {
	f.got = append(f.got, e)
	return f.applied, f.err
}

func eventsHandler(svc httpadapter.TenantEventService, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithTenantEvents(svc))
}

func deliver(h http.Handler, token, key, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, eventsPath, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-Correlation-Id", "t-ev")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestC_AnAppliedEventIsA201AndARepeatOrAnOlderOneIsA200BothWithNoBody(t *testing.T) {
	for applied, status := range map[bool]int{true: http.StatusCreated, false: http.StatusOK} {
		svc := &fakeTenantEvents{applied: applied}
		rec := deliver(eventsHandler(svc, io.Discard), serviceBearer(t), eventKey, "application/json", envelopeJSON("TenantInactivated", "INACTIVE"))
		if rec.Code != status || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "t-ev" {
			t.Errorf("applied=%v: %d %q %v", applied, rec.Code, rec.Body, rec.Header())
		}
		want := tenantevent.Event{PathTenantID: eventTenant, EventID: eventKey, Type: "TenantInactivated", Version: 1, TenantID: eventTenant, AggregateID: eventTenant,
			PayloadTenantID: eventTenant, Identifier: "travesia-natural", Status: "INACTIVE", OccurredAt: time.Date(2026, 10, 10, 10, 0, 0, 500000000, time.UTC)}
		if len(svc.got) != 1 || svc.got[0] != want {
			t.Errorf("the use case got %+v", svc.got)
		}
	}
}

func TestC_OnlyTheTokenOfAServiceDeliversEvents(t *testing.T) {
	for name, c := range map[string]struct {
		token  string
		status int
	}{
		"no token":          {"", 401},
		"the platform":      {tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""), 403},
		"a tenant":          {tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, eventTenant, ""), 403},
		"a service":         {serviceBearer(t), 201},
		"a service + other": {tokenWith(t, []string{"SERVICE", "ANALYST"}, "", ""), 403},
	} {
		svc := &fakeTenantEvents{applied: true}
		rec := deliver(eventsHandler(svc, io.Discard), c.token, eventKey, "application/json", envelopeJSON("TenantCreated", "ACTIVE"))
		if rec.Code != c.status || (c.status != 201 && len(svc.got) != 0) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestC_TheIdempotencyKeyIsTheIdOfTheEvent(t *testing.T) {
	for name, key := range map[string]string{"missing": "", "too short": "6b9f2c1", "another id": "00000000-0000-4000-8000-000000000000", "too long": strings.Repeat("k", 129)} {
		svc := &fakeTenantEvents{applied: true}
		rec := deliver(eventsHandler(svc, io.Discard), serviceBearer(t), key, "application/json", envelopeJSON("TenantCreated", "ACTIVE"))
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != http.StatusBadRequest || env.Error != "VALIDATION_ERROR" || len(svc.got) != 0 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestC_ABodyThatIsNotAnEnvelopeIsA400A415OrA413AndOneThatIsTooBigForTheLimitOnlyJustFits(t *testing.T) {
	cases := []struct {
		name, contentType, body string
		status                  int
		code                    string
	}{
		{"bad JSON", "application/json", `{"eventId":`, 400, "VALIDATION_ERROR"},
		{"wrong type", "application/json", strings.Replace(envelopeJSON("TenantCreated", "ACTIVE"), `"eventVersion":1`, `"eventVersion":"1"`, 1), 400, "VALIDATION_ERROR"},
		{"bad instant", "application/json", strings.Replace(envelopeJSON("TenantCreated", "ACTIVE"), "2026-10-10T10:00:00.5Z", "yesterday", 1), 400, "VALIDATION_ERROR"},
		{"payload that is not an object", "application/json", strings.Replace(envelopeJSON("TenantCreated", "ACTIVE"), `"payload":{`, `"payload":[{`, 1), 400, "VALIDATION_ERROR"},
		{"not JSON", "text/plain", envelopeJSON("TenantCreated", "ACTIVE"), 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"over 16 KB", "application/json", strings.Replace(envelopeJSON("TenantCreated", "ACTIVE"), `"country":"CO"`, `"notes":"`+strings.Repeat("n", 17000)+`"`, 1), 413, "PAYLOAD_TOO_LARGE"},
	}
	for _, c := range cases {
		svc := &fakeTenantEvents{applied: true}
		rec := deliver(eventsHandler(svc, io.Discard), serviceBearer(t), eventKey, c.contentType, c.body)
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != c.status || env.Error != c.code || env.TraceID != "t-ev" || len(svc.got) != 0 {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
	}
	svc := &fakeTenantEvents{applied: true}
	big := strings.Replace(envelopeJSON("TenantCreated", "ACTIVE"), `"country":"CO"`, `"notes":"`+strings.Repeat("n", 9000)+`"`, 1)
	if rec := deliver(eventsHandler(svc, io.Discard), serviceBearer(t), eventKey, "application/json", big); rec.Code != http.StatusCreated {
		t.Errorf("an envelope of 9 KB, with the full state of the tenant, fits: %d", rec.Code)
	}
}

func TestC_TheAnswersOfTheUseCaseBecomeTheirStatusAndNoCauseIsShown(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"invalid", tenantevent.ErrInvalid, 400, "VALIDATION_ERROR"},
		{"retry later", tenantevent.ErrRetryLater, 503, "SERVICE_UNAVAILABLE"},
		{"failure", errors.New("dial tcp 10.0.0.5: refused"), 500, "INTERNAL_ERROR"},
	}
	for _, c := range cases {
		rec := deliver(eventsHandler(&fakeTenantEvents{err: c.err}, io.Discard), serviceBearer(t), eventKey, "application/json", envelopeJSON("TenantCreated", "ACTIVE"))
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != c.status || env.Error != c.code || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
		if c.status == 503 && rec.Header().Get("Retry-After") == "" {
			t.Errorf("a 503 tells when to come back")
		}
	}
}

func TestC_LogsHoldNoPayloadOfAnEvent(t *testing.T) {
	var logs bytes.Buffer
	token := serviceBearer(t)
	for _, err := range []error{nil, tenantevent.ErrInvalid, tenantevent.ErrRetryLater, errors.New("boom")} {
		deliver(eventsHandler(&fakeTenantEvents{err: err}, &logs), token, eventKey, "application/json", envelopeJSON("TenantCreated", "ACTIVE"))
	}
	for _, secret := range []string{"Travesía", "payment overdue", "travesia-natural", token} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log holds %q", secret)
		}
	}
	if !strings.Contains(logs.String(), "held back") || !strings.Contains(logs.String(), eventKey) {
		t.Fatalf("an event that stays held back is visible to the operator, by its id: %s", logs.String())
	}
}

func TestC_TheInstantMayCarryAnyOffsetAndTheVersionMustBeANumber(t *testing.T) {
	zone := strings.Replace(envelopeJSON("TenantCreated", "ACTIVE"), "2026-10-10T10:00:00.5Z", "2026-10-10T05:00:00.5-05:00", 1)
	svc := &fakeTenantEvents{applied: true}
	if rec := deliver(eventsHandler(svc, io.Discard), serviceBearer(t), eventKey, "application/json", zone); rec.Code != http.StatusCreated ||
		!svc.got[0].OccurredAt.Equal(time.Date(2026, 10, 10, 10, 0, 0, 500000000, time.UTC)) {
		t.Fatalf("%d %+v", rec.Code, svc.got)
	}
}

func TestC_WithoutTheTenantEventsUseCaseTheRouteDoesNotExist(t *testing.T) {
	rec := deliver(newHandler(newKey(t)), serviceBearer(t), eventKey, "application/json", envelopeJSON("TenantCreated", "ACTIVE"))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestC_TheCommercialNameOfThePayloadReachesTheUseCase(t *testing.T) {
	svc := &fakeTenantEvents{applied: true}
	rec := deliver(eventsHandler(svc, io.Discard), serviceBearer(t), eventKey, "application/json", envelopeJSON("TenantCreated", "ACTIVE"))
	if rec.Code != http.StatusCreated || len(svc.got) != 1 || svc.got[0].CommercialName != "Travesía Natural SAS" {
		t.Fatalf("%d %+v", rec.Code, svc.got)
	}
}
