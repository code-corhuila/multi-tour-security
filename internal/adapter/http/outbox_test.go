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
	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
	"github.com/golang-jwt/jwt/v5"
)

const (
	outboxRoute   = "/api/v1/security/internal/outbox"
	outboxEventID = "6b9f2c1e-7a3d-4c58-9e10-2f4a8b7c6d5e"
	publishedPath = outboxRoute + "/" + outboxEventID + "/published"
	attemptsPath  = outboxRoute + "/" + outboxEventID + "/attempts"
)

var outboxNow = time.Date(2026, 10, 10, 10, 0, 0, 123456000, time.UTC)

func sampleEvent() outbox.Event {
	return outbox.Event{ID: outboxEventID, Type: "AccountBlocked", Version: 1, TenantID: "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f",
		AggregateID: "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b", Payload: json.RawMessage(`{"accountId":"a"}`), CorrelationID: "c-1",
		OccurredAt: outboxNow, Status: outbox.Pending, Attempts: 2, LastError: "503", NextAttemptAt: outboxNow.Add(20 * time.Second)}
}

type fakeOutbox struct {
	page                         outbox.Page
	event                        outbox.Event
	err                          error
	gotPage, gotLimit            int
	gotID, gotText               string
	listed, published, attempted int
}

func (f *fakeOutbox) ListDue(_ context.Context, page, limit int) (outbox.Page, error) {
	f.listed++
	f.gotPage, f.gotLimit = page, limit
	return f.page, f.err
}
func (f *fakeOutbox) MarkPublished(_ context.Context, id string) (outbox.Event, error) {
	f.published++
	f.gotID = id
	return f.event, f.err
}
func (f *fakeOutbox) RecordFailedAttempt(_ context.Context, id, text string) (outbox.Event, error) {
	f.attempted++
	f.gotID, f.gotText = id, text
	return f.event, f.err
}

func outboxHandler(svc httpadapter.OutboxService, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithOutbox(svc))
}

// serviceBearer signs the token of a worker: the role SERVICE, no tenant, no mark.
func serviceBearer(t *testing.T) string {
	t.Helper()
	return tokenWith(t, []string{"SERVICE"}, "", "")
}

func tokenWith(t *testing.T, roles []string, tenantID, access string) string {
	t.Helper()
	claims := jwt.MapClaims{"sub": "worker-event-relay", "roles": roles, "exp": time.Now().Add(time.Hour).Unix()}
	if tenantID != "" {
		claims["tenantId"] = tenantID
	}
	if access != "" {
		claims["access"] = access
	}
	return sign(t, jwt.SigningMethodRS256, routeKey, claims)
}

func call(h http.Handler, method, path, token, contentType, body, correlationID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if correlationID != "" {
		req.Header.Set("X-Correlation-Id", correlationID)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var internalCalls = []struct{ name, method, path, body string }{
	{"list", http.MethodGet, outboxRoute, ""},
	{"published", http.MethodPost, publishedPath, ""},
	{"attempts", http.MethodPost, attemptsPath, `{"error":"503"}`},
}

func TestC_OnlyTheTokenOfAServiceReachesTheInternalRoutesAndEveryOtherGetsTheSameAnswer(t *testing.T) {
	tenantID := "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	tokens := []struct {
		name, token string
		status      int
	}{
		{"no token", "", 401},
		{"not a token", "not-a-jwt", 401},
		{"the Platform Administrator", tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""), 403},
		{"a tenant administrator", tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, tenantID, ""), 403},
		{"a service with a tenant", tokenWith(t, []string{"SERVICE"}, tenantID, ""), 403},
		{"a service that is also something else", tokenWith(t, []string{"SERVICE", "ANALYST"}, "", ""), 403},
		{"a service with an access mark", tokenWith(t, []string{"SERVICE"}, "", "restricted"), 403},
		{"the token of a temporary credential", tokenWith(t, nil, tenantID, "password-change"), 403},
		{"lower-case role", tokenWith(t, []string{"service"}, "", ""), 403},
		{"a token with no roles", tokenWith(t, nil, "", ""), 403},
	}
	for _, c := range internalCalls {
		bodies := map[int]map[string]bool{401: {}, 403: {}}
		for _, tok := range tokens {
			svc := &fakeOutbox{event: sampleEvent()}
			rec := call(outboxHandler(svc, io.Discard), c.method, c.path, tok.token, "application/json", c.body, "same")
			if rec.Code != tok.status || svc.listed+svc.published+svc.attempted != 0 {
				t.Errorf("%s / %s: %d (want %d) %s", c.name, tok.name, rec.Code, tok.status, rec.Body)
				continue
			}
			bodies[tok.status][rec.Body.String()] = true
		}
		for status, set := range bodies {
			if len(set) != 1 {
				t.Errorf("%s: the %d answers differ: %v", c.name, status, set)
			}
		}
		var env envelope
		rec := call(outboxHandler(&fakeOutbox{}, io.Discard), c.method, c.path, tokens[2].token, "application/json", c.body, "")
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if env.Error != "FORBIDDEN" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: a role that is not allowed is FORBIDDEN: %s %v", c.name, rec.Body, rec.Header())
		}
	}
}

func TestC_TheListIsAPageOfEventsWithTheirDatesInUTCAndTheFieldsOfTheEnvelope(t *testing.T) {
	svc := &fakeOutbox{page: outbox.Page{Data: []outbox.Event{sampleEvent()}, Page: 2, Limit: 5, Total: 7, TotalPages: 2}}
	rec := call(outboxHandler(svc, io.Discard), http.MethodGet, outboxRoute+"?page=2&limit=5&status=PENDING", serviceBearer(t), "", "", "t-9")
	if rec.Code != http.StatusOK || svc.gotPage != 2 || svc.gotLimit != 5 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "t-9" {
		t.Fatalf("%d page %d limit %d %v", rec.Code, svc.gotPage, svc.gotLimit, rec.Header())
	}
	var got struct {
		Data []map[string]any `json:"data"`
		Meta map[string]any   `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Data) != 1 {
		t.Fatalf("%s %v", rec.Body, err)
	}
	e := got.Data[0]
	if e["eventId"] != outboxEventID || e["eventType"] != "AccountBlocked" || e["eventVersion"] != float64(1) || e["status"] != "PENDING" || e["attempts"] != float64(2) ||
		e["lastError"] != "503" || e["correlationId"] != "c-1" || e["occurredAt"] != "2026-10-10T10:00:00.123456Z" || e["nextAttemptAt"] != "2026-10-10T10:00:20.123456Z" ||
		e["tenantId"] != "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f" || e["payload"].(map[string]any)["accountId"] != "a" {
		t.Fatalf("event = %v", e)
	}
	if _, has := e["publishedAt"]; has {
		t.Errorf("a pending event has no publishedAt: %v", e)
	}
	if got.Meta["page"] != float64(2) || got.Meta["limit"] != float64(5) || got.Meta["total"] != float64(7) || got.Meta["totalPages"] != float64(2) {
		t.Fatalf("meta = %v", got.Meta)
	}
}

func TestC_TheListDefaultsTo20OfPage1AndAnEventWithoutTenantOmitsIt(t *testing.T) {
	e := sampleEvent()
	e.TenantID = ""
	svc := &fakeOutbox{page: outbox.Page{Data: []outbox.Event{e}, Page: 1, Limit: 20, Total: 1, TotalPages: 1}}
	rec := call(outboxHandler(svc, io.Discard), http.MethodGet, outboxRoute, serviceBearer(t), "", "", "")
	if rec.Code != http.StatusOK || svc.gotPage != 1 || svc.gotLimit != 20 || strings.Contains(rec.Body.String(), "tenantId") {
		t.Fatalf("%d page %d limit %d %s", rec.Code, svc.gotPage, svc.gotLimit, rec.Body)
	}
}

func TestC_ABadQueryIsA400AndNeverReachesTheUseCase(t *testing.T) {
	for _, q := range []string{"?page=0", "?page=abc", "?page=-1", "?limit=0", "?limit=101", "?limit=x", "?status=PUBLISHED", "?status=pending",
		"?filter=1", "?page=1&page=2", "?page=1&limit=20&extra=a", "?page=", "?page=99999999999999999999"} {
		svc := &fakeOutbox{}
		rec := call(outboxHandler(svc, io.Discard), http.MethodGet, outboxRoute+q, serviceBearer(t), "", "", "t-1")
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != http.StatusBadRequest || env.Error != "VALIDATION_ERROR" || env.TraceID != "t-1" || svc.listed != 0 {
			t.Errorf("%s: %d %s", q, rec.Code, rec.Body)
		}
	}
}

func TestC_AnEventIsMarkedPublishedAndAnUnknownOneIsA404(t *testing.T) {
	published := sampleEvent()
	published.Status = outbox.Published
	published.PublishedAt = outboxNow
	svc := &fakeOutbox{event: published}
	rec := call(outboxHandler(svc, io.Discard), http.MethodPost, publishedPath, serviceBearer(t), "", "", "")
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || svc.gotID != outboxEventID || got["status"] != "PUBLISHED" || got["publishedAt"] != "2026-10-10T10:00:00.123456Z" {
		t.Fatalf("%d %s id %q", rec.Code, rec.Body, svc.gotID)
	}
	rec = call(outboxHandler(&fakeOutbox{err: outbox.ErrNotFound}, io.Discard), http.MethodPost, publishedPath, serviceBearer(t), "", "", "")
	var env envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if rec.Code != http.StatusNotFound || env.Error != "NOT_FOUND" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_AFailedAttemptIsRecordedFromAStrictBody(t *testing.T) {
	failed := sampleEvent()
	svc := &fakeOutbox{event: failed}
	rec := call(outboxHandler(svc, io.Discard), http.MethodPost, attemptsPath, serviceBearer(t), "application/json", `{"error":"consumer said 503"}`, "")
	if rec.Code != http.StatusOK || svc.gotText != "consumer said 503" || svc.gotID != outboxEventID {
		t.Fatalf("%d %s %+v", rec.Code, rec.Body, svc)
	}
	big := `{"error":"` + strings.Repeat("e", 4200) + `"}`
	cases := []struct {
		name, contentType, body string
		err                     error
		status                  int
		code                    string
	}{
		{"bad JSON", "application/json", `{"error":`, nil, 400, "VALIDATION_ERROR"},
		{"missing field", "application/json", `{}`, nil, 400, "VALIDATION_ERROR"},
		{"unknown field", "application/json", `{"error":"x","a":1}`, nil, 400, "VALIDATION_ERROR"},
		{"invalid text", "application/json", `{"error":"x"}`, outbox.ErrInvalid, 400, "VALIDATION_ERROR"},
		{"unknown event", "application/json", `{"error":"x"}`, outbox.ErrNotFound, 404, "NOT_FOUND"},
		{"not JSON", "text/plain", `{"error":"x"}`, nil, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"too large", "application/json", big, nil, 413, "PAYLOAD_TOO_LARGE"},
		{"failure", "application/json", `{"error":"x"}`, errors.New("dial tcp 10.0.0.5: refused"), 500, "INTERNAL_ERROR"},
	}
	for _, c := range cases {
		svc := &fakeOutbox{event: failed, err: c.err}
		rec := call(outboxHandler(svc, io.Discard), http.MethodPost, attemptsPath, serviceBearer(t), c.contentType, c.body, "t-1")
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != c.status || env.Error != c.code || env.TraceID != "t-1" || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
		if c.err == nil && c.status != 200 && svc.attempted != 0 {
			t.Errorf("%s reached the use case", c.name)
		}
	}
}

func TestC_LogsShowNoErrorTextAndNoPayloadOfAnEvent(t *testing.T) {
	var logs bytes.Buffer
	secret := "consumer-error-with-private-text"
	svc := &fakeOutbox{event: sampleEvent(), err: errors.New("boom")}
	call(outboxHandler(svc, &logs), http.MethodPost, attemptsPath, serviceBearer(t), "application/json", `{"error":"`+secret+`"}`, "")
	call(outboxHandler(&fakeOutbox{page: outbox.Page{Data: []outbox.Event{sampleEvent()}}}, &logs), http.MethodGet, outboxRoute, serviceBearer(t), "", "", "")
	if logs.Len() == 0 || strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), "accountId") {
		t.Fatalf("the log must exist and hold neither the error text nor a payload: %s", logs.String())
	}
}

func TestC_WithoutTheUseCaseTheInternalRoutesDoNotExist(t *testing.T) {
	rec := call(newHandler(newKey(t)), http.MethodGet, outboxRoute, serviceBearer(t), "", "", "")
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}
