package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/jwt"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// End to end against PostgreSQL through HTTP, with the token a real service gets: job 7 reads, delivers and reports
// (ADR-004 D4, RN-SEC-001-07).

const outboxURL = "/api/v1/security/internal/outbox"

type outboxEvent struct {
	EventID       string         `json:"eventId"`
	EventType     string         `json:"eventType"`
	TenantID      string         `json:"tenantId"`
	AggregateID   string         `json:"aggregateId"`
	Payload       map[string]any `json:"payload"`
	CorrelationID string         `json:"correlationId"`
	Status        string         `json:"status"`
	Attempts      int            `json:"attempts"`
	LastError     string         `json:"lastError"`
	PublishedAt   string         `json:"publishedAt"`
}

type outboxPage struct {
	Data []outboxEvent `json:"data"`
	Meta struct{ Page, Limit, Total, TotalPages int }
}

// serviceToken is what the service gives a worker: the same issuer, the same key, the role SERVICE and no tenant.
func (s *stack) serviceToken(t *testing.T) string {
	t.Helper()
	claims, err := token.Service("worker-event-relay", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwtadapter.NewSigner(s.private).Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (s *stack) call(method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Correlation-Id", "e2e-outbox")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

// dueEventually waits for the first event to be due: it becomes due at the instant the database wrote it, by the clock
// of the database, and the service reads it with its own, which can differ by a few milliseconds.
func (s *stack) dueEventually(t *testing.T) outboxPage {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		page := s.due(t)
		if len(page.Data) > 0 || time.Now().After(deadline) {
			return page
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *stack) due(t *testing.T) outboxPage {
	t.Helper()
	rec := s.call(http.MethodGet, outboxURL, s.serviceToken(t), "")
	var page outboxPage
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	return page
}

func TestC_AWorkerReadsTheEventsTheServiceLeftDeliversThemAndTheyLeaveTheList(t *testing.T) {
	s := newStack(t)
	account := s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	for i := 0; i < 5; i++ {
		s.signIn(tenantURL, "ana@example.com", "wrong")
	}
	page := s.dueEventually(t)
	if page.Meta.Total != 1 || len(page.Data) != 1 {
		t.Fatalf("one event waits: %+v", page)
	}
	e := page.Data[0]
	if e.EventType != "AccountBlocked" || e.TenantID != tenantA || e.AggregateID != account || e.Status != "PENDING" || e.CorrelationID != "e2e-1" ||
		e.Payload["accountId"] != account {
		t.Fatalf("event = %+v", e)
	}
	rec := s.call(http.MethodPost, outboxURL+"/"+e.EventID+"/published", s.serviceToken(t), "")
	var published outboxEvent
	_ = json.Unmarshal(rec.Body.Bytes(), &published)
	if rec.Code != http.StatusOK || published.Status != "PUBLISHED" || published.PublishedAt == "" {
		t.Fatalf("mark published: %d %s", rec.Code, rec.Body)
	}
	if again := s.call(http.MethodPost, outboxURL+"/"+e.EventID+"/published", s.serviceToken(t), ""); again.Code != http.StatusOK {
		t.Fatalf("a repeat is a 200: %d", again.Code)
	}
	if page := s.due(t); page.Meta.Total != 0 || len(page.Data) != 0 {
		t.Fatalf("a published event leaves the list: %+v", page)
	}
}

func TestC_TwentyFailedReportsGiveTheEventUpAndItLeavesTheList(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	for i := 0; i < 5; i++ {
		s.signIn(tenantURL, "ana@example.com", "wrong")
	}
	id := s.dueEventually(t).Data[0].EventID
	var last outboxEvent
	for i := 0; i < 20; i++ {
		rec := s.call(http.MethodPost, outboxURL+"/"+id+"/attempts", s.serviceToken(t), `{"error":"consumer answered 503"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("report %d: %d %s", i+1, rec.Code, rec.Body)
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &last)
	}
	if last.Status != "FAILED" || last.Attempts != 20 || last.LastError != "consumer answered 503" {
		t.Fatalf("%+v", last)
	}
	if page := s.due(t); page.Meta.Total != 0 {
		t.Fatalf("a given-up event leaves the list: %+v", page)
	}
	if rec := s.call(http.MethodPost, outboxURL+"/"+id+"/attempts", s.serviceToken(t), `{"error":"late"}`); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "late") {
		t.Fatalf("a late report does not touch it: %d %s", rec.Code, rec.Body)
	}
}

func TestC_ARetriedEventIsNotDueUntilItsWaitHasPassed(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	for i := 0; i < 5; i++ {
		s.signIn(tenantURL, "ana@example.com", "wrong")
	}
	id := s.dueEventually(t).Data[0].EventID
	if rec := s.call(http.MethodPost, outboxURL+"/"+id+"/attempts", s.serviceToken(t), `{"error":"503"}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	if page := s.due(t); page.Meta.Total != 0 {
		t.Fatalf("after a failure the event waits 5 seconds: %+v", page)
	}
}

func TestC_NoTokenThatIsNotAServiceReachesTheInternalRoutes(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	s.account(t, "", "root@example.com", pgtest.Options{}, "PLATFORM_ADMINISTRATOR")
	s.account(t, tenantA, "new@example.com", pgtest.Options{TemporaryUntil: time.Now().Add(time.Hour)}, "ANALYST")
	tenantToken, _ := s.claims(t, s.signIn(tenantURL, "ana@example.com", password))
	platformToken, _ := s.claims(t, s.signIn(rootURL, "root@example.com", password))
	changeToken, _ := s.claims(t, s.signIn(tenantURL, "new@example.com", password))
	for name, tok := range map[string]string{"a tenant administrator": tenantToken.AccessToken, "the Platform Administrator": platformToken.AccessToken,
		"a temporary credential": changeToken.AccessToken} {
		if rec := s.call(http.MethodGet, outboxURL, tok, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if rec := s.call(http.MethodGet, outboxURL, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
}

func TestC_TheEventOfAFirstPasswordIsInTheListAndNoPasswordIsInTheLogs(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "new@example.com", pgtest.Options{TemporaryUntil: time.Now().Add(time.Hour)}, "TENANT_ADMINISTRATOR")
	a, _ := s.claims(t, s.signIn(tenantURL, "new@example.com", password))
	if rec := s.changePassword(a.AccessToken, chosen); rec.Code != http.StatusNoContent {
		t.Fatalf("%d", rec.Code)
	}
	page := s.dueEventually(t)
	if len(page.Data) != 1 || page.Data[0].EventType != "AccountSessionsRevoked" {
		t.Fatalf("%+v", page)
	}
	for _, secret := range []string{chosen, password, a.AccessToken} {
		if strings.Contains(s.logs.String(), secret) {
			t.Errorf("the log shows a secret")
		}
	}
}
