package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// End to end against PostgreSQL through HTTP, as job 7 delivers it: the status of a tenant reaches the sign-in
// (RN-SEC-001-10, -11; ADR-004 D4 and D5).

const (
	tenantZ = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	tenantW = "6b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e"
)

var eventSeq int

// deliver sends one event of a tenant: its own id, the instant it happened and the full state in its payload.
func (s *stack) deliver(token, tenantID, kind, identifier, status string, at time.Time) *httptest.ResponseRecorder {
	eventSeq++
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", eventSeq)
	body := fmt.Sprintf(`{"eventId":"%s","eventType":"%s","eventVersion":1,"tenantId":"%s","aggregateId":"%s","actorId":"a","correlationId":"c-ev",`+
		`"occurredAt":"%s","payload":{"tenantId":"%s","identifier":"%s","commercialName":"Nueva Agencia SAS","tenantStatus":"%s","country":"CO"}}`,
		id, kind, tenantID, tenantID, at.UTC().Format(time.RFC3339Nano), tenantID, identifier, status)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/internal/tenants/"+tenantID+"/events", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", id)
	req.Header.Set("X-Correlation-Id", "e2e-ev")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func signInAt(s *stack, identifier, email string) *httptest.ResponseRecorder {
	return s.signIn("/api/v1/security/public/tenants/"+identifier+"/sessions", email, password)
}

func TestC_ATenantExistsForTheSignInOnlyWhenItsEventsSayAndFollowsThemInOrder(t *testing.T) {
	s := newStack(t)
	svc := s.serviceToken(t)
	s.account(t, tenantZ, "boss@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	s.account(t, tenantZ, "ana@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	t0 := time.Now().Add(-time.Hour)

	if rec := signInAt(s, "nueva-agencia", "boss@example.com"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a tenant nobody told the service about: %d", rec.Code)
	}
	if rec := s.deliver(svc, tenantZ, "TenantCreated", "nueva-agencia", "PENDING", t0); rec.Code != http.StatusCreated {
		t.Fatalf("created: %d %s", rec.Code, rec.Body)
	}
	if rec := signInAt(s, "nueva-agencia", "boss@example.com"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a pending tenant is not open: %d", rec.Code)
	}
	if rec := s.deliver(svc, tenantZ, "TenantCreated", "nueva-agencia", "ACTIVE", t0.Add(time.Minute)); rec.Code != http.StatusCreated {
		t.Fatalf("active: %d %s", rec.Code, rec.Body)
	}
	if rec := signInAt(s, "nueva-agencia", "ana@example.com"); rec.Code != http.StatusOK {
		t.Fatalf("an active tenant lets its people in: %d", rec.Code)
	}
	if rec := s.deliver(svc, tenantZ, "TenantInactivated", "nueva-agencia", "INACTIVE", t0.Add(2*time.Minute)); rec.Code != http.StatusCreated {
		t.Fatalf("inactivated: %d", rec.Code)
	}
	if _, claims := s.claims(t, signInAt(s, "nueva-agencia", "boss@example.com")); claims["access"] != "restricted" {
		t.Fatalf("its Administrator gets a restricted access: %v", claims)
	}
	if rec := signInAt(s, "nueva-agencia", "ana@example.com"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the rest are refused: %d", rec.Code)
	}
	// an event that arrives late, from before the inactivation, changes nothing
	if rec := s.deliver(svc, tenantZ, "TenantReactivated", "nueva-agencia", "ACTIVE", t0.Add(90*time.Second)); rec.Code != http.StatusOK {
		t.Fatalf("an older event is a 200: %d", rec.Code)
	}
	if rec := signInAt(s, "nueva-agencia", "ana@example.com"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the late event did not reopen the tenant: %d", rec.Code)
	}
	if rec := s.deliver(svc, tenantZ, "TenantReactivated", "nueva-agencia", "ACTIVE", t0.Add(3*time.Minute)); rec.Code != http.StatusCreated {
		t.Fatalf("reactivated: %d", rec.Code)
	}
	if rec := signInAt(s, "nueva-agencia", "ana@example.com"); rec.Code != http.StatusOK {
		t.Fatalf("the tenant is open again: %d", rec.Code)
	}
}

func TestC_AnIdentifierAnotherTenantStillHoldsIsToBeDeliveredAgainUntilTheRenameArrives(t *testing.T) {
	s := newStack(t)
	svc := s.serviceToken(t)
	t0 := time.Now().Add(-time.Hour)
	if rec := s.deliver(svc, tenantZ, "TenantCreated", "nueva-agencia", "ACTIVE", t0); rec.Code != http.StatusCreated {
		t.Fatalf("%d", rec.Code)
	}
	rec := s.deliver(svc, tenantW, "TenantCreated", "nueva-agencia", "ACTIVE", t0.Add(time.Minute))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || strings.Contains(rec.Body.String(), "uq_tenant_copy") {
		t.Fatalf("the identifier is taken for now: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
	// the event that renames the first tenant arrives, and the delivery of the second one is repeated
	if rec := s.deliver(svc, tenantZ, "TenantReactivated", "otra-nueva", "ACTIVE", t0.Add(2*time.Minute)); rec.Code != http.StatusCreated {
		t.Fatalf("the rename: %d %s", rec.Code, rec.Body)
	}
	if rec := s.deliver(svc, tenantW, "TenantCreated", "nueva-agencia", "ACTIVE", t0.Add(time.Minute)); rec.Code != http.StatusCreated {
		t.Fatalf("the retry: %d %s", rec.Code, rec.Body)
	}
}

func TestC_OnlyAServiceDeliversEventsAndAnEnvelopeThatContradictsItselfIsRefused(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	person, _ := s.claims(t, s.signIn(tenantURL, "ana@example.com", password))
	now := time.Now()
	if rec := s.deliver(person.AccessToken, tenantZ, "TenantCreated", "nueva-agencia", "ACTIVE", now); rec.Code != http.StatusForbidden {
		t.Fatalf("a tenant administrator cannot tell the service what a tenant is: %d", rec.Code)
	}
	if rec := s.deliver("", tenantZ, "TenantCreated", "nueva-agencia", "ACTIVE", now); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := s.deliver(s.serviceToken(t), tenantZ, "TenantInactivated", "nueva-agencia", "ACTIVE", now); rec.Code != http.StatusBadRequest {
		t.Fatalf("an inactivation that says the tenant is active: %d", rec.Code)
	}
	if rec := signInAt(s, "nueva-agencia", "ana@example.com"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("none of those left a tenant: %d", rec.Code)
	}
}

func TestC_NothingOfTheTenantIsLogged(t *testing.T) {
	s := newStack(t)
	s.deliver(s.serviceToken(t), tenantZ, "TenantCreated", "nueva-agencia", "ACTIVE", time.Now())
	if s.logs.Len() == 0 || strings.Contains(s.logs.String(), "Nueva Agencia") {
		t.Fatalf("the log must exist and hold no payload: %s", s.logs.String())
	}
}

func TestC_TheCommercialNameOfATenantEventIsKeptInTheCopy(t *testing.T) {
	s := newStack(t)
	svc := s.serviceToken(t)
	if rec := s.deliver(svc, tenantZ, "TenantCreated", "nueva-agencia", "ACTIVE", time.Now().Add(-time.Hour)); rec.Code != http.StatusCreated {
		t.Fatalf("created: %d %s", rec.Code, rec.Body)
	}
	got, found, err := postgres.NewTenants(s.pool).FindByIdentifier(context.Background(), "nueva-agencia")
	if err != nil || !found || got.CommercialName != "Nueva Agencia SAS" {
		t.Fatalf("copy = %+v %v %v, want the name of the event", got, found, err)
	}
}
