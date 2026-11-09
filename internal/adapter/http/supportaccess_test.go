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
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportrequest"
)

// HU-SEC-007 part A, security spec 009: the routes where the Platform Administrator asks for a support access and lists the own requests.

const (
	supportRoute = "/api/v1/security/platform-support-accesses"
	supportKey   = "ask-support-0001"
	supportBody  = `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"The cash closing does not show the transfers","areas":["CASH","RESERVATIONS"],"hours":4}`
)

type fakeSupport struct {
	asked   []supportrequest.Command
	queries []supportrequest.Query
	access  supportaccess.Access
	created bool
	page    supportrequest.Page
	err     error
}

func (f *fakeSupport) Ask(_ context.Context, c supportrequest.Command) (supportaccess.Access, bool, error) {
	f.asked = append(f.asked, c)
	return f.access, f.created, f.err
}

func (f *fakeSupport) List(_ context.Context, q supportrequest.Query) (supportrequest.Page, error) {
	f.queries = append(f.queries, q)
	return f.page, f.err
}

func supportHandler(svc httpadapter.SupportRequester, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithSupportRequests(svc))
}

func platformAdminToken(t *testing.T) string {
	return tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", "")
}

func askedAccess() supportaccess.Access {
	a, _ := supportaccess.New("3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", "44444444-4444-4444-8444-444444444444", "The cash closing does not show the transfers", []string{"CASH", "RESERVATIONS"}, 4,
		time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC))
	a.ID = "55555555-5555-4555-8555-555555555555"
	return a
}

func supportCall(h http.Handler, method, path, token, contentType, body, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Correlation-Id", "sup-1")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
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

func TestC_ThePlatformAdministratorAsksAndTheUseCaseGetsTheCallerNotTheBody(t *testing.T) {
	svc := &fakeSupport{access: askedAccess(), created: true}
	rec := supportCall(supportHandler(svc, io.Discard), http.MethodPost, supportRoute, platformAdminToken(t), "application/json", supportBody, supportKey)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	want := supportrequest.Command{ActorID: "worker-event-relay", TenantID: "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f",
		Reason: "The cash closing does not show the transfers", Areas: []string{"CASH", "RESERVATIONS"}, Hours: 4, IdempotencyKey: supportKey}
	if len(svc.asked) != 1 || svc.asked[0].ActorID != want.ActorID || svc.asked[0].TenantID != want.TenantID || svc.asked[0].Hours != 4 ||
		strings.Join(svc.asked[0].Areas, ",") != "CASH,RESERVATIONS" || svc.asked[0].IdempotencyKey != supportKey || svc.asked[0].Reason != want.Reason {
		t.Fatalf("the use case got %+v", svc.asked)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["supportAccessId"] != "55555555-5555-4555-8555-555555555555" || out["status"] != "PENDING" || out["hours"] != float64(4) || out["requestedAt"] != "2026-11-09T10:00:00Z" {
		t.Fatalf("the answer is %v", out)
	}
	if _, has := out["expiresAt"]; has {
		t.Errorf("a pending request has no end yet: %v", out)
	}
}

func TestC_TheSameKeyAnswers200WithTheSameRequest(t *testing.T) {
	svc := &fakeSupport{access: askedAccess(), created: false}
	rec := supportCall(supportHandler(svc, io.Discard), http.MethodPost, supportRoute, platformAdminToken(t), "application/json", supportBody, supportKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_OnlyThePlatformAdministratorWithoutAnAccessMarkAsksOrLists(t *testing.T) {
	tokens := map[string]string{
		"tenant administrator":   tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", ""),
		"service with no role":   tokenWith(t, nil, "", ""),
		"customer":               tokenWith(t, []string{"FINAL_CUSTOMER"}, "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", ""),
		"restricted platform":    tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", "restricted"),
		"the token of an access": tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", "exceptional"),
	}
	for name, token := range tokens {
		svc := &fakeSupport{access: askedAccess(), created: true}
		h := supportHandler(svc, io.Discard)
		if rec := supportCall(h, http.MethodPost, supportRoute, token, "application/json", supportBody, supportKey); rec.Code != http.StatusForbidden {
			t.Errorf("%s asking: %d", name, rec.Code)
		}
		if rec := supportCall(h, http.MethodGet, supportRoute, token, "", "", ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s listing: %d", name, rec.Code)
		}
		if len(svc.asked)+len(svc.queries) != 0 {
			t.Errorf("%s reached the use case", name)
		}
	}
	h := supportHandler(&fakeSupport{}, io.Discard)
	if rec := supportCall(h, http.MethodPost, supportRoute, "", "application/json", supportBody, supportKey); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
}

func TestC_ABadBodyIsRefusedBeforeTheUseCase(t *testing.T) {
	cases := map[string]struct {
		contentType, body string
		status            int
	}{
		"not json":         {"text/plain", supportBody, http.StatusUnsupportedMediaType},
		"broken json":      {"application/json", `{"tenantId":`, http.StatusBadRequest},
		"unknown field":    {"application/json", `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"x","areas":["CASH"],"hours":1,"actorId":"x"}`, http.StatusBadRequest},
		"hours not number": {"application/json", `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"x","areas":["CASH"],"hours":"4"}`, http.StatusBadRequest},
		"areas not list":   {"application/json", `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"x","areas":"CASH","hours":1}`, http.StatusBadRequest},
	}
	for name, c := range cases {
		svc := &fakeSupport{}
		rec := supportCall(supportHandler(svc, io.Discard), http.MethodPost, supportRoute, platformAdminToken(t), c.contentType, c.body, supportKey)
		if rec.Code != c.status || len(svc.asked) != 0 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestC_AFieldTheUseCaseRefusesIsNamedAndATenantThatIsNotThereIs404(t *testing.T) {
	svc := &fakeSupport{err: &supportrequest.FieldError{Field: "areas", Err: errors.New("is not valid")}}
	rec := supportCall(supportHandler(svc, io.Discard), http.MethodPost, supportRoute, platformAdminToken(t), "application/json", supportBody, supportKey)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"areas"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// the tenant comes in the body, so a wrong one is a fault of the caller too
	svc = &fakeSupport{err: &supportrequest.FieldError{Field: "tenantId", Err: errors.New("is not valid")}}
	if rec := supportCall(supportHandler(svc, io.Discard), http.MethodPost, supportRoute, platformAdminToken(t), "application/json", supportBody, supportKey); rec.Code != http.StatusBadRequest {
		t.Fatalf("tenantId: %d %s", rec.Code, rec.Body)
	}
	svc = &fakeSupport{err: supportrequest.ErrTenantNotFound}
	if rec := supportCall(supportHandler(svc, io.Discard), http.MethodPost, supportRoute, platformAdminToken(t), "application/json", supportBody, supportKey); rec.Code != http.StatusNotFound {
		t.Fatalf("not found: %d %s", rec.Code, rec.Body)
	}
}

func TestC_AFailureOfTheUseCaseIsAnInternalErrorWithNoDetail(t *testing.T) {
	var logs strings.Builder
	svc := &fakeSupport{err: errors.New("pq: connection refused at db-host-7")}
	rec := supportCall(supportHandler(svc, &logs), http.MethodPost, supportRoute, platformAdminToken(t), "application/json", supportBody, supportKey)
	// the cause stays out of the answer and out of the log: only its type and the trace id are written, as for every route
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "db-host-7") || strings.Contains(logs.String(), "db-host-7") ||
		!strings.Contains(logs.String(), "asking for a support access failed") || !strings.Contains(logs.String(), "sup-1") {
		t.Fatalf("%d %s / log %s", rec.Code, rec.Body, logs.String())
	}
}

func TestC_TheListIsOfTheCallerAndItsParametersAreTheDeclaredOnes(t *testing.T) {
	svc := &fakeSupport{page: supportrequest.Page{Data: []supportaccess.Access{askedAccess()}, Page: 2, Limit: 10, Total: 11, TotalPages: 2}}
	h := supportHandler(svc, io.Discard)
	rec := supportCall(h, http.MethodGet, supportRoute+"?page=2&limit=10&status=PENDING", platformAdminToken(t), "", "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if len(svc.queries) != 1 || svc.queries[0] != (supportrequest.Query{ActorID: "worker-event-relay", Status: "PENDING", Page: 2, Limit: 10}) {
		t.Fatalf("query = %+v", svc.queries)
	}
	var out struct {
		Data []map[string]any
		Meta map[string]int
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Data) != 1 || out.Meta["total"] != 11 || out.Meta["totalPages"] != 2 || out.Meta["page"] != 2 {
		t.Fatalf("answer = %s %v", rec.Body, err)
	}
	for _, bad := range []string{"?tenantId=x", "?status=", "?status=A&status=B", "?page=x", "?limit=-1", "?page=1;"} {
		before := len(svc.queries)
		if rec := supportCall(h, http.MethodGet, supportRoute+bad, platformAdminToken(t), "", "", ""); rec.Code != http.StatusBadRequest || len(svc.queries) != before {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	svc.err = &supportrequest.FieldError{Field: "limit", Err: errors.New("is not valid")}
	if rec := supportCall(h, http.MethodGet, supportRoute+"?limit=1000", platformAdminToken(t), "", "", ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"limit"`) {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}
