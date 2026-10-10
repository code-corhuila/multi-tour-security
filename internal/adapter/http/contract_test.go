package httpadapter_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"

	"github.com/code-corhuila/multi-tour-security/internal/core/changepassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenantevent"
)

// Every answer is validated against the published contract, each scenario says the status it must give, and the last
// check fails when a response declared by an operation of the contract was never produced: that is the gate toward
// qa (ADR-004 D7).
func TestC_EveryResponseOfEveryContractOperationIsProducedAndValid(t *testing.T) {
	ctx := context.Background()
	doc, err := openapi3.NewLoader().LoadFromFile("../../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(ctx); err != nil {
		t.Fatalf("the contract is not valid: %v", err)
	}
	router, err := legacy.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}

	big := `{"email":"ana@example.com","password":"` + strings.Repeat("p", 4096) + `"}`
	type scenario struct {
		method, path, contentType, body string
		svc                             *fakeSignIn
		refresh                         *fakeRefresh
		change                          *fakeChange
		token                           string
		want                            int
	}
	scenarios := []scenario{{method: http.MethodGet, path: "/health", want: http.StatusOK}}
	for _, route := range []string{tenantRoute, platformRoute} {
		scenarios = append(scenarios,
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{tokens: okTokens()}, nil, nil, "", http.StatusOK},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: signin.ErrRefused}, nil, nil, "", http.StatusUnauthorized},
			scenario{http.MethodPost, route, "application/json", `{"email":`, &fakeSignIn{}, nil, nil, "", http.StatusBadRequest},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: signin.ErrInvalidRequest}, nil, nil, "", http.StatusBadRequest},
			scenario{http.MethodPost, route, "text/plain", goodBody, &fakeSignIn{}, nil, nil, "", http.StatusUnsupportedMediaType},
			scenario{http.MethodPost, route, "application/json", big, &fakeSignIn{}, nil, nil, "", http.StatusRequestEntityTooLarge},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: errors.New("boom")}, nil, nil, "", http.StatusInternalServerError},
		)
	}

	bigRefresh := `{"refreshToken":"` + strings.Repeat("r", 4200) + `"}`
	for _, r := range []struct {
		contentType, body string
		svc               *fakeRefresh
		want              int
	}{
		{"application/json", refreshBody, &fakeRefresh{tokens: okTokens()}, http.StatusOK},
		{"application/json", refreshBody, &fakeRefresh{err: signin.ErrRefused}, http.StatusUnauthorized},
		{"application/json", `{"refreshToken":`, &fakeRefresh{}, http.StatusBadRequest},
		{"text/plain", refreshBody, &fakeRefresh{}, http.StatusUnsupportedMediaType},
		{"application/json", bigRefresh, &fakeRefresh{}, http.StatusRequestEntityTooLarge},
		{"application/json", refreshBody, &fakeRefresh{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		scenarios = append(scenarios, scenario{method: http.MethodPost, path: refreshRoute, contentType: r.contentType, body: r.body, refresh: r.svc, want: r.want})
	}

	bigPassword := `{"newPassword":"` + strings.Repeat("p", 4200) + `"}`
	pc := bearer(t, "password-change")
	for _, c := range []struct {
		token, contentType, body string
		svc                      *fakeChange
		want                     int
	}{
		{pc, "application/json", passwordBody, &fakeChange{}, http.StatusNoContent},
		{"", "application/json", passwordBody, &fakeChange{}, http.StatusUnauthorized},
		{pc, "application/json", passwordBody, &fakeChange{err: signin.ErrRefused}, http.StatusUnauthorized},
		{pc, "application/json", `{"newPassword":`, &fakeChange{}, http.StatusBadRequest},
		{pc, "application/json", passwordBody, &fakeChange{err: changepassword.ErrWeakPassword}, http.StatusBadRequest},
		{pc, "text/plain", passwordBody, &fakeChange{}, http.StatusUnsupportedMediaType},
		{pc, "application/json", bigPassword, &fakeChange{}, http.StatusRequestEntityTooLarge},
		{pc, "application/json", passwordBody, &fakeChange{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		scenarios = append(scenarios, scenario{method: http.MethodPut, path: passwordRoute, contentType: c.contentType, body: c.body, change: c.svc, token: c.token, want: c.want})
	}

	key := newKey(t)
	exercised := map[string]bool{}
	run := func(handler http.Handler, method, path, contentType, body, token string, want int) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("X-Correlation-Id", "gate-1")
		if strings.HasSuffix(path, "/events") {
			req.Header.Set("Idempotency-Key", eventKey)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s %s: status %d, want %d (%s)", method, path, rec.Code, want, rec.Body)
			return
		}

		route, params, err := router.FindRoute(req)
		if err != nil {
			t.Fatalf("%s %s is not in the contract: %v", method, path, err)
		}
		response := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route},
			Status:                 rec.Code,
			Header:                 rec.Header(),
			Options:                &openapi3filter.Options{IncludeResponseStatus: true},
		}
		response.SetBodyBytes(rec.Body.Bytes())
		if err := openapi3filter.ValidateResponse(ctx, response); err != nil {
			t.Errorf("%s %s answered %d against the contract: %v", method, path, rec.Code, err)
		}
		exercised[method+" "+route.Path+" "+strconv.Itoa(rec.Code)] = true
	}
	for _, s := range scenarios {
		handler := newHandler(key)
		if s.svc != nil {
			handler = signInHandler(s.svc, io.Discard)
		}
		if s.refresh != nil {
			handler = refreshHandler(s.refresh, io.Discard)
		}
		if s.change != nil {
			handler = changeHandler(s.change, io.Discard)
		}
		run(handler, s.method, s.path, s.contentType, s.body, s.token, s.want)
	}

	// the internal routes: only the token of a service, and the answers of the use case as they come
	svcToken := serviceBearer(t)
	page := outbox.Page{Data: []outbox.Event{sampleEvent()}, Page: 1, Limit: 20, Total: 1, TotalPages: 1}
	bigAttempt := `{"error":"` + strings.Repeat("e", 4200) + `"}`
	for _, c := range []struct {
		method, path, contentType, body, token string
		svc                                    *fakeOutbox
		want                                   int
	}{
		{http.MethodGet, outboxRoute, "", "", svcToken, &fakeOutbox{page: page}, http.StatusOK},
		{http.MethodGet, outboxRoute + "?limit=500", "", "", svcToken, &fakeOutbox{}, http.StatusBadRequest},
		{http.MethodGet, outboxRoute, "", "", "", &fakeOutbox{}, http.StatusUnauthorized},
		{http.MethodGet, outboxRoute, "", "", tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""), &fakeOutbox{}, http.StatusForbidden},
		{http.MethodGet, outboxRoute, "", "", svcToken, &fakeOutbox{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodPost, publishedPath, "", "", svcToken, &fakeOutbox{event: sampleEvent()}, http.StatusOK},
		{http.MethodPost, publishedPath, "", "", "", &fakeOutbox{}, http.StatusUnauthorized},
		{http.MethodPost, publishedPath, "", "", tokenWith(t, nil, "", ""), &fakeOutbox{}, http.StatusForbidden},
		{http.MethodPost, publishedPath, "", "", svcToken, &fakeOutbox{err: outbox.ErrNotFound}, http.StatusNotFound},
		{http.MethodPost, publishedPath, "", "", svcToken, &fakeOutbox{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, svcToken, &fakeOutbox{event: sampleEvent()}, http.StatusOK},
		{http.MethodPost, attemptsPath, "application/json", `{"error":`, svcToken, &fakeOutbox{}, http.StatusBadRequest},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, "", &fakeOutbox{}, http.StatusUnauthorized},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, tokenWith(t, []string{"ANALYST"}, "t-1", ""), &fakeOutbox{}, http.StatusForbidden},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, svcToken, &fakeOutbox{err: outbox.ErrNotFound}, http.StatusNotFound},
		{http.MethodPost, attemptsPath, "text/plain", `{"error":"503"}`, svcToken, &fakeOutbox{}, http.StatusUnsupportedMediaType},
		{http.MethodPost, attemptsPath, "application/json", bigAttempt, svcToken, &fakeOutbox{}, http.StatusRequestEntityTooLarge},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, svcToken, &fakeOutbox{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(outboxHandler(c.svc, io.Discard), c.method, c.path, c.contentType, c.body, c.token, c.want)
	}

	// the receiver of the events of a tenant, with the id of the event as its idempotency key
	bigEvent := strings.Replace(envelopeJSON("TenantCreated", "ACTIVE"), `"country":"CO"`, `"notes":"`+strings.Repeat("n", 17000)+`"`, 1)
	for _, c := range []struct {
		contentType, body, token string
		svc                      *fakeTenantEvents
		want                     int
	}{
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{applied: true}, http.StatusCreated},
		{"application/json", envelopeJSON("TenantInactivated", "INACTIVE"), svcToken, &fakeTenantEvents{applied: false}, http.StatusOK},
		{"application/json", `{"eventId":`, svcToken, &fakeTenantEvents{}, http.StatusBadRequest},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{err: tenantevent.ErrInvalid}, http.StatusBadRequest},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), "", &fakeTenantEvents{}, http.StatusUnauthorized},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, eventTenant, ""), &fakeTenantEvents{}, http.StatusForbidden},
		{"text/plain", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{}, http.StatusUnsupportedMediaType},
		{"application/json", bigEvent, svcToken, &fakeTenantEvents{}, http.StatusRequestEntityTooLarge},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{err: errors.New("boom")}, http.StatusInternalServerError},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{err: tenantevent.ErrRetryLater}, http.StatusServiceUnavailable},
	} {
		run(eventsHandler(c.svc, io.Discard), http.MethodPost, eventsPath, c.contentType, c.body, c.token, c.want)
	}

	for path, item := range doc.Paths.Map() {
		for method, operation := range item.Operations() {
			for status := range operation.Responses.Map() {
				if !exercised[method+" "+path+" "+status] {
					t.Errorf("the response %s of %s %s was never produced", status, method, path)
				}
			}
		}
	}
}
