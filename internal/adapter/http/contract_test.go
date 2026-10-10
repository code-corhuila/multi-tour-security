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

	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
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
		want                            int
	}
	scenarios := []scenario{{method: http.MethodGet, path: "/health", want: http.StatusOK}}
	for _, route := range []string{tenantRoute, platformRoute} {
		scenarios = append(scenarios,
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{tokens: okTokens()}, http.StatusOK},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: signin.ErrRefused}, http.StatusUnauthorized},
			scenario{http.MethodPost, route, "application/json", `{"email":`, &fakeSignIn{}, http.StatusBadRequest},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: signin.ErrInvalidRequest}, http.StatusBadRequest},
			scenario{http.MethodPost, route, "text/plain", goodBody, &fakeSignIn{}, http.StatusUnsupportedMediaType},
			scenario{http.MethodPost, route, "application/json", big, &fakeSignIn{}, http.StatusRequestEntityTooLarge},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: errors.New("boom")}, http.StatusInternalServerError},
		)
	}

	key := newKey(t)
	exercised := map[string]bool{}
	for _, s := range scenarios {
		handler := newHandler(key)
		if s.svc != nil {
			handler = signInHandler(s.svc, io.Discard)
		}
		req := httptest.NewRequest(s.method, s.path, strings.NewReader(s.body))
		if s.contentType != "" {
			req.Header.Set("Content-Type", s.contentType)
		}
		req.Header.Set("X-Correlation-Id", "gate-1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != s.want {
			t.Errorf("%s %s: status %d, want %d (%s)", s.method, s.path, rec.Code, s.want, rec.Body)
			continue
		}

		route, params, err := router.FindRoute(req)
		if err != nil {
			t.Fatalf("%s %s is not in the contract: %v", s.method, s.path, err)
		}
		response := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route},
			Status:                 rec.Code,
			Header:                 rec.Header(),
			Options:                &openapi3filter.Options{IncludeResponseStatus: true},
		}
		response.SetBodyBytes(rec.Body.Bytes())
		if err := openapi3filter.ValidateResponse(ctx, response); err != nil {
			t.Errorf("%s %s answered %d against the contract: %v", s.method, s.path, rec.Code, err)
		}
		exercised[s.method+" "+route.Path+" "+strconv.Itoa(rec.Code)] = true
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
