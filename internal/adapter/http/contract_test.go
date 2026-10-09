package httpadapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"
)

// Every answer is validated against the published contract, and the last check fails when an
// operation of the contract was never exercised: that is the gate toward qa (ADR-004 D7).
func TestC_EveryContractOperationIsExercised(t *testing.T) {
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

	handler := newHandler(newKey(t))
	exercised := map[string]bool{}
	for _, scenario := range []struct{ method, path string }{
		{http.MethodGet, "/health"},
	} {
		req := httptest.NewRequest(scenario.method, scenario.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		route, params, err := router.FindRoute(req)
		if err != nil {
			t.Fatalf("%s %s is not in the contract: %v", scenario.method, scenario.path, err)
		}
		response := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route},
			Status:                 rec.Code,
			Header:                 rec.Header(),
			Options:                &openapi3filter.Options{IncludeResponseStatus: true},
		}
		response.SetBodyBytes(rec.Body.Bytes())
		if err := openapi3filter.ValidateResponse(ctx, response); err != nil {
			t.Errorf("%s %s answered %d against the contract: %v", scenario.method, scenario.path, rec.Code, err)
		}
		exercised[scenario.method+" "+route.Path] = true
	}

	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			if !exercised[method+" "+path] {
				t.Errorf("the operation %s %s of the contract was never exercised", method, path)
			}
		}
	}
}
