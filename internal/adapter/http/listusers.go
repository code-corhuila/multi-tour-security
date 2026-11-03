package httpadapter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/code-corhuila/multi-tour-security/internal/core/listusers"
)

// UserLister is what the route that lists users needs from the use case, so a test can replace it.
type UserLister interface {
	List(ctx context.Context, q listusers.Query) (listusers.Page, error)
}

// WithListInternalUsers registers the route where a Tenant Administrator lists the users of their own tenant (HU-SEC-005).
func WithListInternalUsers(service UserLister) Option {
	return func(s *server) { s.userLister = service }
}

// single reads a filter that may be given once and not empty; a repeated or empty one is refused instead of guessed, so
// "no filter" is only ever the absence of the parameter.
func single(query url.Values, name string) (string, bool) {
	values, present := query[name]
	if !present {
		return "", true
	}
	return values[0], len(values) == 1 && values[0] != ""
}

// listInternalUsers takes the tenant from the credential and nothing in the query can change it: the only parameters are
// the declared ones, and any other is a 400. The values are judged by the use case, so the rules live in one place.
func (s *server) listInternalUsers(w http.ResponseWriter, r *http.Request) {
	// ParseQuery reports a pair it cannot read, where URL.Query() would drop it and let an undeclared filter slip through
	query, err := url.ParseQuery(r.URL.RawQuery)
	valid := err == nil
	for name := range query {
		if name != "page" && name != "limit" && name != "role" && name != "status" {
			valid = false
		}
	}
	page, okPage := number(query, "page", 1)
	limit, okLimit := number(query, "limit", 20)
	role, okRole := single(query, "role")
	status, okStatus := single(query, "status")
	if !valid || !okPage || !okLimit || !okRole || !okStatus {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "page, limit, role and status are the only parameters, and they must be valid")
		return
	}
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	result, err := s.userLister.List(r.Context(), listusers.Query{TenantID: claims.TenantID, Role: role, Status: status, Page: page, Limit: limit})
	var invalid *listusers.FieldError
	// a tenant that is not an id comes from the credential, not from the caller: it is our failure, not a 400
	if errors.As(err, &invalid) && invalid.Field != "tenantId" {
		writeEnvelope(w, r, http.StatusBadRequest, errorBody{Error: "VALIDATION_ERROR", Message: "the request is not valid",
			Details: []fieldDetail{{Field: invalid.Field, Message: "is not valid"}}})
		return
	}
	data := make([]accountBody, 0, len(result.Data))
	for i := 0; err == nil && i < len(result.Data); i++ {
		var body accountBody
		if body, err = toAccountBody(result.Data[i]); err == nil {
			data = append(data, body)
		}
	}
	if err != nil {
		s.logger.ErrorContext(r.Context(), "listing the internal users failed", "traceId", traceID(r.Context()), "errorType", fmt.Sprintf("%T", err)) // only the type: a driver error can quote a row
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": data,
		"meta": map[string]int{"page": result.Page, "limit": result.Limit, "total": result.Total, "totalPages": result.TotalPages},
	})
}
