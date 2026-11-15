package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportdecision"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// SupportDecider is what the routes of the Tenant Administrator need from the use case, so a test can replace it.
type SupportDecider interface {
	List(ctx context.Context, q supportdecision.Query) (supportdecision.Page, error)
	Approve(ctx context.Context, d supportdecision.Decision) (supportaccess.Access, error)
	Reject(ctx context.Context, d supportdecision.Decision) (supportaccess.Access, error)
}

// WithSupportDecisions registers the routes where a Tenant Administrator lists the support requests that concern their tenant and approves
// or rejects them (HU-SEC-007 part A).
func WithSupportDecisions(service SupportDecider) Option {
	return func(s *server) { s.supportDecisions = service }
}

// requireTenantAdministratorOrRestricted lets in the Tenant Administrator of a tenant, with an ordinary token or with the restricted access
// of an inactive tenant, and nobody else: the approval of a support access is still theirs when the tenant is inactive (HU-SEC-007, AC2).
// The other marks (a temporary credential, the access of a support) and every other role are refused.
func (s *server) requireTenantAdministratorOrRestricted(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		if !slices.Contains(claims.Roles, account.RoleTenantAdministrator) || claims.TenantID == "" || (claims.Access != "" && claims.Access != token.RestrictedAccess) {
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "access denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// supportRejectionBody is the StatusChangeRequest of the contract: the reason, and nothing that names a tenant or an actor.
type supportRejectionBody struct {
	Reason string `json:"reason"`
}

// refuseDecision answers what the use case refused. The tenant and the actor come from the credential, so a fault in them is ours.
func (s *server) refuseDecision(w http.ResponseWriter, r *http.Request, what string, err error) {
	var invalid *supportdecision.FieldError
	switch {
	case errors.As(err, &invalid) && callerField(invalid):
		refuseField(w, r, invalid)
	case errors.Is(err, supportdecision.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the support access does not exist")
	case errors.Is(err, supportaccess.ErrInvalidTransition):
		refuseTransition(w, r, "the support access is not waiting for a decision")
	default:
		s.fail(w, r, what, err)
	}
}

func (s *server) listSupportAccesses(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	valid := err == nil
	for name := range query {
		if name != "page" && name != "limit" && name != "status" {
			valid = false
		}
	}
	page, okPage := number(query, "page", 1)
	limit, okLimit := number(query, "limit", 20)
	status, okStatus := single(query, "status")
	if !valid || !okPage || !okLimit || !okStatus {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "page, limit and status are the only parameters, and they must be valid")
		return
	}
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	result, err := s.supportDecisions.List(r.Context(), supportdecision.Query{TenantID: claims.TenantID, Status: status, Page: page, Limit: limit})
	if err != nil {
		s.refuseDecision(w, r, "listing the support accesses of the tenant", err)
		return
	}
	data := make([]supportAccessBody, len(result.Data))
	for i, a := range result.Data {
		data[i] = toSupportAccessBody(a)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": data,
		"meta": map[string]int{"page": result.Page, "limit": result.Limit, "total": result.Total, "totalPages": result.TotalPages},
	})
}

// decideSupportAccess takes the tenant and the actor from the credential and the request from the path; the rejection also reads its reason.
func (s *server) decideSupportAccess(decide func(context.Context, supportdecision.Decision) (supportaccess.Access, error), withReason bool, what string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		d := supportdecision.Decision{TenantID: claims.TenantID, ActorID: claims.Subject, ID: r.PathValue("supportAccessId")}
		if withReason {
			var body supportRejectionBody
			if !readJSON(w, r, &body) {
				return
			}
			d.Reason = body.Reason
		}
		decided, err := decide(r.Context(), d)
		if err != nil {
			s.refuseDecision(w, r, what, err)
			return
		}
		writeJSON(w, http.StatusOK, toSupportAccessBody(decided))
	}
}
