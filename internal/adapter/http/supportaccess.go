package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportrequest"
)

// SupportRequester is what the routes of the Platform Administrator need from the use case, so a test can replace it.
type SupportRequester interface {
	Ask(ctx context.Context, c supportrequest.Command) (supportaccess.Access, bool, error)
	List(ctx context.Context, q supportrequest.Query) (supportrequest.Page, error)
}

// WithSupportRequests registers the routes where the Platform Administrator asks for a support access to a tenant and lists what they asked
// (HU-SEC-007 part A).
func WithSupportRequests(service SupportRequester) Option {
	return func(s *server) { s.supportRequests = service }
}

// requirePlatformAdministrator lets in the Platform Administrator and nobody else: not a Tenant Administrator, and not the Platform
// Administrator with an access mark, whose token is for one tenant and one purpose (the restricted or the exceptional access).
func (s *server) requirePlatformAdministrator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		if !slices.Contains(claims.Roles, account.RolePlatformAdministrator) || claims.TenantID != "" || claims.Access != "" {
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "access denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// supportAccessRequestBody is the CreateSupportAccessRequest of the contract. It has no field for the actor, and the reader refuses any field
// it does not name, so nothing in the body can change who is asking.
type supportAccessRequestBody struct {
	TenantID string   `json:"tenantId"`
	Reason   string   `json:"reason"`
	Areas    []string `json:"areas"`
	Hours    int      `json:"hours"`
}

// supportAccessBody is the SupportAccess of the contract. The instants that are not there yet are left out.
type supportAccessBody struct {
	SupportAccessID string   `json:"supportAccessId"`
	TenantID        string   `json:"tenantId"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
	Areas           []string `json:"areas"`
	Hours           int      `json:"hours"`
	RequestedBy     string   `json:"requestedBy"`
	RequestedAt     string   `json:"requestedAt"`
	DecidedBy       string   `json:"decidedBy,omitempty"`
	DecidedAt       string   `json:"decidedAt,omitempty"`
	DecisionReason  string   `json:"decisionReason,omitempty"`
	ExpiresAt       string   `json:"expiresAt,omitempty"`
	OpenedAt        string   `json:"openedAt,omitempty"`
	ClosedAt        string   `json:"closedAt,omitempty"`
	ClosedReason    string   `json:"closedReason,omitempty"`
}

func toSupportAccessBody(a supportaccess.Access) supportAccessBody {
	return supportAccessBody{
		SupportAccessID: a.ID, TenantID: a.TenantID, Status: string(a.Status), Reason: a.Reason, Areas: a.AreaNames(), Hours: a.Hours,
		RequestedBy: a.RequestedBy, RequestedAt: instant(a.RequestedAt), DecidedBy: a.DecidedBy, DecidedAt: instant(a.DecidedAt),
		DecisionReason: a.DecisionReason, ExpiresAt: instant(a.ExpiresAt), OpenedAt: instant(a.OpenedAt), ClosedAt: instant(a.ClosedAt),
		ClosedReason: a.ClosedReason,
	}
}

// instant is the RFC 3339 form in UTC of an instant, or nothing for the zero one.
func instant(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// refuseSupport answers what the use case refused. The tenant comes in the body, so its fault is the caller's too; only the actor, who
// comes from the credential, is not.
func (s *server) refuseSupport(w http.ResponseWriter, r *http.Request, what string, err error) {
	var invalid *supportrequest.FieldError
	switch {
	case errors.As(err, &invalid) && invalid.Field != "actorId":
		refuseField(w, r, invalid)
	case errors.Is(err, supportrequest.ErrTenantNotFound):
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the tenant does not exist")
	default:
		s.fail(w, r, what, err)
	}
}

// askForSupportAccess takes the actor from the credential. A missing field arrives empty and the use case refuses it by name.
func (s *server) askForSupportAccess(w http.ResponseWriter, r *http.Request) {
	var body supportAccessRequestBody
	if !readJSON(w, r, &body) {
		return
	}
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	access, created, err := s.supportRequests.Ask(r.Context(), supportrequest.Command{
		ActorID: claims.Subject, TenantID: body.TenantID, Reason: body.Reason, Areas: body.Areas, Hours: body.Hours,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		s.refuseSupport(w, r, "asking for a support access", err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, toSupportAccessBody(access))
}

// listPlatformSupportAccesses lists what the caller asked for; the only parameters are the declared ones, and any other is a 400.
func (s *server) listPlatformSupportAccesses(w http.ResponseWriter, r *http.Request) {
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
	result, err := s.supportRequests.List(r.Context(), supportrequest.Query{ActorID: claims.Subject, Status: status, Page: page, Limit: limit})
	if err != nil {
		s.refuseSupport(w, r, "listing the support accesses", err)
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
