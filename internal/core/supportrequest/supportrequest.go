// Package supportrequest is the use case where the Platform Administrator asks for a support access to a tenant and lists the requests they
// made (HU-SEC-007 part A, security spec 009: RN-SEC-009-01, -07, -09). It imports only the standard library and the rest of the core.
package supportrequest

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// ErrInvalid and FieldError are those every use case shares.
var ErrInvalid = validate.ErrInvalid

type FieldError = validate.FieldError

// ErrTenantNotFound is a tenant that does not exist or is neither active nor inactive: from here it is the same answer.
var ErrTenantNotFound = errors.New("the tenant does not exist")

const (
	maxLimit        = 100
	minKey, maxKey  = 8, 128
	reasonField     = "reason"
	areasField      = "areas"
	hoursField      = "hours"
	tenantField     = "tenantId"
	keyField        = "idempotencyKey"
	actorField      = "actorId"
	statusField     = "status"
	limitField      = "limit"
	pageField       = "page"
	notWiredMessage = "support requests are not wired: every piece is needed"
)

var statuses = []supportaccess.Status{supportaccess.Pending, supportaccess.Approved, supportaccess.Rejected, supportaccess.Expired, supportaccess.Closed}

// Command is one request. The actor is the Platform Administrator of the credential, never of the body.
type Command struct {
	ActorID        string
	TenantID       string
	Reason         string
	Areas          []string
	Hours          int
	IdempotencyKey string
}

// Query is one listing of the own requests. Status is empty for any.
type Query struct {
	ActorID string
	Status  string
	Page    int
	Limit   int
}

// Page is one page of requests and the numbers that tell where it is.
type Page struct {
	Data       []supportaccess.Access
	Page       int
	Limit      int
	Total      int
	TotalPages int
}

// Service holds the pieces of the use case; the composition root fills every one.
type Service struct {
	Tenants port.Tenants
	Store   port.SupportAccesses
	Clock   func() time.Time
}

// Ask stores a pending request, or returns the one the same key already made with created false and stores nothing.
func (s *Service) Ask(ctx context.Context, c Command) (supportaccess.Access, bool, error) {
	if s.Tenants == nil || s.Store == nil || s.Clock == nil {
		return supportaccess.Access{}, false, errors.New(notWiredMessage)
	}
	if !validate.UUID(c.ActorID) {
		return supportaccess.Access{}, false, &FieldError{Field: actorField}
	}
	if n := len(c.IdempotencyKey); n < minKey || n > maxKey {
		return supportaccess.Access{}, false, &FieldError{Field: keyField}
	}
	if !validate.UUID(c.TenantID) {
		return supportaccess.Access{}, false, &FieldError{Field: tenantField}
	}
	request, err := supportaccess.New(c.TenantID, c.ActorID, c.Reason, c.Areas, c.Hours, s.Clock())
	switch {
	case errors.Is(err, supportaccess.ErrInvalidReason):
		return supportaccess.Access{}, false, &FieldError{Field: reasonField}
	case errors.Is(err, supportaccess.ErrInvalidAreas):
		return supportaccess.Access{}, false, &FieldError{Field: areasField}
	case errors.Is(err, supportaccess.ErrInvalidHours):
		return supportaccess.Access{}, false, &FieldError{Field: hoursField}
	case err != nil:
		return supportaccess.Access{}, false, err
	}
	// after the fields: a form for a tenant that does not exist is judged by its fields first, as the other use cases do
	copyOfTenant, found, err := s.Tenants.FindByID(ctx, c.TenantID)
	if err != nil {
		return supportaccess.Access{}, false, err
	}
	if !found || (copyOfTenant.Status != tenant.Active && copyOfTenant.Status != tenant.Inactive) {
		return supportaccess.Access{}, false, ErrTenantNotFound
	}
	return s.Store.Create(ctx, request, c.IdempotencyKey)
}

// List shows the requests of the caller. The ones that ran out are shown as expired, and a pending request nobody decided in time is
// marked first, so a filter by status agrees with what the page shows.
func (s *Service) List(ctx context.Context, q Query) (Page, error) {
	if s.Store == nil || s.Clock == nil {
		return Page{}, errors.New(notWiredMessage)
	}
	switch {
	case !validate.UUID(q.ActorID):
		return Page{}, &FieldError{Field: actorField}
	case q.Status != "" && !slices.Contains(statuses, supportaccess.Status(q.Status)):
		return Page{}, &FieldError{Field: statusField}
	case q.Limit < 1 || q.Limit > maxLimit:
		return Page{}, &FieldError{Field: limitField}
	// the offset (Page-1)*Limit must fit an int
	case q.Page < 1 || q.Page > math.MaxInt/q.Limit:
		return Page{}, &FieldError{Field: pageField}
	}
	now := s.Clock()
	if err := s.Store.ExpirePending(ctx, now); err != nil {
		return Page{}, err
	}
	found, total, err := s.Store.ListByRequester(ctx, q.ActorID, q.Status, q.Limit, (q.Page-1)*q.Limit)
	if err != nil {
		return Page{}, err
	}
	data := make([]supportaccess.Access, len(found))
	for i, a := range found {
		data[i] = a.At(now)
	}
	return Page{Data: data, Page: q.Page, Limit: q.Limit, Total: total, TotalPages: (total + q.Limit - 1) / q.Limit}, nil
}
