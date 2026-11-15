// Package supportdecision is the use case where a Tenant Administrator sees the support requests that concern their tenant and approves or
// rejects them (HU-SEC-007 part A, security spec 009: RN-SEC-009-03, -04, -07). The Administrator of an inactive tenant does the same with
// the restricted access; the route decides who gets in, this package decides what happens. It imports only the standard library and the
// rest of the core.
package supportdecision

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// FieldError is the one every use case shares.
type FieldError = validate.FieldError

// ErrNotFound is a request that does not exist or that concerns another tenant: from here it is the same answer.
var ErrNotFound = errors.New("the support access does not exist")

const maxLimit = 100

var statuses = []supportaccess.Status{supportaccess.Pending, supportaccess.Approved, supportaccess.Rejected, supportaccess.Expired, supportaccess.Closed}

// Decision is one approval or rejection. The tenant and the actor are those of the credential, never of the body; Reason is asked of a rejection.
type Decision struct {
	TenantID string
	ActorID  string
	ID       string
	Reason   string
}

// Query is one listing of the requests of a tenant. Status is empty for any.
type Query struct {
	TenantID string
	Status   string
	Page     int
	Limit    int
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
	Store port.SupportAccesses
	Clock func() time.Time
}

var errNotWired = errors.New("support decisions are not wired: every piece is needed")

// List shows the requests of the tenant. A pending request nobody decided in time is marked first, and every one that ran out is shown as
// expired. An approval whose hours ended is written as expired here too, with the fact that closes an access that was opened (plan D-05).
func (s *Service) List(ctx context.Context, q Query) (Page, error) {
	if s.Store == nil || s.Clock == nil {
		return Page{}, errNotWired
	}
	switch {
	case !validate.UUID(q.TenantID):
		return Page{}, &FieldError{Field: "tenantId"}
	case q.Status != "" && !slices.Contains(statuses, supportaccess.Status(q.Status)):
		return Page{}, &FieldError{Field: "status"}
	case q.Limit < 1 || q.Limit > maxLimit:
		return Page{}, &FieldError{Field: "limit"}
	// the offset (Page-1)*Limit must fit an int
	case q.Page < 1 || q.Page > math.MaxInt/q.Limit:
		return Page{}, &FieldError{Field: "page"}
	}
	now := s.Clock()
	if err := s.Store.ExpireApproved(ctx, "", q.TenantID, now); err != nil {
		return Page{}, err
	}
	if err := s.Store.ExpirePendingOfTenant(ctx, q.TenantID, now); err != nil {
		return Page{}, err
	}
	found, total, err := s.Store.ListByTenant(ctx, q.TenantID, q.Status, q.Limit, (q.Page-1)*q.Limit)
	if err != nil {
		return Page{}, err
	}
	data := make([]supportaccess.Access, len(found))
	for i, a := range found {
		data[i] = a.At(now)
	}
	return Page{Data: data, Page: q.Page, Limit: q.Limit, Total: total, TotalPages: (total + q.Limit - 1) / q.Limit}, nil
}

// Approve lets the Platform Administrator in for the hours asked, counted from now.
func (s *Service) Approve(ctx context.Context, d Decision) (supportaccess.Access, error) {
	return s.decide(ctx, d, func(a supportaccess.Access, now time.Time) (supportaccess.Access, error) {
		return a.Approve(d.ActorID, now)
	})
}

// Reject refuses the request, with a reason.
func (s *Service) Reject(ctx context.Context, d Decision) (supportaccess.Access, error) {
	return s.decide(ctx, d, func(a supportaccess.Access, now time.Time) (supportaccess.Access, error) {
		return a.Reject(d.ActorID, d.Reason, now)
	})
}

// decide reads the request of that tenant, applies the rule, and stores the result only while the request is still pending, so two
// Administrators deciding at once have one winner and the other is told that it is not pending any more.
func (s *Service) decide(ctx context.Context, d Decision, apply func(supportaccess.Access, time.Time) (supportaccess.Access, error)) (supportaccess.Access, error) {
	if s.Store == nil || s.Clock == nil {
		return supportaccess.Access{}, errNotWired
	}
	switch {
	case !validate.UUID(d.TenantID):
		return supportaccess.Access{}, &FieldError{Field: "tenantId"}
	case !validate.UUID(d.ActorID):
		return supportaccess.Access{}, &FieldError{Field: "actorId"}
	case !validate.UUID(d.ID):
		return supportaccess.Access{}, ErrNotFound
	}
	current, found, err := s.Store.FindForTenant(ctx, d.TenantID, d.ID)
	if err != nil {
		return supportaccess.Access{}, err
	}
	if !found {
		return supportaccess.Access{}, ErrNotFound
	}
	// the store keeps microseconds: the instants of the answer are cut the same way, so a later read agrees with it
	decided, err := apply(current, s.Clock().Truncate(time.Microsecond))
	switch {
	case errors.Is(err, supportaccess.ErrInvalidReason):
		return supportaccess.Access{}, &FieldError{Field: "reason"}
	case err != nil:
		return supportaccess.Access{}, err
	}
	stored, err := s.Store.Decide(ctx, decided)
	if err != nil {
		return supportaccess.Access{}, err
	}
	if !stored {
		return supportaccess.Access{}, supportaccess.ErrInvalidTransition
	}
	return decided, nil
}
