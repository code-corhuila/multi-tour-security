package port

import (
	"context"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

// SupportAccesses is where the support accesses of the Platform Administrator live (HU-SEC-007 part A, security spec 009).
type SupportAccesses interface {
	// Create stores a new request, or, when its author already used the key, returns the request that key made with created false and
	// stores nothing (RN-SEC-009-09). The id is the store's.
	Create(ctx context.Context, a supportaccess.Access, key string) (access supportaccess.Access, created bool, err error)
	// FindByKey returns the request that the key of that author made, if any: a repeat of the key is answered with it before anything else is looked at.
	FindByKey(ctx context.Context, requestedBy, key string) (supportaccess.Access, bool, error)
	// ListByRequester lists the requests of one Platform Administrator, the most recent first, with the total of the filter; status is
	// empty for any. Only the requests of that person are ever returned (RN-SEC-009-07).
	ListByRequester(ctx context.Context, requestedBy, status string, limit, offset int) ([]supportaccess.Access, int, error)
	// FindForTenant returns the request with that id when it concerns that tenant; another tenant's request is the same as none.
	FindForTenant(ctx context.Context, tenantID, id string) (supportaccess.Access, bool, error)
	// ListByTenant lists the requests that concern one tenant, the most recent first, with the total of the filter; status is empty for any.
	ListByTenant(ctx context.Context, tenantID, status string, limit, offset int) ([]supportaccess.Access, int, error)
	// ExpirePendingOfTenant marks as expired the requests of that tenant that nobody decided in time.
	ExpirePendingOfTenant(ctx context.Context, tenantID string, now time.Time) error
	// Decide stores the approval or the rejection of a request, only while it is still pending: false says it was not (another decision won).
	Decide(ctx context.Context, a supportaccess.Access) (bool, error)
	// ExpirePending marks as expired the requests of that author that nobody decided in time, so a listing by status agrees with what it shows.
	ExpirePending(ctx context.Context, requestedBy string, now time.Time) error
}
