package port

import (
	"context"

	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// Tenants keeps the copy of the tenants.
type Tenants interface {
	// Apply stores the state of an event only when it is strictly newer than the one stored, and says whether it did.
	// Delivery is not ordered and is repeated: an older or repeated event is ignored with no error. An identifier
	// that another tenant still holds is an error that goes away when the event that renames that tenant arrives, so
	// the route that receives the events answers it as retryable and never as a refusal of the event (SEC-09).
	Apply(ctx context.Context, c tenant.Copy) (applied bool, err error)
	FindByIdentifier(ctx context.Context, identifier string) (tenant.Copy, bool, error)
	// FindByID is how a renewal knows the tenant of an account, which carries the id and not the identifier of a link.
	FindByID(ctx context.Context, tenantID string) (tenant.Copy, bool, error)
}
