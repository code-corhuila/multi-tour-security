// Package changepermission is the use case that assigns and removes a special permission of an internal user of a tenant (HU-SEC-006,
// RN-SEC-005-03 to -07 and -10). The core decides from the facts the store gives; the store writes.
package changepermission

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// ErrInvalid and FieldError are those every use case shares.
var ErrInvalid = validate.ErrInvalid

type FieldError = validate.FieldError

var (
	// ErrNotAssignable is a permission that the role of the user may not hold: a Manager, an Accountant, an Analyst, a Final Customer
	// or the platform never hold one, and an Administrator holds three by profile and is assigned only the fourth.
	ErrNotAssignable = errors.New("the role of the user cannot hold that permission")
	// ErrProfilePermission is a permission that the Tenant Administrator holds by profile: it is neither assigned nor removed.
	ErrProfilePermission = errors.New("the permission is held by profile and is neither assigned nor removed")
)

// Request is one change. The tenant and the actor are those of the credential, never of the body.
type Request struct {
	TenantID      string
	AccountID     string
	ActorID       string
	Permission    string
	CorrelationID string
}

// Service changes the permissions through the store the composition root gives it.
type Service struct {
	Store port.UserPermissions
	Clock func() time.Time
}

// Grant makes the user hold the permission from their next sign-in or refresh; it cuts no session.
func (s *Service) Grant(ctx context.Context, r Request) (port.Registered, error) {
	return s.change(ctx, r, true)
}

// Remove takes the permission away and cuts the sessions of the user.
func (s *Service) Remove(ctx context.Context, r Request) (port.Registered, error) {
	return s.change(ctx, r, false)
}

func (s *Service) change(ctx context.Context, r Request, grant bool) (port.Registered, error) {
	if s.Store == nil || s.Clock == nil {
		return port.Registered{}, errors.New("the change of permissions is not wired: the store and the clock are needed")
	}
	switch {
	case !validate.UUID(r.TenantID):
		return port.Registered{}, &FieldError{Field: "tenantId"}
	case !validate.UUID(r.AccountID):
		return port.Registered{}, &FieldError{Field: "accountId"}
	case !validate.UUID(r.ActorID):
		return port.Registered{}, &FieldError{Field: "actorId"}
	case !account.IsSpecialPermission(r.Permission):
		// no operation creates a permission: anything but the four is refused, and the value is never repeated (AC8)
		return port.Registered{}, &FieldError{Field: "permission"}
	case !validate.CorrelationID(r.CorrelationID):
		// every request has one that the HTTP adapter checked: another is a mistake of ours
		return port.Registered{}, errors.New("the change of permissions has no usable correlation id")
	}
	holder, err := s.Store.Holder(ctx, r.TenantID, r.AccountID)
	if err != nil {
		return port.Registered{}, err
	}
	// reading the role before the write is safe while a role never changes (Phase 1); the store writes only to an internal user of the tenant
	if slices.Contains(account.ProfilePermissions([]string{holder.Role}), r.Permission) {
		return port.Registered{}, ErrProfilePermission
	}
	// a stray row of a role that cannot hold it can still be removed: removing is never refused for that
	if grant && !account.Assignable(holder.Role, r.Permission) {
		return port.Registered{}, ErrNotAssignable
	}
	// the actor is a Tenant Administrator because the route that calls this lets in no one else (plan D-07); the core does not check it
	change := port.PermissionChange{TenantID: r.TenantID, AccountID: r.AccountID, Permission: r.Permission, By: account.By(account.RoleTenantAdministrator, r.ActorID),
		ActorID: r.ActorID, ActorRole: account.RoleTenantAdministrator, CorrelationID: r.CorrelationID, Now: s.Clock()}
	if grant {
		return s.Store.Grant(ctx, change)
	}
	return s.Store.Remove(ctx, change)
}
