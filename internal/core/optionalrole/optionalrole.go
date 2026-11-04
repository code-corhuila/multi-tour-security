// Package optionalrole is the use case that lists, enables and disables the optional roles of a tenant (HU-SEC-006, RN-SEC-005-02, -12
// and -13). The store counts the holders and writes; this decides what may be asked.
package optionalrole

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// ErrInvalid and FieldError are those every use case shares.
var ErrInvalid = validate.ErrInvalid

type FieldError = validate.FieldError

// Query asks for the optional roles of the tenant of the credential.
type Query struct {
	TenantID string
}

// Request is one change. The tenant and the actor are those of the credential, never of the body.
type Request struct {
	TenantID      string
	ActorID       string
	Role          string
	CorrelationID string
}

// Service reads and changes the optional roles through the store the composition root gives it.
type Service struct {
	Store port.OptionalRoles
	Clock func() time.Time
}

func (s *Service) wired() error {
	if s.Store == nil || s.Clock == nil {
		return errors.New("the optional roles are not wired: the store and the clock are needed")
	}
	return nil
}

// List gives the three optional roles of the tenant, each enabled or not; a tenant starts with none enabled.
func (s *Service) List(ctx context.Context, q Query) ([]port.OptionalRoleState, error) {
	if s.Store == nil {
		return nil, errors.New("the optional roles are not wired: the store is needed")
	}
	if !validate.UUID(q.TenantID) {
		return nil, &FieldError{Field: "tenantId"}
	}
	return s.Store.List(ctx, q.TenantID)
}

// Enable turns the role on: from then on the tenant may register users with it.
func (s *Service) Enable(ctx context.Context, r Request) (port.OptionalRoleState, error) {
	c, err := s.change(r)
	if err != nil {
		return port.OptionalRoleState{}, err
	}
	return s.Store.Enable(ctx, c)
}

// Disable turns the role off, refused by the store while an active user of the tenant holds it.
func (s *Service) Disable(ctx context.Context, r Request) (port.OptionalRoleState, error) {
	c, err := s.change(r)
	if err != nil {
		return port.OptionalRoleState{}, err
	}
	return s.Store.Disable(ctx, c)
}

func (s *Service) change(r Request) (port.OptionalRoleChange, error) {
	if err := s.wired(); err != nil {
		return port.OptionalRoleChange{}, err
	}
	switch {
	case !validate.UUID(r.TenantID):
		return port.OptionalRoleChange{}, &FieldError{Field: "tenantId"}
	case !validate.UUID(r.ActorID):
		return port.OptionalRoleChange{}, &FieldError{Field: "actorId"}
	case !account.IsOptionalRole(r.Role):
		// no operation creates a role: anything but the three is refused, and the value is never repeated (AC8)
		return port.OptionalRoleChange{}, &FieldError{Field: "role"}
	case !validate.CorrelationID(r.CorrelationID):
		// every request has one that the HTTP adapter checked: another is a mistake of ours
		return port.OptionalRoleChange{}, errors.New("the change of an optional role has no usable correlation id")
	}
	// the actor is a Tenant Administrator because the route that calls this lets in no one else (plan D-07); the core does not check it
	return port.OptionalRoleChange{TenantID: r.TenantID, Role: r.Role, By: "tenant-administrator/" + r.ActorID, ActorID: r.ActorID,
		ActorRole: account.RoleTenantAdministrator, CorrelationID: r.CorrelationID, Now: s.Clock()}, nil
}
