package port

import (
	"context"
	"errors"
	"time"
)

// ErrRoleInUse is the disabling of an optional role that an active user of the tenant still holds: no operation of Phase 1 takes a
// role away from a person (spec 005, RN-SEC-005-13).
var ErrRoleInUse = errors.New("an active user of the tenant holds the role")

// ErrRoleNotEnabled is the registration of a user with an optional role that the tenant has not enabled (RN-SEC-005-12).
var ErrRoleNotEnabled = errors.New("the optional role is not enabled in the tenant")

// OptionalRoleState is one optional role of a tenant. A role the tenant never touched is not enabled and has no change.
type OptionalRoleState struct {
	Role      string
	Enabled   bool
	ChangedAt time.Time
	ChangedBy string
}

// OptionalRoleChange asks to enable or disable one optional role of a tenant. By is the actor as it is recorded with the setting and
// ActorID and ActorRole are the same actor as the event shows them.
type OptionalRoleChange struct {
	TenantID      string
	Role          string
	By            string
	ActorID       string
	ActorRole     string
	CorrelationID string
	Now           time.Time
}

// OptionalRoles is where the optional roles a tenant enabled are kept (HU-SEC-006, RN-SEC-005-12 to -14 and -16).
type OptionalRoles interface {
	// List gives the three optional roles of the tenant, in a fixed order, enabled or not.
	List(ctx context.Context, tenantID string) ([]OptionalRoleState, error)
	// Enable turns the role on and writes who and when and OptionalRoleEnabled, together. A role that is enabled is
	// ErrStatusTransition and nothing is written.
	Enable(ctx context.Context, c OptionalRoleChange) (OptionalRoleState, error)
	// Disable turns the role off and writes who and when and OptionalRoleDisabled, together, only while no active user of the
	// tenant holds the role (ErrRoleInUse) and the role is enabled (ErrStatusTransition). The count and the write are one transaction.
	Disable(ctx context.Context, c OptionalRoleChange) (OptionalRoleState, error)
}
