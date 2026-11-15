// Package supportemergency is the use case where the Platform Administrator opens an emergency access to a tenant (HU-SEC-007 part B, security
// spec 010: RN-SEC-010-01, -02, -03, -08, -09). It imports only the standard library and the rest of the core.
package supportemergency

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// FieldError is the one every use case shares.
type FieldError = validate.FieldError

// ErrTenantNotFound is a tenant that does not exist or is neither active nor inactive: from here it is the same answer.
var ErrTenantNotFound = errors.New("the tenant does not exist")

const (
	minKey, maxKey  = 8, 128
	notWiredMessage = "the emergency access is not wired: every piece is needed"
)

// Command is one emergency access. The actor is the Platform Administrator of the credential, never of the body.
type Command struct {
	ActorID         string
	TenantID        string
	Reason          string
	Statement       string
	Areas           []string
	Hours           int
	Sensitive       bool
	SensitiveReason string
	IdempotencyKey  string
	CorrelationID   string
}

// Service holds the pieces of the use case; the composition root fills every one.
type Service struct {
	Tenants port.Tenants
	Store   port.EmergencyAccesses
	Clock   func() time.Time
}

// Open stores an emergency access that starts now, or returns the one the same key already made with created false and stores nothing.
func (s *Service) Open(ctx context.Context, c Command) (supportaccess.Access, bool, error) {
	if s.Tenants == nil || s.Store == nil || s.Clock == nil {
		return supportaccess.Access{}, false, errors.New(notWiredMessage)
	}
	if !validate.UUID(c.ActorID) {
		return supportaccess.Access{}, false, &FieldError{Field: "actorId"}
	}
	if n := len(c.IdempotencyKey); n < minKey || n > maxKey {
		return supportaccess.Access{}, false, &FieldError{Field: "idempotencyKey"}
	}
	// a repeat of the key is answered with the access it made, whatever the body or the tenant are now (Annex C)
	if prior, found, err := s.Store.FindByKey(ctx, c.ActorID, c.IdempotencyKey); err != nil || found {
		return prior.At(s.Clock()), false, err
	}
	if !validate.UUID(c.TenantID) {
		return supportaccess.Access{}, false, &FieldError{Field: "tenantId"}
	}
	access, err := supportaccess.NewEmergency(c.TenantID, c.ActorID, c.Reason, c.Statement, c.Areas, c.Hours, c.Sensitive, c.SensitiveReason, s.Clock())
	if err != nil {
		return supportaccess.Access{}, false, fieldOf(err)
	}
	// after the fields: a form for a tenant that does not exist is judged by its fields first, as the other use cases do
	copyOfTenant, found, err := s.Tenants.FindByID(ctx, c.TenantID)
	if err != nil {
		return supportaccess.Access{}, false, err
	}
	if !found || (copyOfTenant.Status != tenant.Active && copyOfTenant.Status != tenant.Inactive) {
		return supportaccess.Access{}, false, ErrTenantNotFound
	}
	made, created, err := s.Store.OpenEmergency(ctx, access, c.IdempotencyKey, c.CorrelationID)
	return made.At(s.Clock()), created, err
}

// fieldOf names the field of the body that the rule refused; an error that is no rule of the body goes up as it is.
func fieldOf(err error) error {
	switch {
	case errors.Is(err, supportaccess.ErrInvalidReason):
		return &FieldError{Field: "reason"}
	case errors.Is(err, supportaccess.ErrInvalidStatement):
		return &FieldError{Field: "statement"}
	case errors.Is(err, supportaccess.ErrInvalidAreas):
		return &FieldError{Field: "areas"}
	case errors.Is(err, supportaccess.ErrInvalidHours):
		return &FieldError{Field: "hours"}
	case errors.Is(err, supportaccess.ErrInvalidSensitiveReason):
		return &FieldError{Field: "sensitiveReason"}
	case errors.Is(err, supportaccess.ErrSensitiveReasonWithoutFlag):
		return &FieldError{Field: "sensitive"}
	}
	return err
}
