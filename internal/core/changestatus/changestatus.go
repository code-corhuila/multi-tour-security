// Package changestatus is the use case that inactivates and reactivates an internal user of a tenant (HU-SEC-005,
// RN-SEC-003-09 and -10).
package changestatus

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// ErrInvalid and FieldError are those every use case shares.
var ErrInvalid = validate.ErrInvalid

type FieldError = validate.FieldError

const maxReason = 500

// Request is one change. The tenant and the actor are those of the credential, never of the body.
type Request struct {
	TenantID      string
	AccountID     string
	ActorID       string
	Reason        string
	CorrelationID string
}

// Service changes the status through the store the composition root gives it.
type Service struct {
	Store port.UserStatus
	Clock func() time.Time
}

// Inactivate cuts the access of an active user and their sessions.
func (s *Service) Inactivate(ctx context.Context, r Request) (port.Registered, error) {
	return s.change(ctx, r, account.Inactive)
}

// Reactivate gives back the access of an inactive user, on the same record.
func (s *Service) Reactivate(ctx context.Context, r Request) (port.Registered, error) {
	return s.change(ctx, r, account.Active)
}

func (s *Service) change(ctx context.Context, r Request, to account.Status) (port.Registered, error) {
	if s.Store == nil || s.Clock == nil {
		return port.Registered{}, errors.New("the status change is not wired: the store and the clock are needed")
	}
	reason := strings.TrimSpace(r.Reason)
	switch {
	case !validate.UUID(r.TenantID):
		return port.Registered{}, &FieldError{Field: "tenantId"}
	case !validate.UUID(r.AccountID):
		return port.Registered{}, &FieldError{Field: "accountId"}
	case !validate.UUID(r.ActorID):
		return port.Registered{}, &FieldError{Field: "actorId"}
	case reason == "" || utf8.RuneCountInString(reason) > maxReason:
		return port.Registered{}, &FieldError{Field: "reason"}
	case !validate.CorrelationID(r.CorrelationID):
		// every request has one that the HTTP adapter checked: another is a mistake of ours, not of the caller
		return port.Registered{}, errors.New("the status change has no correlation id")
	}
	return s.Store.ChangeStatus(ctx, port.StatusCommand{
		TenantID: r.TenantID, AccountID: r.AccountID, To: to, By: account.By(account.RoleTenantAdministrator, r.ActorID), ActorID: r.ActorID,
		Reason: reason, CorrelationID: r.CorrelationID, Now: s.Clock(),
	})
}
