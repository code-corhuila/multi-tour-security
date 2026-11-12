// Package changestatus is the use case that inactivates and reactivates an internal user of a tenant (HU-SEC-005,
// RN-SEC-003-09 and -10).
package changestatus

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// ErrInvalid is any part of the request that is not valid; FieldError says which.
var ErrInvalid = errors.New("the request is not valid")

// FieldError names the field that was refused, never its value.
type FieldError struct{ Field string }

func (e *FieldError) Error() string        { return e.Field + ": is not valid" }
func (e *FieldError) Is(target error) bool { return target == ErrInvalid }

const (
	maxReason        = 500
	maxCorrelationID = 128 // what the outbox takes
)

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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
	case !uuid.MatchString(r.TenantID):
		return port.Registered{}, &FieldError{Field: "tenantId"}
	case !uuid.MatchString(r.AccountID):
		return port.Registered{}, &FieldError{Field: "accountId"}
	case !uuid.MatchString(r.ActorID):
		return port.Registered{}, &FieldError{Field: "actorId"}
	case reason == "" || utf8.RuneCountInString(reason) > maxReason:
		return port.Registered{}, &FieldError{Field: "reason"}
	case r.CorrelationID == "" || len(r.CorrelationID) > maxCorrelationID:
		// every request has one that the HTTP adapter checked: another is a mistake of ours, not of the caller
		return port.Registered{}, errors.New("the status change has no correlation id")
	}
	return s.Store.ChangeStatus(ctx, port.StatusCommand{
		TenantID: r.TenantID, AccountID: r.AccountID, To: to, By: "tenant-administrator/" + r.ActorID, ActorID: r.ActorID,
		Reason: reason, CorrelationID: r.CorrelationID, Now: s.Clock(),
	})
}
