// Package tenantevent is the use case that learns the status of a tenant from the events of identity-audit, which job 7
// delivers once or more, in any order (ADR-004 D4 and D5, RN-SEC-001-11). It imports only the standard library and the
// rest of the core.
package tenantevent

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

var (
	// ErrInvalid is an envelope that contradicts itself or breaks the contract.
	ErrInvalid = errors.New("the event is not valid")
	// ErrRetryLater is an event that cannot be applied yet, because another tenant still holds its identifier; the
	// delivery is repeated and the identifier is free when the event that renames the other tenant has arrived.
	ErrRetryLater = errors.New("the identifier is held by another tenant for now")
)

// Event is the envelope as the route read it. PathTenantID is the one of the URL; the others are the ones of the body.
type Event struct {
	PathTenantID    string
	EventID         string
	Type            string
	Version         int
	TenantID        string
	AggregateID     string
	PayloadTenantID string // empty when the payload does not name it
	Identifier      string
	Status          string
	// CommercialName is the visible name of the tenant in the payload; empty when the event does not carry it.
	CommercialName string
	OccurredAt     time.Time
}

var (
	uuid       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	identifier = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

// Service holds the copy of the tenants.
type Service struct {
	Tenants port.Tenants
}

// Receive checks the envelope and gives the state it describes to the copy, which keeps it only if it is the newest.
// It says whether the copy changed.
func (s *Service) Receive(ctx context.Context, e Event) (bool, error) {
	if s.Tenants == nil {
		return false, errors.New("the receiver of events is not wired")
	}
	state, err := check(e)
	if err != nil {
		return false, err
	}
	applied, err := s.Tenants.Apply(ctx, state)
	if errors.Is(err, port.ErrIdentifierTaken) {
		return false, ErrRetryLater
	}
	return applied, err
}

// check reads the envelope as a state of a tenant. The three ids are one: the one of the URL, the one of the body, the
// one of the aggregate, and the one of the payload when it names it. An inactivation says INACTIVE and a reactivation
// says ACTIVE; a creation may say any status, because the payload is the full new state and that is what is believed.
func check(e Event) (tenant.Copy, error) {
	status, statusErr := tenant.ParseStatus(e.Status)
	switch {
	case !uuid.MatchString(e.EventID), !uuid.MatchString(e.TenantID):
	case e.PathTenantID != e.TenantID, e.AggregateID != e.TenantID, e.PayloadTenantID != "" && e.PayloadTenantID != e.TenantID:
	case e.Version < 1, e.OccurredAt.IsZero(), statusErr != nil:
	case len(e.Identifier) < 3, len(e.Identifier) > 40, !identifier.MatchString(e.Identifier):
	case e.Type == "TenantCreated":
		return copyOf(e, status), nil
	case e.Type == "TenantInactivated" && status == tenant.Inactive, e.Type == "TenantReactivated" && status == tenant.Active:
		return copyOf(e, status), nil
	}
	return tenant.Copy{}, ErrInvalid
}

func copyOf(e Event, status tenant.Status) tenant.Copy {
	return tenant.Copy{TenantID: e.TenantID, Identifier: e.Identifier, Status: status, OccurredAt: e.OccurredAt}
}
