// Package tenant is what this service knows of a tenant: a copy kept from the events of identity-audit, never asked
// at sign-in (ADR-004 D5). It imports only the standard library.
package tenant

import (
	"fmt"
	"time"
)

// Status of a tenant as identity-audit publishes it.
type Status string

const (
	Pending  Status = "PENDING"
	Active   Status = "ACTIVE"
	Inactive Status = "INACTIVE"
	Failed   Status = "FAILED"
)

// ParseStatus accepts exactly the four names, in capitals and with nothing around them.
func ParseStatus(name string) (Status, error) {
	switch s := Status(name); s {
	case Pending, Active, Inactive, Failed:
		return s, nil
	}
	return "", fmt.Errorf("%q is not a tenant status", name)
}

// Copy is the state of a tenant at the instant of the newest event applied.
type Copy struct {
	TenantID   string
	Identifier string
	Status     Status
	OccurredAt time.Time
}

// IsActive tells whether everyone of the tenant may sign in.
func (c Copy) IsActive() bool { return c.Status == Active }
