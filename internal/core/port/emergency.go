package port

import (
	"context"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

// EmergencyAccesses is what opening an emergency access needs (HU-SEC-007 part B, security spec 010).
type EmergencyAccesses interface {
	// FindByKey returns the access that the key of that author made, if any: a repeat of the key is answered with it before anything else is looked at.
	FindByKey(ctx context.Context, requestedBy, key string) (supportaccess.Access, bool, error)
	// OpenEmergency stores the access and writes the fact that it opened in the same step (RN-SEC-010-07), or, when its author already used the
	// key, returns that access with created false and stores nothing. It refuses with supportaccess.ErrOpenAccessExists when the author has
	// another access to the same tenant that is still open (RN-SEC-010-09).
	OpenEmergency(ctx context.Context, a supportaccess.Access, key, correlationID string) (access supportaccess.Access, created bool, err error)
}
