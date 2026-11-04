package port

import (
	"context"
	"time"
)

// PermissionHolder is what the core needs to know about a user to decide whether a special permission may be assigned or removed:
// their role and the permissions they hold now (spec 005, plan D-08).
type PermissionHolder struct {
	Role string
	Held []string
}

// PermissionChange asks to assign or remove one special permission of one internal user of a tenant. By is the actor as it is
// recorded with the permission and ActorID and ActorRole are the same actor as the events show them.
type PermissionChange struct {
	TenantID      string
	AccountID     string
	Permission    string
	By            string
	ActorID       string
	ActorRole     string
	CorrelationID string
	Now           time.Time
}

// UserPermissions is where the special permissions of the users of a tenant are kept (HU-SEC-006, RN-SEC-005-07 to -09).
type UserPermissions interface {
	// Holder reads the facts of the user, or ErrUserNotFound when they are not an internal user of the tenant: another tenant's, a
	// customer's, the platform's or none.
	Holder(ctx context.Context, tenantID, accountID string) (PermissionHolder, error)
	// Grant makes the user hold the permission and writes who and when and the event SpecialPermissionGranted, together. A
	// permission they already hold changes nothing: no row and no event. It cuts no session. It answers the user as they are
	// now, or ErrUserNotFound.
	Grant(ctx context.Context, c PermissionChange) (Registered, error)
	// Remove takes the permission away and, in the same transaction, cuts every session of the user (the cutoff and the event
	// AccountSessionsRevoked with the actor and the reason) and writes SpecialPermissionRevoked, or nothing. A permission they do
	// not hold changes nothing. It answers the user as they are now, or ErrUserNotFound.
	Remove(ctx context.Context, c PermissionChange) (Registered, error)
}
