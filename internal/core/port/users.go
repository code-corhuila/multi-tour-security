package port

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

// UserFilter narrows the listing of the users of a tenant. Roles are the roles that count as the ones to list: the use case
// puts the internal roles there, so that a customer is never listed whatever the caller asks, and an empty list matches
// nobody, never everybody. Status is empty for any.
type UserFilter struct {
	Roles  []string
	Status string
}

// UserDirectory is the read side of the users of a tenant (spec 003, RN-SEC-003-07).
type UserDirectory interface {
	// List returns one page of the accounts of the tenant that hold one of the roles of the filter, newest first with a stable
	// order, and the total that the filter matches whatever the page. The hash of a password is never part of the answer.
	List(ctx context.Context, tenantID string, f UserFilter, limit, offset int) ([]Registered, int, error)
}

var (
	// ErrUserNotFound is a user that is not an internal user of that tenant: another tenant's, a customer's, the platform's or none.
	ErrUserNotFound = errors.New("the user does not exist in the tenant")
	// ErrStatusTransition is a change to the status the account already has, or from a status that cannot make it.
	ErrStatusTransition = errors.New("the account cannot go to that status from the one it has")
)

// StatusChange is the last change of status of an account: who, when and why. The zero value is an account that never changed.
type StatusChange struct {
	At     time.Time
	By     string
	Reason string
}

// StatusCommand asks to inactivate (To Inactive) or reactivate (To Active) one internal user. By is the actor as it is
// recorded with the account and ActorID is the same actor's id as the event shows it.
type StatusCommand struct {
	TenantID      string
	AccountID     string
	To            account.Status
	By            string
	ActorID       string
	Reason        string
	CorrelationID string
	Now           time.Time
}

// UserStatus changes the status of an internal user of a tenant (spec 003, RN-SEC-003-09 and -10).
type UserStatus interface {
	// ChangeStatus does it in one transaction: the status, who, when and why, and, when it inactivates, the cutoff that cuts
	// the sessions the account had and the event AccountSessionsRevoked with the actor and the reason, all or nothing. It
	// answers the user as it is now. Its refusals are ErrUserNotFound and ErrStatusTransition.
	ChangeStatus(ctx context.Context, c StatusCommand) (Registered, error)
}
