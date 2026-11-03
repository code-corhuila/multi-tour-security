package port

import "context"

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
