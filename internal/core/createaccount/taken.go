package createaccount

import (
	"context"
	"errors"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// roleFinalCustomer is the role of a person who signs up by themselves.
const roleFinalCustomer = "FINAL_CUSTOMER"

// TakenReason says whose an e-mail that is already in use is, so that the Administrator who registers a user knows what to
// do about it (spec 003, RN-SEC-003-05).
type TakenReason int

const (
	// TakenByInternalUser is an internal user of the tenant who is active.
	TakenByInternalUser TakenReason = iota + 1
	// TakenByInactiveInternalUser is an internal user who can be reactivated instead of registered again.
	TakenByInactiveInternalUser
	// TakenByCustomer is an inactive Final Customer account, which a role does not bring back.
	TakenByCustomer
	// TakenByPendingCustomer is a Final Customer account whose e-mail is not verified yet: the Administrator waits for the person to verify it.
	TakenByPendingCustomer
)

// EmailTakenError is the refusal of a taken e-mail together with its reason. It is also port.ErrEmailTaken, so whoever only
// needs to know that the e-mail is taken keeps asking errors.Is.
type EmailTakenError struct{ Reason TakenReason }

func (e *EmailTakenError) Error() string        { return port.ErrEmailTaken.Error() }
func (e *EmailTakenError) Is(target error) bool { return target == port.ErrEmailTaken }

// whyTaken is the refusal for an e-mail that has an account. Only the Administrator who registers a user is told whose it
// is: a person who signs up, who is nobody yet, gets the plain refusal and learns nothing about the staff of a tenant.
func (s *Service) whyTaken(ctx context.Context, kind Kind, existing account.Account) error {
	if kind != InternalUser {
		return port.ErrEmailTaken
	}
	roles, err := s.rolesHeld(ctx, existing.ID)
	if err != nil {
		return err
	}
	if isCustomerOnly(roles) {
		if existing.Status == account.Pending {
			return &EmailTakenError{Reason: TakenByPendingCustomer}
		}
		return &EmailTakenError{Reason: TakenByCustomer}
	}
	// like the answer of the routes, a status this code does not know is refused as a failure, not read as an active user
	switch existing.Status {
	case account.Inactive:
		return &EmailTakenError{Reason: TakenByInactiveInternalUser}
	case account.Active, account.Pending:
		return &EmailTakenError{Reason: TakenByInternalUser}
	}
	return errUnknownStatus
}

var errUnknownStatus = errors.New("the existing account has a status that the use case does not know")
