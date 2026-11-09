package createaccount

import (
	"context"
	"errors"
	"strings"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// whenTaken answers an e-mail that already has an account. The Administrator who registers an internal user over the account of an
// active, verified Final Customer gives that account the internal role, with no new account and no new password (HU-SEC-008,
// RN-SEC-007-01); every other case is the refusal that says whose the e-mail is.
func (s *Service) whenTaken(ctx context.Context, c Command, existing account.Account, scope string) (port.Registered, bool, error) {
	if c.Kind == InternalUser && existing.Status == account.Active {
		roles, err := s.Accounts.RolesOf(ctx, existing.ID)
		if err != nil {
			return port.Registered{}, false, err
		}
		if isCustomerOnly(roles) {
			made, err := s.Registry.AddRole(ctx, port.AddedRole{TenantID: c.TenantID, AccountID: existing.ID, Role: strings.TrimSpace(c.Role)}, scope, c.IdempotencyKey)
			if errors.Is(err, port.ErrKeyTaken) {
				// another request with the same key won the race: the answer is the repeat of its account
				prior, found, ferr := s.Registry.FindKey(ctx, scope, c.IdempotencyKey)
				if ferr == nil && !found {
					ferr = errors.New("the idempotency key was taken and cannot be read")
				}
				return withoutHash(prior), false, ferr
			}
			return withoutHash(made), err == nil, err
		}
	}
	return port.Registered{}, false, s.whyTaken(ctx, c.Kind, existing)
}

// isCustomerOnly tells an account that holds the customer role and no internal one.
func isCustomerOnly(roles []string) bool {
	customer := false
	for _, role := range roles {
		switch {
		case role == roleFinalCustomer:
			customer = true
		case account.IsInternalRole(role):
			return false
		}
	}
	return customer
}
