package httpadapter

import (
	"context"

	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// AccountCreator is what the routes that make accounts need from the use case, so a test can replace it.
type AccountCreator interface {
	Create(ctx context.Context, c createaccount.Command) (port.Registered, bool, error)
}

// TenantFinder resolves the identifier of a link to the copy of its tenant.
type TenantFinder interface {
	FindByIdentifier(ctx context.Context, identifier string) (tenant.Copy, bool, error)
}

// WithCreateAccount registers the public route where a person creates the account of a Final Customer.
func WithCreateAccount(service AccountCreator, tenants TenantFinder) Option {
	return func(s *server) { s.accounts, s.accountTenants = service, tenants }
}
