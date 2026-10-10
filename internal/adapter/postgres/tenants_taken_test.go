package postgres_test

import (
	"errors"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// The caller is told the identifier is held by another tenant with a type it can act on, and the driver's error stays
// reachable for the log.
func TestI_AnIdentifierHeldByAnotherTenantIsTheErrorTheCallerCanRetry(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	apply(t, tenants, copyAt(coretenant.Active, 0))
	other := copyAt(coretenant.Active, 1)
	other.TenantID = otherTenant
	_, err := tenants.Apply(ctx, other)
	if !errors.Is(err, port.ErrIdentifierTaken) || pgCode(err) != "23505" {
		t.Fatalf("on insert: %v", err)
	}
	own := copyAt(coretenant.Active, 0)
	own.TenantID, own.Identifier = otherTenant, "second-tenant"
	apply(t, tenants, own)
	takes := copyAt(coretenant.Active, 20)
	takes.TenantID = otherTenant
	if _, err := tenants.Apply(ctx, takes); !errors.Is(err, port.ErrIdentifierTaken) {
		t.Fatalf("on update: %v", err)
	}
	if _, err := tenants.Apply(ctx, copyAt("DELETED", 30)); errors.Is(err, port.ErrIdentifierTaken) {
		t.Fatalf("a bad status is not a collision: %v", err)
	}
}
