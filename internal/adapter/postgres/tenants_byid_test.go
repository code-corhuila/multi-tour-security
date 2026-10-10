package postgres_test

import (
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// A renewal knows the tenant by the id in the account, not by the identifier of a link.
func TestI_ATenantIsFoundByItsIdAndOnlyThere(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	apply(t, tenants, copyAt(coretenant.Inactive, 3))
	got, found, err := tenants.FindByID(ctx, tenant)
	if err != nil || !found || got.Identifier != "travesia-natural" || got.Status != coretenant.Inactive || !got.OccurredAt.Equal(base.Add(3*time.Minute)) {
		t.Fatalf("FindByID = %+v %v %v", got, found, err)
	}
	if _, found, err := tenants.FindByID(ctx, otherTenant); found || err != nil {
		t.Errorf("an unknown tenant is found=false with no error: %v %v", found, err)
	}
	if _, found, err := tenants.FindByID(ctx, "not-a-uuid"); found || err == nil {
		t.Errorf("an id that is not a UUID is an error and not a silent miss: %v %v", found, err)
	}
}
