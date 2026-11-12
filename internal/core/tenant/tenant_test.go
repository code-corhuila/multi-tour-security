package tenant_test

import (
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// RN-SEC-001-11: the service knows the status of each tenant from the events of identity-audit.

func TestD_EveryStatusOfATenantIsParsedToItsTypedConstant(t *testing.T) {
	want := map[string]tenant.Status{"PENDING": tenant.Pending, "ACTIVE": tenant.Active, "INACTIVE": tenant.Inactive, "FAILED": tenant.Failed}
	for name, constant := range want {
		got, err := tenant.ParseStatus(name)
		if err != nil || got != constant || string(constant) != name {
			t.Errorf("ParseStatus(%q) = %q, %v; the constant is %q", name, got, err, constant)
		}
	}
}

func TestD_AStatusThatIsNotOneOfTheFourIsRefused(t *testing.T) {
	for _, name := range []string{"", "active", "Active", " ACTIVE", "ACTIVE ", "DELETED", "ACTIVE\n"} {
		if _, err := tenant.ParseStatus(name); err == nil {
			t.Errorf("ParseStatus(%q) was accepted", name)
		}
	}
}

func TestD_OnlyAnActiveCopyIsActiveAndAnUnknownOrEmptyOneNever(t *testing.T) {
	want := map[tenant.Status]bool{tenant.Pending: false, tenant.Active: true, tenant.Inactive: false, tenant.Failed: false, "": false, "DELETED": false}
	for status, open := range want {
		if got := (tenant.Copy{Status: status}).IsActive(); got != open {
			t.Errorf("IsActive() of %q = %v", status, got)
		}
	}
	if (tenant.Copy{}).IsActive() {
		t.Error("a zero copy is not active")
	}
}

func TestD_TheDisplayNameIsTheCommercialNameOrThePlatformsOwn(t *testing.T) {
	if got := (tenant.Copy{CommercialName: "Acme Tours"}).DisplayName(); got != "Acme Tours" {
		t.Fatalf("display name = %q", got)
	}
	if got := (tenant.Copy{}).DisplayName(); got != "Multitour" {
		t.Fatalf("display name = %q, want the platform's", got)
	}
}
