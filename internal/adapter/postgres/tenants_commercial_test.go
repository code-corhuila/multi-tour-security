package postgres_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

func TestI_TheTenantCopyKeepsTheCommercialNameAndAnEventWithoutOneDoesNotErase(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	named := copyAt(coretenant.Active, 0)
	named.CommercialName = "Travesía Natural SAS"
	apply(t, tenants, named)
	for _, got := range []coretenant.Copy{find(t, tenants, "travesia-natural"), findByID(t, tenants, tenant)} {
		if got.CommercialName != "Travesía Natural SAS" {
			t.Fatalf("commercial name = %q", got.CommercialName)
		}
	}
	// a later event that does not carry the name keeps the one already known
	apply(t, tenants, copyAt(coretenant.Inactive, 1))
	if got := find(t, tenants, "travesia-natural"); got.Status != coretenant.Inactive || got.CommercialName != "Travesía Natural SAS" {
		t.Fatalf("copy = %+v, want the new status and the old name", got)
	}
	// a later event with another name replaces it
	renamed := copyAt(coretenant.Active, 2)
	renamed.CommercialName = "Travesía Natural Tours"
	apply(t, tenants, renamed)
	if got := find(t, tenants, "travesia-natural"); got.CommercialName != "Travesía Natural Tours" {
		t.Fatalf("commercial name = %q", got.CommercialName)
	}
}

func findByID(t *testing.T, tenants *postgres.Tenants, id string) coretenant.Copy {
	t.Helper()
	got, found, err := tenants.FindByID(ctx, id)
	if err != nil || !found {
		t.Fatalf("FindByID(%q): %+v %v %v", id, got, found, err)
	}
	return got
}

func TestI_ACommercialNameOfMoreThanAHundredCharactersIsCutAndNeverRejectsTheEvent(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	long := copyAt(coretenant.Active, 0)
	long.CommercialName = strings.Repeat("é", 130)
	apply(t, tenants, long)
	if got := find(t, tenants, "travesia-natural"); utf8.RuneCountInString(got.CommercialName) != 100 || got.Status != coretenant.Active {
		t.Fatalf("copy = %d characters of name, status %s: the status must be kept and the name cut to 100", utf8.RuneCountInString(got.CommercialName), got.Status)
	}
}
