package account_test

import (
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

// The two sides of an account and the context a sign-in works from (HU-SEC-008, RN-SEC-007-04 and -05).

var both = []string{"FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR"}

func TestD_TheSideNamedIsTheOneCarried(t *testing.T) {
	ctx, roles := account.ForContext(both, account.ContextTeam)
	if ctx != account.ContextTeam || !slices.Equal(roles, []string{"OPERATIONAL_COLLABORATOR"}) {
		t.Fatalf("team: %q %v", ctx, roles)
	}
	ctx, roles = account.ForContext(both, account.ContextCustomer)
	if ctx != account.ContextCustomer || !slices.Equal(roles, []string{"FINAL_CUSTOMER"}) {
		t.Fatalf("customer: %q %v", ctx, roles)
	}
}

func TestD_WithNoSideNamedTheCustomerSideIsCarried(t *testing.T) {
	for _, asked := range []string{"", "ANYTHING"} {
		ctx, roles := account.ForContext(both, asked)
		if ctx != account.ContextCustomer || !slices.Equal(roles, []string{"FINAL_CUSTOMER"}) {
			t.Fatalf("asked %q: %q %v", asked, ctx, roles)
		}
	}
}

func TestD_AnAccountWithOneSideCarriesItWhateverIsNamed(t *testing.T) {
	for _, roles := range [][]string{{"FINAL_CUSTOMER"}, {"TENANT_ADMINISTRATOR", "MANAGER"}, {"PLATFORM_ADMINISTRATOR"}} {
		for _, asked := range []string{"", account.ContextCustomer, account.ContextTeam} {
			ctx, got := account.ForContext(roles, asked)
			if ctx != "" || !slices.Equal(got, roles) {
				t.Fatalf("%v asked %q: %q %v", roles, asked, ctx, got)
			}
		}
	}
}

func TestD_TheCustomerSideCarriesNoPermission(t *testing.T) {
	_, roles := account.ForContext([]string{"FINAL_CUSTOMER", "TENANT_ADMINISTRATOR"}, account.ContextCustomer)
	assigned := []string{account.PermissionConsultSensitiveData, account.PermissionManageCash}
	if got := account.PermissionsFor(roles, assigned); len(got) != 0 {
		t.Fatalf("the customer side holds %v", got)
	}
	// the team side of the same person keeps the three of the profile and the assigned one
	_, team := account.ForContext([]string{"FINAL_CUSTOMER", "TENANT_ADMINISTRATOR"}, account.ContextTeam)
	if got := account.PermissionsFor(team, assigned); len(got) != 4 {
		t.Fatalf("the team side holds %v", got)
	}
}

func TestD_ForContextDoesNotChangeItsInput(t *testing.T) {
	in := slices.Clone(both)
	account.ForContext(in, account.ContextTeam)
	if !slices.Equal(in, both) {
		t.Fatalf("%v", in)
	}
}
