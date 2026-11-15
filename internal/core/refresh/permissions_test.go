package refresh_test

import (
	"errors"
	"slices"
	"testing"
)

// HU-SEC-006, RN-SEC-005-03 to -06 and -10: the renewed token carries the permissions of now, so an assignment reaches the next refresh.

func renewWith(t *testing.T, w *world) []string {
	t.Helper()
	if _, err := w.service.Renew(ctx, oldValue); err != nil {
		t.Fatal(err)
	}
	return w.signer.claims[len(w.signer.claims)-1].Permissions
}

func TestA_TheRenewedTokenOfTheAdministratorCarriesTheThreeProfilePermissions(t *testing.T) {
	w := newWorld()
	w.accounts.roles[accountID] = []string{"TENANT_ADMINISTRATOR"}
	if got := renewWith(t, w); !slices.Equal(got, []string{"MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "VALIDATE_PAYMENT_PROOFS"}) {
		t.Fatalf("%v", got)
	}
}

func TestA_ApermissionAssignedBetweenTwoRenewalsReachesTheSecondAndAnotherRemovedLeavesIt(t *testing.T) {
	w := newWorld()
	w.accounts.roles[accountID] = []string{"OPERATIONAL_COLLABORATOR"}
	if got := renewWith(t, w); got == nil || len(got) != 0 {
		t.Fatalf("before the assignment: %#v", got)
	}
	w.accounts.assigned = map[string][]string{accountID: {"MANAGE_CASH"}}
	if got := renewWith(t, w); !slices.Equal(got, []string{"MANAGE_CASH"}) {
		t.Fatalf("the assignment reaches the next refresh: %v", got)
	}
	w.accounts.assigned = map[string][]string{accountID: nil}
	if got := renewWith(t, w); len(got) != 0 {
		t.Fatalf("a removal leaves the next one: %v", got)
	}
}

func TestA_ARenewedTokenOfAnOptionalRoleCarriesNoPermissionWhateverWasWritten(t *testing.T) {
	w := newWorld()
	w.accounts.roles[accountID] = []string{"MANAGER"}
	w.accounts.assigned = map[string][]string{accountID: {"MANAGE_CASH"}}
	if got := renewWith(t, w); got == nil || len(got) != 0 {
		t.Fatalf("%#v", got)
	}
}

func TestA_AFailureReadingThePermissionsFailsTheRenewalAndNoTokenIsIssued(t *testing.T) {
	w := newWorld()
	boom := errors.New("boom")
	w.accounts.permErr = boom
	if _, err := w.service.Renew(ctx, oldValue); !errors.Is(err, boom) || len(w.signer.claims) != 0 {
		t.Fatalf("%v", err)
	}
}
