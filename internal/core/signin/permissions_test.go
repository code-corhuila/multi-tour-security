package signin_test

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// HU-SEC-006, RN-SEC-005-03 to -06 and -11: the token carries the whole set of permissions of the person, as the list shows it.

var profile = []string{"MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "VALIDATE_PAYMENT_PROOFS"}

func signInAs(t *testing.T, roles []string, assigned []string, edit func(*account.Account)) (token.Claims, *world) {
	t.Helper()
	w := newWorld()
	w.add("acc-1", tenantID, "ana@example.com", roles, edit)
	w.accounts.assigned = map[string][]string{"acc-1": assigned}
	if _, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); err != nil {
		t.Fatal(err)
	}
	return w.signer.claims[0], w
}

func TestA_TheAdministratorTokenCarriesTheThreeProfilePermissionsAndNotSensitiveDataUntilItIsAssigned(t *testing.T) {
	c, _ := signInAs(t, []string{"TENANT_ADMINISTRATOR"}, nil, nil)
	if !slices.Equal(c.Permissions, profile) {
		t.Fatalf("%v: the Administrator holds three by profile and never the fourth until it is assigned", c.Permissions)
	}
	c, _ = signInAs(t, []string{"TENANT_ADMINISTRATOR"}, []string{"CONSULT_SENSITIVE_DATA"}, nil)
	if !slices.Contains(c.Permissions, "CONSULT_SENSITIVE_DATA") || len(c.Permissions) != 4 {
		t.Fatalf("%v", c.Permissions)
	}
}

func TestA_ACollaboratorTokenCarriesWhatWasAssignedSortedAndNothingElse(t *testing.T) {
	c, _ := signInAs(t, []string{"OPERATIONAL_COLLABORATOR"}, []string{"MANAGE_CASH", "CONSULT_SENSITIVE_DATA"}, nil)
	if !slices.Equal(c.Permissions, []string{"CONSULT_SENSITIVE_DATA", "MANAGE_CASH"}) {
		t.Fatalf("%v", c.Permissions)
	}
	c, _ = signInAs(t, []string{"OPERATIONAL_COLLABORATOR"}, nil, nil)
	if c.Permissions == nil || len(c.Permissions) != 0 {
		t.Fatalf("a collaborator with none carries an empty list and never null: %#v", c.Permissions)
	}
}

func TestA_AnOptionalRoleACustomerAndAnyoneElseCarryNoPermissionWhateverWasWritten(t *testing.T) {
	for _, role := range []string{"MANAGER", "ACCOUNTANT", "ANALYST", "FINAL_CUSTOMER"} {
		c, _ := signInAs(t, []string{role}, []string{"MANAGE_CASH", "CONSULT_SENSITIVE_DATA"}, nil)
		if c.Permissions == nil || len(c.Permissions) != 0 {
			t.Errorf("%s carries %#v", role, c.Permissions)
		}
	}
}

func TestA_TheTemporaryCredentialCarriesNoPermissionAndTheStoreIsNotEvenAsked(t *testing.T) {
	c, w := signInAs(t, []string{"TENANT_ADMINISTRATOR"}, []string{"CONSULT_SENSITIVE_DATA"}, func(a *account.Account) { a.TemporaryUntil = now.Add(time.Hour) })
	if c.Access != token.PasswordChangeAccess || len(c.Permissions) != 0 || w.accounts.permCalls != 0 {
		t.Fatalf("%+v asked %d times", c, w.accounts.permCalls)
	}
}

func TestA_TheRestrictedAdministratorOfAnInactiveTenantCarriesTheSameList(t *testing.T) {
	w := newWorld()
	w.add("acc-1", otherID, "boss@example.com", []string{"TENANT_ADMINISTRATOR"}, nil)
	if _, err := w.service.SignIn(ctx, request("parked", "boss@example.com", password)); err != nil {
		t.Fatal(err)
	}
	c := w.signer.claims[0]
	if c.Access != token.RestrictedAccess || !slices.Equal(c.Permissions, profile) {
		t.Fatalf("the services already limit it by the access mark: %+v", c)
	}
}

func TestA_AUserReactivatedSignsInWithThePermissionThatTheStoreStillHolds(t *testing.T) {
	c, _ := signInAs(t, []string{"OPERATIONAL_COLLABORATOR"}, []string{"VALIDATE_PAYMENT_PROOFS"}, nil)
	if !reflect.DeepEqual(c.Permissions, []string{"VALIDATE_PAYMENT_PROOFS"}) {
		t.Fatalf("an inactive user keeps what they held and gets it back on reactivation: %v", c.Permissions)
	}
}

func TestA_AFailureReadingThePermissionsIsOurFailureAndRecordsNoSuccess(t *testing.T) {
	w := newWorld()
	w.add("acc-1", tenantID, "ana@example.com", []string{"OPERATIONAL_COLLABORATOR"}, nil)
	boom := errors.New("boom")
	w.accounts.permErr = boom
	if _, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	if len(w.accounts.successes) != 0 || len(w.signer.claims) != 0 {
		t.Fatal("a sign-in that could not read the permissions must not clear the failures nor issue a token")
	}
}
