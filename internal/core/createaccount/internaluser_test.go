package createaccount_test

import (
	"errors"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-005, RN-SEC-003-03: the Administrator types the password of a user and its confirmation, like a customer does.
func TestA_TheConfirmationMustMatchForAnInternalUserToo(t *testing.T) {
	w := newWorld()
	c := internalUser()
	c.Confirmation = goodPass + "x"
	_, _, err := w.service.Create(ctx, c)
	if got := fieldOf(t, err); got != "passwordConfirmation" {
		t.Fatalf("field = %q", got)
	}
	nothingWritten(t, w)
}

// The first Administrator is made by the saga, which sends no confirmation: that kind does not ask for one.
func TestA_TheFirstAdministratorNeedsNoConfirmation(t *testing.T) {
	w := newWorld()
	c := firstAdministrator()
	c.Confirmation = ""
	if _, created, err := w.service.Create(ctx, c); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}

// takenBy puts an existing account with that e-mail in the tenant, with its status and roles.
func takenBy(w *world, status account.Status, roles ...string) {
	w.accounts.byKey[tenantID+"|luis@example.com"] = account.Account{ID: existingID, TenantID: tenantID, Status: status}
	w.accounts.roles[existingID] = roles
}

func reasonOf(t *testing.T, err error) createaccount.TakenReason {
	t.Helper()
	if !errors.Is(err, port.ErrEmailTaken) {
		t.Fatalf("err = %v, want the refusal of a taken e-mail", err)
	}
	var taken *createaccount.EmailTakenError
	if !errors.As(err, &taken) {
		t.Fatalf("err = %v, want an EmailTakenError that says why", err)
	}
	return taken.Reason
}

// RN-SEC-003-05: the refusal of an e-mail says whose it is, so the Administrator knows what to do.
func TestA_EmailOfAnActiveInternalUserIsRefusedWithItsReason(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Active, "OPERATIONAL_COLLABORATOR")
	_, _, err := w.service.Create(ctx, internalUser())
	if got := reasonOf(t, err); got != createaccount.TakenByInternalUser {
		t.Fatalf("reason = %v", got)
	}
	nothingWritten(t, w)
}

// RN-SEC-003-05, RN-SEC-003-10: an inactive user is told apart, because they can be reactivated.
func TestA_EmailOfAnInactiveInternalUserSaysItCanBeReactivated(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Inactive, "ANALYST")
	_, _, err := w.service.Create(ctx, internalUser())
	if got := reasonOf(t, err); got != createaccount.TakenByInactiveInternalUser {
		t.Fatalf("reason = %v", got)
	}
	nothingWritten(t, w)
}

// RN-SEC-003-05: until HU-SEC-008 adds the role to the account, the e-mail of a customer is refused as such.
func TestA_EmailOfACustomerIsRefusedUntilHuSec008(t *testing.T) {
	for _, status := range []account.Status{account.Pending, account.Active, account.Inactive} {
		w := newWorld()
		takenBy(w, status, "FINAL_CUSTOMER")
		_, _, err := w.service.Create(ctx, internalUser())
		if got := reasonOf(t, err); got != createaccount.TakenByCustomer {
			t.Fatalf("status %d: reason = %v", status, got)
		}
		nothingWritten(t, w)
	}
}

// The public sign-up of a customer keeps its plain refusal: it must not tell a stranger that the e-mail belongs to staff.
func TestA_TheCustomerSignUpKeepsItsPlainRefusal(t *testing.T) {
	w := newWorld()
	w.accounts.byKey[tenantID+"|ana@example.com"] = account.Account{ID: existingID, TenantID: tenantID, Status: account.Active}
	w.accounts.roles[existingID] = []string{"MANAGER"}
	_, _, err := w.service.Create(ctx, customer())
	if !errors.Is(err, port.ErrEmailTaken) {
		t.Fatalf("err = %v", err)
	}
	var taken *createaccount.EmailTakenError
	if errors.As(err, &taken) {
		t.Fatalf("a public caller must not learn whose the e-mail is: %v", taken.Reason)
	}
}
