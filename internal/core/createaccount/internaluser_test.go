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

// HU-SEC-008, RN-SEC-007-01: the e-mail of an active, verified customer gets the internal role on the same account.
func TestA_AnEmailOfACustomerGetsTheInternalRole(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Active, "FINAL_CUSTOMER")
	made, created, err := w.service.Create(ctx, internalUser())
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	want := port.AddedRole{TenantID: tenantID, AccountID: existingID, Role: "OPERATIONAL_COLLABORATOR"}
	if len(w.registry.added) != 1 || w.registry.added[0] != want {
		t.Fatalf("added = %+v", w.registry.added)
	}
	if made.Account.ID != existingID || made.Account.PasswordHash != "" {
		t.Fatalf("the answer is the account of the customer, without a hash: %+v", made)
	}
	nothingWritten(t, w) // no account created, and the password of the form is never hashed
}

// RN-SEC-007-01: the repeat of the key answers the account already changed, and adds nothing.
func TestA_TheRepeatOfTheKeyAnswersTheSameAccountAndAddsNothing(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Active, "FINAL_CUSTOMER")
	if _, _, err := w.service.Create(ctx, internalUser()); err != nil {
		t.Fatal(err)
	}
	again, created, err := w.service.Create(ctx, internalUser())
	if err != nil || created || again.Account.ID != existingID || len(w.registry.added) != 1 {
		t.Fatalf("created=%v err=%v added=%d", created, err, len(w.registry.added))
	}
}

// RN-SEC-007-02: a customer whose e-mail is not verified is refused, and told so.
func TestA_APendingCustomerIsRefusedAsPending(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Pending, "FINAL_CUSTOMER")
	_, _, err := w.service.Create(ctx, internalUser())
	if got := reasonOf(t, err); got != createaccount.TakenByPendingCustomer {
		t.Fatalf("reason = %v", got)
	}
	nothingWritten(t, w)
	if len(w.registry.added) != 0 {
		t.Fatal("a pending customer got a role")
	}
}

// An inactive customer account is not brought back by a role: it keeps its refusal.
func TestA_AnInactiveCustomerIsRefusedAsACustomer(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Inactive, "FINAL_CUSTOMER")
	_, _, err := w.service.Create(ctx, internalUser())
	if got := reasonOf(t, err); got != createaccount.TakenByCustomer {
		t.Fatalf("reason = %v", got)
	}
	nothingWritten(t, w)
	if len(w.registry.added) != 0 {
		t.Fatal("an inactive customer got a role")
	}
}

// A customer who already holds an internal role is an internal user: a second role is not added.
func TestA_ACustomerWhoIsAlreadyStaffIsAnInternalUser(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Active, "FINAL_CUSTOMER", "MANAGER")
	_, _, err := w.service.Create(ctx, internalUser())
	if got := reasonOf(t, err); got != createaccount.TakenByInternalUser {
		t.Fatalf("reason = %v", got)
	}
	if len(w.registry.added) != 0 {
		t.Fatal("a second internal role was added")
	}
}

// RN-SEC-007-03: the store refuses an optional role the tenant has not enabled, and that refusal reaches the caller.
func TestA_ARoleTheTenantHasNotEnabledIsRefusedForACustomerToo(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Active, "FINAL_CUSTOMER")
	w.registry.addFn = func(port.AddedRole) error { return port.ErrRoleNotEnabled }
	c := internalUser()
	c.Role = "ANALYST"
	if _, _, err := w.service.Create(ctx, c); !errors.Is(err, port.ErrRoleNotEnabled) {
		t.Fatalf("err = %v", err)
	}
}

// RN-SEC-007-10: the same e-mail in another tenant is another person; this tenant gets its own account.
func TestA_ACustomerOfAnotherTenantIsNotTouched(t *testing.T) {
	w := newWorld()
	w.accounts.byKey[otherTenant+"|luis@example.com"] = account.Account{ID: "acc-other", TenantID: otherTenant, Status: account.Active}
	w.accounts.roles["acc-other"] = []string{"FINAL_CUSTOMER"}
	if _, created, err := w.service.Create(ctx, internalUser()); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if len(w.registry.added) != 0 || len(w.registry.created) != 1 {
		t.Fatalf("added=%d created=%d", len(w.registry.added), len(w.registry.created))
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

// A status the use case does not know is a failure of the platform, never read as an active user: the refusal would tell the
// Administrator something that nobody checked.
func TestA_AnAccountWithAStatusItDoesNotKnowIsAFailureAndNotARefusal(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Status(99), "MANAGER")
	_, _, err := w.service.Create(ctx, internalUser())
	if err == nil || errors.Is(err, port.ErrEmailTaken) {
		t.Fatalf("err = %v, want a failure that is not the refusal of a taken e-mail", err)
	}
	nothingWritten(t, w)
}
