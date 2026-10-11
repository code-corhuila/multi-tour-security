package createaccount_test

import (
	"errors"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

func TestA_TheAnswerNeverCarriesTheHashOnTheCreatedPathNorOnTheRepeat(t *testing.T) {
	w := newWorld()
	first, _, err := w.service.Create(ctx, customer())
	if err != nil || first.Account.PasswordHash != "" {
		t.Fatalf("created answer: err=%v hash=%q", err, first.Account.PasswordHash)
	}
	again, created, err := w.service.Create(ctx, customer())
	if err != nil || created || again.Account.PasswordHash != "" {
		t.Fatalf("repeat answer: created=%v err=%v hash=%q", created, err, again.Account.PasswordHash)
	}
	raced := newWorld()
	raced.registry.createFn = func(port.NewAccount) error {
		raced.registry.keys = map[string]port.Registered{"customer:" + tenantID + "|" + idemKey: {Account: account.Account{PasswordHash: "h"}}}
		return port.ErrKeyTaken
	}
	got, _, err := raced.service.Create(ctx, customer())
	if err != nil || got.Account.PasswordHash != "" {
		t.Fatalf("raced answer: err=%v hash=%q", err, got.Account.PasswordHash)
	}
}

func TestA_AnInternalUserTakesOnlyTheRolesOfATenantAndNeverAPlatformOrCustomerRole(t *testing.T) {
	for _, role := range []string{"TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "MANAGER", "ACCOUNTANT", "ANALYST"} {
		w := newWorld()
		c := internalUser()
		c.Role = role
		if _, created, err := w.service.Create(ctx, c); err != nil || !created || w.registry.created[0].Role != role {
			t.Fatalf("%s must be accepted: created=%v err=%v", role, created, err)
		}
	}
	for _, role := range []string{"PLATFORM_ADMINISTRATOR", "FINAL_CUSTOMER", "SERVICE", "root", "manager", ""} {
		w := newWorld()
		c := internalUser()
		c.Role = role
		_, _, err := w.service.Create(ctx, c)
		if fieldOf(t, err) != "role" {
			t.Fatalf("%q must be refused on role: %v", role, err)
		}
		nothingWritten(t, w)
	}
}

// plan D-03 fixes the order: the shape of the form (3), the tenant (4), the password policy (5), the e-mail (6).
func TestA_PlanD03TheTenantIsCheckedBeforeThePasswordPolicyAndTheEmail(t *testing.T) {
	weak := func(c createaccount.Command) createaccount.Command {
		c.Password, c.Confirmation = "weakpass", "weakpass"
		return c
	}
	w := newWorld()
	c := weak(customer())
	c.TenantID = otherTenant
	if _, _, err := w.service.Create(ctx, c); !errors.Is(err, createaccount.ErrTenantNotFound) {
		t.Fatalf("weak password and unknown tenant: %v", err)
	}
	w = newWorld()
	w.tenants.copies[tenantID] = tenant.Copy{TenantID: tenantID, Status: tenant.Inactive}
	if _, _, err := w.service.Create(ctx, weak(customer())); !errors.Is(err, createaccount.ErrTenantNotActive) {
		t.Fatalf("weak password and inactive tenant: %v", err)
	}
	w = newWorld()
	w.tenants.copies[tenantID] = tenant.Copy{TenantID: tenantID, Status: tenant.Inactive}
	w.accounts.byKey[tenantID+"|ana@example.com"] = account.Account{ID: existingID, TenantID: tenantID}
	if _, _, err := w.service.Create(ctx, customer()); !errors.Is(err, createaccount.ErrTenantNotActive) {
		t.Fatalf("duplicate e-mail and inactive tenant: %v", err)
	}
	nothingWritten(t, w)
}

func TestA_PlanD03TheShapeOfTheFormIsCheckedBeforeTheTenant(t *testing.T) {
	w := newWorld()
	c := customer()
	c.TenantID, c.Phone = otherTenant, "12"
	_, _, err := w.service.Create(ctx, c)
	if fieldOf(t, err) != "phone" || errors.Is(err, createaccount.ErrTenantNotFound) {
		t.Fatalf("malformed phone and unknown tenant: %v", err)
	}
}

func TestA_TheActorIsRecordedTrimmedAndAnInternalUserWithoutPhoneKeepsNone(t *testing.T) {
	w := newWorld()
	c := internalUser()
	c.Actor = "  " + actorAdmin + " "
	if _, _, err := w.service.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	n := w.registry.created[0]
	if n.CreatedBy != "tenant-administrator/"+actorAdmin || n.Phone != "" {
		t.Fatalf("created by %q phone %q", n.CreatedBy, n.Phone)
	}
}
