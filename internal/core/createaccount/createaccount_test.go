package createaccount_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/password"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

var ctx = context.Background()

// nothingWritten fails the test when a refusal still hashed or stored something.
func nothingWritten(t *testing.T, w *world) {
	t.Helper()
	if len(w.registry.created) != 0 || len(w.hasher.hashed) != 0 {
		t.Fatalf("a refusal must create and hash nothing: created=%d hashed=%d", len(w.registry.created), len(w.hasher.hashed))
	}
}

func fieldOf(t *testing.T, err error) string {
	t.Helper()
	var fe *createaccount.FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v, want a FieldError", err)
	}
	return fe.Field
}

func TestA_PasswordAndConfirmationMustMatch(t *testing.T) {
	w := newWorld()
	c := customer()
	c.Confirmation = goodPass + "x"
	_, _, err := w.service.Create(ctx, c)
	if got := fieldOf(t, err); got != "passwordConfirmation" {
		t.Fatalf("field = %q", got)
	}
	if strings.Contains(err.Error(), goodPass) {
		t.Fatal("the refusal must never quote the password")
	}
	nothingWritten(t, w)
}

func TestA_PasswordPolicyIsTheOneOfThePasswordPackage(t *testing.T) {
	w := newWorld()
	c := customer()
	c.Password, c.Confirmation = "weakpass", "weakpass"
	_, _, err := w.service.Create(ctx, c)
	if !errors.Is(err, password.ErrPolicy) || fieldOf(t, err) != "password" {
		t.Fatalf("err = %v, want the policy refusal on password", err)
	}
	if strings.Contains(err.Error(), "weakpass") {
		t.Fatal("the refusal must never quote the password")
	}
	nothingWritten(t, w)
}

func TestA_ThePolicyAppliesToTheTemporaryPasswordOfTheOtherKindsToo(t *testing.T) {
	for _, c := range []createaccount.Command{internalUser(), firstAdministrator()} {
		w := newWorld()
		c.Password = "weakpass"
		if _, _, err := w.service.Create(ctx, c); !errors.Is(err, password.ErrPolicy) {
			t.Fatalf("kind %d: err = %v", c.Kind, err)
		}
		nothingWritten(t, w)
	}
}

func TestA_TheEmailIsNormalizedAndInvalidOnesAreRefused(t *testing.T) {
	w := newWorld()
	got, created, err := w.service.Create(ctx, customer())
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if w.registry.created[0].EmailNormalized != "ana@example.com" || got.Account.EmailNormalized != "ana@example.com" {
		t.Fatalf("the e-mail must be stored lower-cased and trimmed: %+v", w.registry.created[0])
	}
	for _, bad := range []string{"", "no-at-sign", "@example.com", "ana@", "a b@example.com", "añ@example.com"} {
		w := newWorld()
		c := customer()
		c.Email = bad
		_, _, err := w.service.Create(ctx, c)
		if fieldOf(t, err) != "email" {
			t.Fatalf("%q: err = %v", bad, err)
		}
		nothingWritten(t, w)
	}
}

func TestA_SameEmailInTheSameTenantIsRefusedEvenIfTheFirstIsInactive(t *testing.T) {
	for _, status := range []account.Status{account.Active, account.Inactive} {
		w := newWorld()
		w.accounts.byKey[tenantID+"|ana@example.com"] = account.Account{ID: existingID, TenantID: tenantID, Status: status}
		_, _, err := w.service.Create(ctx, customer())
		if !errors.Is(err, port.ErrEmailTaken) {
			t.Fatalf("status %d: err = %v", status, err)
		}
		nothingWritten(t, w)
	}
}

func TestA_TheSameEmailInAnotherTenantIsAnotherAccount(t *testing.T) {
	w := newWorld()
	w.accounts.byKey[otherTenant+"|ana@example.com"] = account.Account{ID: existingID, TenantID: otherTenant}
	if _, created, err := w.service.Create(ctx, customer()); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}

func TestA_ARaceOnTheUniqueEmailIsTheSameRefusal(t *testing.T) {
	w := newWorld()
	w.registry.createFn = func(port.NewAccount) error { return port.ErrEmailTaken }
	if _, _, err := w.service.Create(ctx, customer()); !errors.Is(err, port.ErrEmailTaken) {
		t.Fatalf("err = %v", err)
	}
}

func TestA_AnInactiveTenantCreatesNoAccountAndAnUnknownOneIsNotFound(t *testing.T) {
	for _, status := range []tenant.Status{tenant.Inactive, tenant.Pending, tenant.Failed} {
		w := newWorld()
		w.tenants.copies[tenantID] = tenant.Copy{TenantID: tenantID, Status: status}
		for _, c := range []createaccount.Command{customer(), internalUser()} {
			if _, _, err := w.service.Create(ctx, c); !errors.Is(err, createaccount.ErrTenantNotActive) {
				t.Fatalf("status %s kind %d: err = %v", status, c.Kind, err)
			}
		}
		nothingWritten(t, w)
	}
	w := newWorld()
	c := customer()
	c.TenantID = otherTenant
	if _, _, err := w.service.Create(ctx, c); !errors.Is(err, createaccount.ErrTenantNotFound) {
		t.Fatalf("err = %v", err)
	}
	nothingWritten(t, w)
}

func TestA_ACustomerAccountIsPendingWithTheRoleFinalCustomerAndNoTemporaryCredential(t *testing.T) {
	w := newWorld()
	got, created, err := w.service.Create(ctx, customer())
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	n := w.registry.created[0]
	if n.Role != "FINAL_CUSTOMER" || !n.TemporaryUntil.IsZero() || n.TenantID != tenantID {
		t.Fatalf("new account = %+v", n)
	}
	if n.FullName != "Ana Pérez" || n.Phone != "+57 300 123 4567" || n.CreatedBy != "customer" {
		t.Fatalf("profile = %+v", n)
	}
	if got.Account.Status != account.Pending || !n.Pending || got.Account.UsesTemporaryCredential(now) {
		t.Fatalf("the customer must be pending with an ordinary password: %+v", got.Account)
	}
	if n.PasswordHash != hashPrefix+goodPass {
		t.Fatal("only the hash of the password is handed to the store")
	}
}

func TestA_TheThreeKindsShareOneUseCase(t *testing.T) {
	cases := []struct {
		name      string
		cmd       createaccount.Command
		role      string
		temporary bool
		by        string
		scope     string
		consults  bool
	}{
		{"customer", customer(), "FINAL_CUSTOMER", false, "customer", "customer:" + tenantID, true},
		{"internal user", internalUser(), "OPERATIONAL_COLLABORATOR", true, "tenant-administrator/" + actorAdmin, "user:" + tenantID, true},
		{"first administrator", firstAdministrator(), "TENANT_ADMINISTRATOR", true, "service/" + serviceSub, "first-admin:" + tenantID, false},
	}
	for _, tc := range cases {
		w := newWorld()
		if _, created, err := w.service.Create(ctx, tc.cmd); err != nil || !created {
			t.Fatalf("%s: created=%v err=%v", tc.name, created, err)
		}
		n := w.registry.created[0]
		if n.Role != tc.role || n.CreatedBy != tc.by || w.registry.scopes[0] != tc.scope {
			t.Fatalf("%s: new=%+v scope=%q", tc.name, n, w.registry.scopes[0])
		}
		wantUntil := now.Add(account.TemporaryCredentialLife)
		if tc.temporary && !n.TemporaryUntil.Equal(wantUntil) || !tc.temporary && !n.TemporaryUntil.IsZero() {
			t.Fatalf("%s: TemporaryUntil = %v", tc.name, n.TemporaryUntil)
		}
		if (w.tenants.calls > 0) != tc.consults {
			t.Fatalf("%s: tenant consulted %d times", tc.name, w.tenants.calls)
		}
	}
}

func TestA_TheFirstAdministratorIsCreatedEvenIfTheTenantCopyHasNotArrived(t *testing.T) {
	w := newWorld()
	w.tenants.copies = map[string]tenant.Copy{}
	if _, created, err := w.service.Create(ctx, firstAdministrator()); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}

func TestA_TheKindsThatNeedAnActorOrARoleRefuseWithoutThem(t *testing.T) {
	noActor, noRole := internalUser(), internalUser()
	noActor.Actor, noRole.Role = "", ""
	noService := firstAdministrator()
	noService.Actor = ""
	for _, c := range []createaccount.Command{noActor, noRole, noService, {Kind: 0}} {
		w := newWorld()
		if _, _, err := w.service.Create(ctx, c); err == nil {
			t.Fatalf("%+v must be refused", c)
		}
		nothingWritten(t, w)
	}
}

func TestA_ARepeatOfTheKeyReturnsTheFirstAccountAndHashesNothing(t *testing.T) {
	w := newWorld()
	first, created, err := w.service.Create(ctx, customer())
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	hashed := len(w.hasher.hashed)
	again := customer()
	again.Email, again.Password, again.Confirmation = "someone@else.com", "nothing", "different"
	got, created, err := w.service.Create(ctx, again)
	if err != nil || created || got.Account.ID != first.Account.ID {
		t.Fatalf("a repeat answers the first account: created=%v err=%v got=%+v", created, err, got)
	}
	if len(w.hasher.hashed) != hashed || len(w.registry.created) != 1 {
		t.Fatal("a repeat must hash and create nothing")
	}
}

func TestA_TheSameKeyOnAnotherKindIsAnotherIntent(t *testing.T) {
	w := newWorld()
	if _, _, err := w.service.Create(ctx, customer()); err != nil {
		t.Fatal(err)
	}
	if _, created, err := w.service.Create(ctx, internalUser()); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}

func TestA_ARaceOnTheKeyIsAnsweredAsARepeat(t *testing.T) {
	w := newWorld()
	winner := port.Registered{Account: account.Account{ID: "acc-winner"}}
	w.registry.createFn = func(port.NewAccount) error {
		w.registry.keys = map[string]port.Registered{"customer:" + tenantID + "|" + idemKey: winner}
		return port.ErrKeyTaken
	}
	got, created, err := w.service.Create(ctx, customer())
	if err != nil || created || got.Account.ID != "acc-winner" {
		t.Fatalf("created=%v err=%v got=%+v", created, err, got)
	}
}

func TestA_EachFieldOfTheFormIsNamedWhenItIsMissingOrMalformed(t *testing.T) {
	long := strings.Repeat("a", 51)
	cases := map[string]func(*createaccount.Command){
		"firstName":      func(c *createaccount.Command) { c.FirstName = "  " },
		"lastName":       func(c *createaccount.Command) { c.LastName = long },
		"phone":          func(c *createaccount.Command) { c.Phone = "" },
		"email":          func(c *createaccount.Command) { c.Email = "" },
		"password":       func(c *createaccount.Command) { c.Password, c.Confirmation = "", "" },
		"idempotencyKey": func(c *createaccount.Command) { c.IdempotencyKey = "short" },
	}
	for field, mutate := range cases {
		w := newWorld()
		c := customer()
		mutate(&c)
		_, _, err := w.service.Create(ctx, c)
		if got := fieldOf(t, err); got != field {
			t.Fatalf("%s: field = %q (%v)", field, got, err)
		}
		nothingWritten(t, w)
	}
	for _, bad := range []string{"12345", "abc-defg-hij", strings.Repeat("1", 21), "300\n1234567"} {
		w := newWorld()
		c := customer()
		c.Phone = bad
		if _, _, err := w.service.Create(ctx, c); fieldOf(t, err) != "phone" {
			t.Fatalf("%q: err = %v", bad, err)
		}
	}
	w := newWorld()
	c := customer()
	c.FirstName = "An\x00a"
	if _, _, err := w.service.Create(ctx, c); fieldOf(t, err) != "firstName" {
		t.Fatalf("a control character must be refused: %v", err)
	}
	u := internalUser()
	u.FullName = strings.Repeat("a", 101)
	if _, _, err := w.service.Create(ctx, u); fieldOf(t, err) != "fullName" {
		t.Fatalf("err = %v", err)
	}
}

func TestA_AFailureOfAStoreOrOfTheHasherIsAnErrorThatIsNotARefusal(t *testing.T) {
	boom := errors.New("boom")
	breakers := map[string]func(*world){
		"tenants":     func(w *world) { w.tenants.err = boom },
		"accounts":    func(w *world) { w.accounts.err = boom },
		"find key":    func(w *world) { w.registry.findErr = boom },
		"hasher":      func(w *world) { w.hasher.err = boom },
		"create":      func(w *world) { w.registry.createFn = func(port.NewAccount) error { return boom } },
		"key re-read": func(w *world) { w.registry.createFn = func(port.NewAccount) error { return port.ErrKeyTaken } },
	}
	for name, breakIt := range breakers {
		w := newWorld()
		breakIt(w)
		_, created, err := w.service.Create(ctx, customer())
		if err == nil || created {
			t.Fatalf("%s: created=%v err=%v", name, created, err)
		}
		var fe *createaccount.FieldError
		if errors.As(err, &fe) || errors.Is(err, port.ErrEmailTaken) || errors.Is(err, createaccount.ErrTenantNotActive) ||
			errors.Is(err, createaccount.ErrTenantNotFound) {
			t.Fatalf("%s: a failure of the platform must not look like a refusal: %v", name, err)
		}
	}
}

func TestA_AServiceWithoutOnePieceRefusesToWorkAndNeverPanics(t *testing.T) {
	pieces := map[string]func(*createaccount.Service){
		"tenants":  func(s *createaccount.Service) { s.Tenants = nil },
		"accounts": func(s *createaccount.Service) { s.Accounts = nil },
		"registry": func(s *createaccount.Service) { s.Registry = nil },
		"hasher":   func(s *createaccount.Service) { s.Hasher = nil },
		"clock":    func(s *createaccount.Service) { s.Clock = nil },
	}
	for name, remove := range pieces {
		w := newWorld()
		remove(w.service)
		if _, _, err := w.service.Create(ctx, customer()); !errors.Is(err, createaccount.ErrNotWired) {
			t.Fatalf("without %s: err = %v", name, err)
		}
	}
}
