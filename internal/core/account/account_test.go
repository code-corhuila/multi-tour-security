package account_test

import (
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

var start = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

func active() account.Account {
	return account.Account{ID: "a1", TenantID: "t1", EmailNormalized: "ana@example.com", PasswordHash: "hash", Status: account.Active}
}

func TestD_InactiveAccountCannotAuthenticate(t *testing.T) {
	a := active()
	a.Status = account.Inactive
	if err := a.CanAuthenticate(start); !errors.Is(err, account.ErrInactive) {
		t.Fatalf("an inactive account authenticated or failed another way: %v", err)
	}
	if err := active().CanAuthenticate(start); err != nil {
		t.Fatalf("an active account was refused: %v", err)
	}
}

func TestD_TemporaryCredentialLasts72HoursAndThenDoesNotAuthenticate(t *testing.T) {
	a := account.NewWithTemporaryCredential("a1", "t1", "ana@example.com", "hash", start)
	inside := start.Add(72*time.Hour - time.Second)
	if err := a.CanAuthenticate(inside); err != nil || !a.UsesTemporaryCredential(inside) {
		t.Fatalf("a temporary credential inside its 72 hours must authenticate and be recognised: %v", err)
	}
	after := start.Add(72*time.Hour + time.Second)
	if err := a.CanAuthenticate(after); !errors.Is(err, account.ErrTemporaryExpired) {
		t.Fatalf("an expired temporary credential must not authenticate: %v", err)
	}
	if a.Status != account.Active {
		t.Fatal("an expired credential must leave the account registered and active")
	}
}

func TestD_AnAccountWithoutTemporaryCredentialDoesNotUseOne(t *testing.T) {
	if active().UsesTemporaryCredential(start) {
		t.Fatal("an ordinary account reports a temporary credential")
	}
}

func TestD_FiveFailuresWithin15MinutesBlockTheAccountForFifteenMinutes(t *testing.T) {
	a := active()
	for i := 0; i < 4; i++ {
		var blocked bool
		a, blocked = a.AfterFailure(start.Add(time.Duration(i) * time.Minute))
		if blocked {
			t.Fatalf("blocked at failure %d, before the fifth", i+1)
		}
		if err := a.CanAuthenticate(start.Add(time.Duration(i) * time.Minute)); err != nil {
			t.Fatalf("refused before the block: %v", err)
		}
	}
	a, blocked := a.AfterFailure(start.Add(4 * time.Minute))
	if !blocked {
		t.Fatal("the fifth failure must report the block, so that it is audited")
	}
	if err := a.CanAuthenticate(start.Add(5 * time.Minute)); !errors.Is(err, account.ErrBlocked) {
		t.Fatalf("a blocked account authenticated: %v", err)
	}
}

func TestD_TheBlockEndsFifteenMinutesAfterTheFifthFailure(t *testing.T) {
	a := active()
	var blocked bool
	for i := 0; i < 5; i++ {
		a, blocked = a.AfterFailure(start)
	}
	if !blocked {
		t.Fatal("the account was not blocked")
	}
	if err := a.CanAuthenticate(start.Add(15*time.Minute - time.Second)); !errors.Is(err, account.ErrBlocked) {
		t.Fatalf("the block ended too early: %v", err)
	}
	if err := a.CanAuthenticate(start.Add(15 * time.Minute)); err != nil {
		t.Fatalf("the block did not end after 15 minutes: %v", err)
	}
	a, blocked = a.AfterFailure(start.Add(16 * time.Minute))
	if blocked || a.Failed != 1 {
		t.Fatalf("after the block the count must start over, got %d (blocked %v)", a.Failed, blocked)
	}
}

func TestD_FailuresOutsideTheWindowStartTheCountOver(t *testing.T) {
	a := active()
	for i := 0; i < 4; i++ {
		a, _ = a.AfterFailure(start)
	}
	a, blocked := a.AfterFailure(start.Add(15 * time.Minute))
	if blocked || a.Failed != 1 {
		t.Fatalf("a failure 15 minutes after the first must open a new window, got %d (blocked %v)", a.Failed, blocked)
	}
}

func TestD_ASuccessResetsTheCount(t *testing.T) {
	a := active()
	for i := 0; i < 4; i++ {
		a, _ = a.AfterFailure(start)
	}
	a = a.AfterSuccess()
	if a.Failed != 0 || !a.FirstFailedAt.IsZero() || !a.BlockedUntil.IsZero() {
		t.Fatalf("a success must clear the failures: %+v", a)
	}
	a, blocked := a.AfterFailure(start.Add(time.Minute))
	if blocked {
		t.Fatal("the count did not start over after the success")
	}
}

func TestD_TheEmailIsNormalizedByCaseAndSpacesOnly(t *testing.T) {
	if got := account.NormalizeEmail("  Ana.Lopez+tag@Example.COM \t"); got != "ana.lopez+tag@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestD_OnlyThePlatformAdministratorHasNoTenant(t *testing.T) {
	platform := active()
	platform.TenantID = ""
	if !platform.IsPlatform() || active().IsPlatform() {
		t.Fatal("an account without tenant is the platform's, and one with a tenant is not")
	}
}
