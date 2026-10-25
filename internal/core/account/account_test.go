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

func blockedAt(t *testing.T) account.Account {
	t.Helper()
	a := active()
	var blocked bool
	for i := 0; i < 5; i++ {
		a, blocked = a.AfterFailure(start.Add(time.Duration(i) * 3 * time.Minute))
	}
	if !blocked {
		t.Fatal("the account was not blocked by the fifth failure")
	}
	return a
}

func TestD_AFailureWhileBlockedDoesNotLiftTheBlockEarly(t *testing.T) {
	a := blockedAt(t) // the fifth failure is at 12 minutes, so the block ends at 27
	again, blocked := a.AfterFailure(start.Add(16 * time.Minute))
	if blocked || again != a {
		t.Fatalf("a failure while blocked must change nothing and report nothing: %+v blocked=%v", again, blocked)
	}
	if err := again.CanAuthenticate(start.Add(17 * time.Minute)); !errors.Is(err, account.ErrBlocked) {
		t.Fatalf("the block was lifted by a later failure: %v", err)
	}
}

func TestD_AFailureWhileBlockedDoesNotExtendTheBlock(t *testing.T) {
	a := blockedAt(t)
	until := a.BlockedUntil
	a, blocked := a.AfterFailure(start.Add(20 * time.Minute))
	if blocked || !a.BlockedUntil.Equal(until) {
		t.Fatalf("the block moved from %v to %v (reported %v)", until, a.BlockedUntil, blocked)
	}
}

func TestD_ASuccessLiftsABlockAndTheExactInstantsOfThe72HoursAreFixed(t *testing.T) {
	if err := blockedAt(t).AfterSuccess().CanAuthenticate(start.Add(13 * time.Minute)); err != nil {
		t.Fatalf("a success must lift the block: %v", err)
	}
	a := account.NewWithTemporaryCredential("a1", "t1", "ana@example.com", "hash", start)
	exact := start.Add(account.TemporaryCredentialLife)
	if a.UsesTemporaryCredential(exact) || !errors.Is(a.CanAuthenticate(exact), account.ErrTemporaryExpired) {
		t.Fatal("the credential must be expired at exactly 72 hours")
	}
	if !a.UsesTemporaryCredential(exact.Add(-time.Nanosecond)) {
		t.Fatal("the credential must still work one instant before the 72 hours")
	}
}

func TestD_TheRefusalsComeInTheOrderInactiveBlockedExpired(t *testing.T) {
	a := account.NewWithTemporaryCredential("a1", "t1", "ana@example.com", "hash", start)
	a.BlockedUntil = start.Add(100 * time.Hour)
	late := start.Add(80 * time.Hour)
	if err := a.CanAuthenticate(late); !errors.Is(err, account.ErrBlocked) {
		t.Fatalf("blocked must come before expired: %v", err)
	}
	a.Status = account.Inactive
	if err := a.CanAuthenticate(late); !errors.Is(err, account.ErrInactive) {
		t.Fatalf("inactive must come first: %v", err)
	}
}

func TestD_PendingAccountCannotAuthenticateAndTheOtherRefusalsComeFirst(t *testing.T) {
	a := active()
	a.Status = account.Pending
	if err := a.CanAuthenticate(start); !errors.Is(err, account.ErrNotVerified) {
		t.Fatalf("a pending account authenticated or failed another way: %v", err)
	}
	blocked := a
	blocked.BlockedUntil = start.Add(time.Minute)
	if err := blocked.CanAuthenticate(start); !errors.Is(err, account.ErrBlocked) {
		t.Fatalf("a blocked pending account must be refused as blocked first: %v", err)
	}
	inactive := a
	inactive.Status = account.Inactive
	if err := inactive.CanAuthenticate(start); !errors.Is(err, account.ErrInactive) {
		t.Fatalf("an inactive account is not a pending one: %v", err)
	}
}

func TestD_AVerifiedAccountAuthenticatesAndKeepsItsData(t *testing.T) {
	a := active()
	a.Status = account.Pending
	v := a.Verified()
	if v.Status != account.Active || v.ID != a.ID || v.TenantID != a.TenantID || v.PasswordHash != a.PasswordHash {
		t.Fatalf("verified = %+v", v)
	}
	if err := v.CanAuthenticate(start); err != nil {
		t.Fatalf("a verified account was refused: %v", err)
	}
}

func TestD_VerifyingNeverReactivatesAnInactiveAccount(t *testing.T) {
	a := active()
	a.Status = account.Inactive
	if got := a.Verified(); got.Status != account.Inactive {
		t.Fatalf("status = %v, want it to stay inactive", got.Status)
	}
}
