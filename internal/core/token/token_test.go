package token_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

var now = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

func person() account.Account {
	return account.Account{ID: "account-1", TenantID: "tenant-1", EmailNormalized: "ana@example.com", Status: account.Active}
}

func TestA_AccessTokenCarriesTheClaimsAndLastsFifteenMinutes(t *testing.T) {
	c := token.Access(person(), []string{"TENANT_ADMINISTRATOR"}, []string{"CASH"}, false, now)
	if c.Subject != "account-1" || c.TenantID != "tenant-1" {
		t.Fatalf("subject and tenant must be the account's: %+v", c)
	}
	if !reflect.DeepEqual(c.Roles, []string{"TENANT_ADMINISTRATOR"}) || !reflect.DeepEqual(c.Permissions, []string{"CASH"}) {
		t.Fatalf("roles and permissions were not carried: %+v", c)
	}
	if c.Issuer != "multi-tour-security" || c.Audience != "multi-tour" {
		t.Fatalf("issuer and audience are fixed by the plan: %q %q", c.Issuer, c.Audience)
	}
	if !c.IssuedAt.Equal(now) || !c.NotBefore.Equal(now) || !c.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("iat, nbf and exp must be now, now and now + 15 minutes: %+v", c)
	}
	if c.Access != "" {
		t.Fatalf("an ordinary token has no access mark: %q", c.Access)
	}
}

func TestA_ThePlatformAdministratorTokenHasNoTenant(t *testing.T) {
	root := person()
	root.TenantID = ""
	c := token.Access(root, []string{"PLATFORM_ADMINISTRATOR"}, nil, false, now)
	if c.TenantID != "" {
		t.Fatalf("the platform has no tenant, got %q", c.TenantID)
	}
}

func TestA_TheAdministratorOfAnInactiveTenantGetsARestrictedAccess(t *testing.T) {
	c := token.Access(person(), []string{"TENANT_ADMINISTRATOR"}, nil, true, now)
	if c.Access != "restricted" {
		t.Fatalf("access must be restricted, got %q", c.Access)
	}
}

func TestA_AClaimListIsNeverNilSoItIsAnEmptyListInTheToken(t *testing.T) {
	c := token.Access(person(), nil, nil, false, now)
	if c.Roles == nil || c.Permissions == nil {
		t.Fatal("roles and permissions must be empty lists and not null")
	}
}

func TestA_ThePasswordChangeTokenHasNoRolesAndLastsTenMinutes(t *testing.T) {
	c := token.PasswordChange(person(), now)
	if len(c.Roles) != 0 || len(c.Permissions) != 0 {
		t.Fatalf("it must carry no role, so that no other service lets it in: %+v", c)
	}
	if c.Access != "password-change" || !c.ExpiresAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("access and life of the password-change token are wrong: %+v", c)
	}
	if c.Subject != "account-1" || c.TenantID != "tenant-1" {
		t.Fatalf("it still names the account: %+v", c)
	}
}

func TestA_AServiceTokenHasNoTenantAndTheRoleService(t *testing.T) {
	c, err := token.Service("onboard-tenant", 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.TenantID != "" || c.Subject != "onboard-tenant" || !reflect.DeepEqual(c.Roles, []string{"SERVICE"}) {
		t.Fatalf("a service has a name, the role SERVICE and no tenant: %+v", c)
	}
	if !c.ExpiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("the life asked was not applied: %v", c.ExpiresAt)
	}
}

func TestA_AServiceTokenLastsAtMostThirtyDaysAndAtLeastOneMinute(t *testing.T) {
	if _, err := token.Service("w", 30*24*time.Hour, now); err != nil {
		t.Fatalf("30 days are allowed: %v", err)
	}
	for _, life := range []time.Duration{30*24*time.Hour + time.Second, 0, -time.Hour, 59 * time.Second} {
		if _, err := token.Service("w", life, now); !errors.Is(err, token.ErrServiceLife) {
			t.Fatalf("life %v must be refused, got %v", life, err)
		}
	}
	for _, name := range []string{"", "  ", " padded", "padded ", strings.Repeat("s", 101), "bad\u0007name"} {
		if _, err := token.Service(name, time.Hour, now); !errors.Is(err, token.ErrServiceName) {
			t.Fatalf("the name %q must be refused, got %v", name, err)
		}
	}
	if _, err := token.Service(strings.Repeat("s", 100), time.Hour, now); err != nil {
		t.Fatalf("a name of 100 characters is allowed: %v", err)
	}
}

// The token of a support access of the Platform Administrator (HU-SEC-007 part A, RN-SEC-009-05; ADR-004 D5).

func TestA_TheTokenOfASupportAccessIsForOneTenantWithItsScopeAndEndsWithTheAccess(t *testing.T) {
	ends := now.Add(4 * time.Hour)
	c, err := token.Exceptional("platform-1", "tenant-1", []string{"CASH", "RESERVATIONS"}, "access-1", ends, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "platform-1" || c.TenantID != "tenant-1" || c.Access != "exceptional" || c.AuthorizationID != "access-1" ||
		!reflect.DeepEqual(c.Scope, []string{"CASH", "RESERVATIONS"}) || !reflect.DeepEqual(c.Roles, []string{"PLATFORM_ADMINISTRATOR"}) ||
		len(c.Permissions) != 0 || c.Permissions == nil || !c.ExpiresAt.Equal(ends) || !c.IssuedAt.Equal(now) || !c.NotBefore.Equal(now) ||
		c.Issuer != token.Issuer || c.Audience != token.Audience {
		t.Fatalf("claims = %+v", c)
	}
}

func TestA_TheTokenOfASupportAccessNeverOutlastsTheAccessNorMoreThan24Hours(t *testing.T) {
	for name, ends := range map[string]time.Time{
		"already over":  now.Add(-time.Minute),
		"this instant":  now,
		"over 24 hours": now.Add(24*time.Hour + time.Second),
	} {
		if _, err := token.Exceptional("platform-1", "tenant-1", []string{"CASH"}, "access-1", ends, now); !errors.Is(err, token.ErrExceptionalLife) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := token.Exceptional("platform-1", "tenant-1", []string{"CASH"}, "access-1", now.Add(24*time.Hour), now); err != nil {
		t.Errorf("exactly 24 hours: %v", err)
	}
}

func TestA_TheTokenOfASupportAccessNeedsAPersonATenantAnAreaAndTheAuthorization(t *testing.T) {
	ends := now.Add(time.Hour)
	for name, args := range map[string][4]any{
		"no person":        {"", "tenant-1", []string{"CASH"}, "access-1"},
		"no tenant":        {"platform-1", "", []string{"CASH"}, "access-1"},
		"no area":          {"platform-1", "tenant-1", []string{}, "access-1"},
		"no authorization": {"platform-1", "tenant-1", []string{"CASH"}, ""},
	} {
		if _, err := token.Exceptional(args[0].(string), args[1].(string), args[2].([]string), args[3].(string), ends, now); !errors.Is(err, token.ErrExceptionalClaims) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestA_TheScopeOfTheTokenIsACopy(t *testing.T) {
	scope := []string{"CASH"}
	c, _ := token.Exceptional("platform-1", "tenant-1", scope, "access-1", now.Add(time.Hour), now)
	scope[0] = "CUSTOMERS"
	if c.Scope[0] != "CASH" {
		t.Error("the caller changed the scope of a token that was built")
	}
}

func TestA_TheScopeOfTheTokenHasNoBlankNorRepeatedArea(t *testing.T) {
	ends := now.Add(time.Hour)
	for name, scope := range map[string][]string{"blank": {""}, "spaces": {" CASH"}, "repeated": {"CASH", "CASH"}, "control": {"CA" + string(rune(7)) + "SH"}} {
		if _, err := token.Exceptional("platform-1", "tenant-1", scope, "access-1", ends, now); !errors.Is(err, token.ErrExceptionalClaims) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for name, args := range map[string][2]string{"person with spaces": {" platform-1", "tenant-1"}, "tenant with spaces": {"platform-1", "tenant-1 "}} {
		if _, err := token.Exceptional(args[0], args[1], []string{"CASH"}, "access-1", ends, now); !errors.Is(err, token.ErrExceptionalClaims) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
