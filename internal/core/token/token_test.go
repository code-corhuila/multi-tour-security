package token_test

import (
	"errors"
	"reflect"
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
	if _, err := token.Service("  ", time.Hour, now); err == nil {
		t.Fatal("a service without a name must be refused")
	}
}
