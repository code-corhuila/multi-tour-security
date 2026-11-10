package token_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// The token of an emergency access (HU-SEC-007 part B, security spec 010: RN-SEC-010-04, -05).

func TestD_AnEmergencyTokenIsMarkedEmergencyAndKeepsEveryRuleOfASupportToken(t *testing.T) {
	now := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	ends := now.Add(4 * time.Hour)
	c, err := token.Emergency("platform-1", "tenant-1", []string{"CASH", "SENSITIVE"}, "access-1", ends, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Access != token.EmergencyAccess || c.Subject != "platform-1" || c.TenantID != "tenant-1" || c.AuthorizationID != "access-1" ||
		!slices.Equal(c.Scope, []string{"CASH", "SENSITIVE"}) || !slices.Equal(c.Roles, []string{"PLATFORM_ADMINISTRATOR"}) || len(c.Permissions) != 0 {
		t.Fatalf("claims = %+v", c)
	}
	if !c.ExpiresAt.Equal(ends) {
		t.Errorf("it ends with the access: %v", c.ExpiresAt)
	}
	if _, err := token.Emergency("platform-1", "tenant-1", []string{"CASH"}, "access-1", now.Add(24*time.Hour+time.Second), now); !errors.Is(err, token.ErrExceptionalLife) {
		t.Errorf("more than 24 hours: %v", err)
	}
	if _, err := token.Emergency("platform-1", "tenant-1", nil, "access-1", ends, now); !errors.Is(err, token.ErrExceptionalClaims) {
		t.Errorf("no scope: %v", err)
	}
}

func TestD_BothMarksOfASupportAccessAreRecognizedAndNoOther(t *testing.T) {
	for access, want := range map[string]bool{token.ExceptionalAccess: true, token.EmergencyAccess: true, "": false, token.RestrictedAccess: false, token.PasswordChangeAccess: false, "other": false} {
		if got := token.IsSupportAccess(access); got != want {
			t.Errorf("%q: %v, want %v", access, got, want)
		}
	}
}
