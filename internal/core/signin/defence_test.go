package signin_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
)

// These three were found by the review of the code, after the first tests were written.

// A header decides nothing about whether an account exists.
func TestC_ACorrelationIdThatCannotBeStoredIsAnInvalidRequestForEveryoneAndNeverAnAnswerAboutTheAccount(t *testing.T) {
	for _, id := range []string{"", strings.Repeat("c", 129)} {
		for _, email := range []string{"ana@example.com", "nobody@example.com"} {
			w := newWorld()
			w.add("a", tenantID, "ana@example.com", []string{"ANALYST"}, nil)
			req := request("travesia-natural", email, "wrong")
			req.CorrelationID = id
			if _, err := w.service.SignIn(ctx, req); !errors.Is(err, signin.ErrInvalidRequest) {
				t.Errorf("correlation id of %d characters, %s: %v", len(id), email, err)
			}
			if len(w.hasher.compared) != 0 || len(w.accounts.failures) != 0 {
				t.Error("the request reached the hasher or the lock")
			}
		}
	}
}

// Defence in depth: the store filters by tenant, and the use case does not trust it alone.
func TestC_AnAccountThatTheStoreReturnsFromAnotherTenantOrFromTheWrongPlaceIsRefused(t *testing.T) {
	w := newWorld()
	w.accounts.byKey[tenantID+"|ana@example.com"] = account.Account{ID: "x", TenantID: otherID, EmailNormalized: "ana@example.com",
		PasswordHash: own, Status: account.Active}
	w.accounts.roles["x"] = []string{"ANALYST"}
	if _, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); err != signin.ErrRefused ||
		!reflect.DeepEqual(w.hasher.compared, []string{dummyHash}) || len(w.signer.claims) != 0 {
		t.Errorf("an account of another tenant came out of the lookup: %v %v", err, w.hasher.compared)
	}
	w = newWorld()
	w.accounts.byKey["|root@example.com"] = account.Account{ID: "y", TenantID: tenantID, EmailNormalized: "root@example.com",
		PasswordHash: own, Status: account.Active}
	w.accounts.roles["y"] = []string{"PLATFORM_ADMINISTRATOR"}
	if _, err := w.service.SignInPlatform(ctx, request("", "root@example.com", password)); err != signin.ErrRefused ||
		!reflect.DeepEqual(w.hasher.compared, []string{dummyHash}) || len(w.signer.claims) != 0 {
		t.Errorf("an account with a tenant came out of the platform lookup: %v %v", err, w.hasher.compared)
	}
}

func TestC_AnAccountWithNoRoleIsRefusedBecauseItWouldOpenNothing(t *testing.T) {
	w := newWorld()
	w.add("a", tenantID, "ana@example.com", nil, nil)
	if got, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); err != signin.ErrRefused || got != (signin.Tokens{}) {
		t.Errorf("an account without a role got in: %v %+v", err, got)
	}
	if len(w.accounts.successes) != 0 || len(w.sessions.opened) != 0 {
		t.Error("a refusal cleared a count or opened a session")
	}
}
