package main

import (
	"net/http"
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/golang-jwt/jwt/v5"
)

// End to end against PostgreSQL, decoding the token that the service signs (HU-SEC-006, AC1 to AC4 and AC7, RN-SEC-005-03 to -06 and -10).

func permissionsClaim(t *testing.T, claims jwt.MapClaims) []string {
	t.Helper()
	list, ok := claims["permissions"].([]any)
	if !ok {
		t.Fatalf("the claim permissions is a list that is always there: %v", claims["permissions"])
	}
	out := []string{}
	for _, p := range list {
		out = append(out, p.(string))
	}
	slices.Sort(out)
	return out
}

func TestC_TheAdministratorTokenCarriesTheThreeProfilePermissionsAndSensitiveDataOnlyFromTheNextRefreshAndSignInAfterItIsAssigned(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	adminID := s.idOf(t, "admin@example.com")
	first, claims := s.claims(t, s.signIn(tenantURL, "admin@example.com", password))
	want := []string{"MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "VALIDATE_PAYMENT_PROOFS"}
	if got := permissionsClaim(t, claims); !slices.Equal(got, want) {
		t.Fatalf("the administrator holds three by profile and never sensitive data until it is assigned: %v", got)
	}
	if rec, _ := s.changePermission(t, admin, adminID, "grant", "CONSULT_SENSITIVE_DATA"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got := permissionsClaim(t, claims); slices.Contains(got, "CONSULT_SENSITIVE_DATA") {
		t.Fatal("a credential already issued is never changed")
	}
	_, renewed := s.claims(t, s.refresh(first.RefreshToken))
	if got := permissionsClaim(t, renewed); !slices.Contains(got, "CONSULT_SENSITIVE_DATA") || len(got) != 4 {
		t.Fatalf("the assignment reaches the next refresh: %v", got)
	}
	_, signedIn := s.claims(t, s.signIn(tenantURL, "admin@example.com", password))
	if got := permissionsClaim(t, signedIn); !slices.Contains(got, "CONSULT_SENSITIVE_DATA") || len(got) != 4 {
		t.Fatalf("the assignment reaches the next sign-in: %v", got)
	}
}

func TestC_ACollaboratorTokenCarriesWhatWasAssignedAndAfterARemovalTheNextSignInCarriesWhatIsStillHeld(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	colabID := s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	before, claims := s.claims(t, s.signIn(tenantURL, "colab@example.com", password))
	if got := permissionsClaim(t, claims); len(got) != 0 {
		t.Fatalf("a new collaborator holds none: %v", got)
	}
	for _, p := range []string{"VALIDATE_PAYMENT_PROOFS", "MANAGE_CASH"} {
		if rec, _ := s.changePermission(t, admin, colabID, "grant", p); rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	}
	renewed, claims := s.claims(t, s.refresh(before.RefreshToken))
	if got := permissionsClaim(t, claims); !slices.Equal(got, []string{"MANAGE_CASH", "VALIDATE_PAYMENT_PROOFS"}) {
		t.Fatalf("the next refresh carries what was assigned: %v", got)
	}
	if rec, _ := s.changePermission(t, admin, colabID, "removal", "MANAGE_CASH"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// the removal cut every session of the user, the one of this renewed token included
	if rec := s.refresh(renewed.RefreshToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after the removal the refresh is refused: %d %s", rec.Code, rec.Body)
	}
	_, claims = s.claims(t, s.signIn(tenantURL, "colab@example.com", password))
	if got := permissionsClaim(t, claims); !slices.Equal(got, []string{"VALIDATE_PAYMENT_PROOFS"}) {
		t.Fatalf("the next sign-in carries what is still held: %v", got)
	}
}

func TestC_AManagerAndACustomerCarryAnEmptyListOfPermissionsWhateverWasWritten(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "manager@example.com", pgtest.Options{}, "MANAGER")
	customerID := s.account(t, tenantA, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	// a stray row that no role may hold, written by hand: the token ignores it
	if _, err := s.pool.Exec(ctx, `INSERT INTO security.membership_permission (membership_id, permission, granted_at, granted_by)
		SELECT m.membership_id, 'MANAGE_CASH', now(), 'test' FROM security.membership m WHERE m.identity_id = $1::uuid`, customerID); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"manager@example.com", "customer@example.com"} {
		_, claims := s.claims(t, s.signIn(tenantURL, email, password))
		if got := permissionsClaim(t, claims); len(got) != 0 {
			t.Errorf("%s carries %v", email, got)
		}
	}
}
