package signin_test

import (
	"slices"
	"testing"
)

// The side a person signs in from (HU-SEC-008, RN-SEC-007-04 and -06).

const doubleID = "44444444-4444-4444-8444-444444444444"

func doubleWorld() *world {
	w := newWorld()
	w.add(doubleID, tenantID, "ana@example.com", []string{"FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR"}, nil)
	return w
}

func TestA_ASignInAsTheTeamCarriesTheTeamRolesAndOpensASessionOfTheTeam(t *testing.T) {
	w := doubleWorld()
	r := request("travesia-natural", "ana@example.com", password)
	r.Context = "TEAM"
	if _, err := w.service.SignIn(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := w.signer.claims[0].Roles; !slices.Equal(got, []string{"OPERATIONAL_COLLABORATOR"}) {
		t.Fatalf("roles %v", got)
	}
	if !slices.Equal(w.sessions.sides, []string{"TEAM"}) {
		t.Fatalf("sides %v", w.sessions.sides)
	}
}

func TestA_ASignInWithNoSideCarriesTheCustomerRoleAndRemembersIt(t *testing.T) {
	w := doubleWorld()
	if _, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); err != nil {
		t.Fatal(err)
	}
	if got := w.signer.claims[0].Roles; !slices.Equal(got, []string{"FINAL_CUSTOMER"}) || len(w.signer.claims[0].Permissions) != 0 {
		t.Fatalf("roles %v permissions %v", got, w.signer.claims[0].Permissions)
	}
	if !slices.Equal(w.sessions.sides, []string{"CUSTOMER"}) {
		t.Fatalf("sides %v", w.sessions.sides)
	}
}

func TestA_AnAccountWithOneSideKeepsItAndOpensASessionWithNoSide(t *testing.T) {
	w := newWorld()
	w.add(doubleID, tenantID, "bea@example.com", []string{"TENANT_ADMINISTRATOR"}, nil)
	r := request("travesia-natural", "bea@example.com", password)
	r.Context = "CUSTOMER"
	if _, err := w.service.SignIn(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := w.signer.claims[0].Roles; !slices.Equal(got, []string{"TENANT_ADMINISTRATOR"}) || !slices.Equal(w.sessions.sides, []string{""}) {
		t.Fatalf("roles %v sides %v", got, w.sessions.sides)
	}
}

func TestA_ASideThatIsNotOneOfTheTwoIsRefusedAsAnInvalidRequest(t *testing.T) {
	w := doubleWorld()
	r := request("travesia-natural", "ana@example.com", password)
	r.Context = "ADMIN"
	if _, err := w.service.SignIn(ctx, r); err == nil || len(w.sessions.opened) != 0 {
		t.Fatalf("err %v opened %d", err, len(w.sessions.opened))
	}
}
