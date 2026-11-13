package createaccount_test

import (
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
)

// HU-SEC-008: a person whose team side is off holds the internal role still; the e-mail is theirs and the answer says it is an internal user,
// not a customer, and no role is added.
func TestA_APersonWhoseTeamSideIsOffIsStillAnInternalUser(t *testing.T) {
	w := newWorld()
	takenBy(w, account.Active, "FINAL_CUSTOMER") // the roles that are active now: the team side is off
	w.service.Held = &fakeHeld{roles: map[string][]string{existingID: {"FINAL_CUSTOMER", "MANAGER"}}}
	_, _, err := w.service.Create(ctx, internalUser())
	if got := reasonOf(t, err); got != createaccount.TakenByInternalUser {
		t.Fatalf("reason = %v", got)
	}
	if len(w.registry.added) != 0 {
		t.Fatal("a role was added to an account that holds one")
	}
}
