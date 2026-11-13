package refresh_test

import (
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// A renewal keeps the side of the sign-in that opened the session and never widens it (HU-SEC-008, RN-SEC-007-06).

func TestA_RenewalKeepsTheSideOfTheSession(t *testing.T) {
	for _, c := range []struct {
		side string
		want []string
	}{
		{"TEAM", []string{"OPERATIONAL_COLLABORATOR"}},
		{"CUSTOMER", []string{"FINAL_CUSTOMER"}},
		{"", []string{"FINAL_CUSTOMER"}}, // a session opened with one side, whose account gained the other: the lesser side
	} {
		w := newWorld()
		w.accounts.roles[accountID] = []string{"FINAL_CUSTOMER", "OPERATIONAL_COLLABORATOR"}
		w.sessions.renewed = port.Renewed{AccountID: accountID, SessionID: "s-1", Context: c.side}
		if _, err := w.service.Renew(ctx, oldValue); err != nil {
			t.Fatalf("%q: %v", c.side, err)
		}
		if got := w.signer.claims[0].Roles; !slices.Equal(got, c.want) {
			t.Fatalf("%q: roles %v", c.side, got)
		}
	}
}
