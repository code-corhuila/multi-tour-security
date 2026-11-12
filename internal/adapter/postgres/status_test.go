package postgres

import (
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

func TestC_AnAccountStatusIsReadExactlyAndAnUnknownOneIsAnError(t *testing.T) {
	for text, want := range map[string]account.Status{"ACTIVE": account.Active, "INACTIVE": account.Inactive, "PENDING": account.Pending} {
		got, err := statusOf(text)
		if err != nil || got != want {
			t.Fatalf("%s: got %v, %v, want %v", text, got, err, want)
		}
	}
	for _, text := range []string{"", "pending", "DELETED", "ACTIVE "} {
		if _, err := statusOf(text); err == nil {
			t.Fatalf("%q must not be read as an account status: Active is the zero value and would let the account in", text)
		}
	}
}
