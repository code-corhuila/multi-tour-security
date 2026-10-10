package account_test

import (
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

// One rule for an e-mail, for the sign-in and for the first Administrator: plain ASCII with no space or control
// character, one @ that is neither first nor last, 3 to 254 characters. The rule of 06-data is open (spec section 6).

func TestD_AnEmailInPlainASCIIWithAnInnerAtSignIsValid(t *testing.T) {
	for _, ok := range []string{"a@b", "ana@example.com", "ana.perez+tours@sub.example.co", strings.Repeat("a", 240) + "@example.com"} {
		if !account.ValidEmail(ok) {
			t.Errorf("%q was refused", ok)
		}
	}
}

func TestD_EveryOtherShapeIsNotAnEmail(t *testing.T) {
	for name, bad := range map[string]string{
		"empty": "", "two characters": "a@", "no at sign": "ana.example.com", "at sign first": "@example.com", "at sign last": "ana@",
		"space inside": "an a@example.com", "tab": "ana\t@example.com", "newline": "ana\n@example.com", "NUL": "ana\x00@example.com",
		"not ASCII": "añá@example.com", "DEL": "ana\x7f@example.com", "255 characters": strings.Repeat("a", 250) + "@b.co",
	} {
		if account.ValidEmail(bad) {
			t.Errorf("%s: %q was accepted", name, bad)
		}
	}
}
