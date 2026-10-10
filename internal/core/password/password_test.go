package password_test

import (
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/password"
)

// 00-governance/security-policy.md: at least 8 characters with an upper-case letter, a lower-case letter, a number and
// a special character, and common passwords rejected. bcrypt reads 72 bytes, so that is the longest.

func TestD_APasswordThatMeetsThePolicyIsAccepted(t *testing.T) {
	for _, ok := range []string{"Tr4vesia-Natural", "aA1!aaaa", "Zq9$kLm2", "Contraseña-Fuerte7", strings.Repeat("aA1!", 18)} {
		if err := password.Check(ok); err != nil {
			t.Errorf("%q was refused: %v", ok, err)
		}
	}
}

func TestD_EveryRuleOfThePolicyRefusesItsOwnViolation(t *testing.T) {
	cases := map[string]string{
		"seven characters":  "aA1!aaa",
		"no upper-case":     "tr4vesia-natural",
		"no lower-case":     "TR4VESIA-NATURAL",
		"no number":         "Travesia-Natural",
		"no special":        "Tr4vesiaNatural",
		"empty":             "",
		"73 bytes":          strings.Repeat("aA1!", 18) + "a",
		"37 two-byte chars": "aA1!" + strings.Repeat("ñ", 35),
	}
	for name, pw := range cases {
		if err := password.Check(pw); err == nil {
			t.Errorf("%s: %q was accepted", name, pw)
		}
	}
}

func TestD_ACommonPasswordIsRefusedWhateverItsCase(t *testing.T) {
	for _, common := range []string{"Password1!", "password1!", "PASSWORD1!", "Welcome123!", "Qwerty123!", "P@ssw0rd"} {
		if err := password.Check(common); err == nil {
			t.Errorf("the common password %q was accepted", common)
		}
	}
}

func TestD_ASpaceCountsAsASpecialCharacterAndIsKeptAsTyped(t *testing.T) {
	if err := password.Check("Tr4vesia Natural"); err != nil {
		t.Errorf("a passphrase with spaces meets the policy: %v", err)
	}
}

func TestD_TheRefusalSaysWhichRuleWasBrokenWithoutQuotingThePassword(t *testing.T) {
	err := password.Check("Secretoo1")
	if err == nil || strings.Contains(err.Error(), "Secretoo1") {
		t.Fatalf("the error must exist and not quote the password: %v", err)
	}
}
