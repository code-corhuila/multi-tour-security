// Package password is the policy of the passwords of every role (00-governance/security-policy.md, PDR section 9). It
// imports only the standard library.
package password

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	minLength = 8
	// maxBytes is how much of a password bcrypt reads: a longer one would be read only up to here.
	maxBytes = 72
)

// ErrPolicy is a password that breaks the policy. Its text says which rule and never quotes the password.
var ErrPolicy = errors.New("the password does not meet the policy")

// common holds the passwords that meet the rules of composition and are still the first ones anyone tries, in lower
// case. A full list of known-compromised passwords needs an outside source and is a declared gap of this piece.
var common = map[string]bool{
	"password1!": true, "password123!": true, "password1234!": true, "passw0rd!": true, "p@ssw0rd": true, "p@ssword1": true,
	"p@ssw0rd1": true, "welcome1!": true, "welcome123!": true, "qwerty1!": true, "qwerty123!": true, "qwerty12345!": true,
	"admin123!": true, "admin1234!": true, "abc12345!": true, "changeme1!": true, "letmein123!": true, "iloveyou1!": true,
	"contraseña1!": true, "multitour1!": true, "colombia1!": true, "corhuila1!": true, "123456aa!": true, "1q2w3e4r!": true,
}

// Check applies the policy: 8 characters at least and 72 bytes at most, with an upper-case letter, a lower-case letter, a
// number and a special character (anything that is not a letter or a number, a space too), and not a common one.
func Check(pw string) error {
	if utf8.RuneCountInString(pw) < minLength {
		return fmt.Errorf("%w: at least %d characters", ErrPolicy, minLength)
	}
	if len(pw) > maxBytes {
		return fmt.Errorf("%w: at most %d bytes", ErrPolicy, maxBytes)
	}
	var upper, lower, digit, special bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case !unicode.IsLetter(r):
			special = true
		}
	}
	if !upper || !lower || !digit || !special {
		return fmt.Errorf("%w: an upper-case letter, a lower-case letter, a number and a special character", ErrPolicy)
	}
	if common[strings.ToLower(pw)] {
		return fmt.Errorf("%w: it is too common", ErrPolicy)
	}
	return nil
}
