package validate_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// The checks that every use case shares: an identifier, a correlation id and the error that names a field.

func TestD_AnIdentifierIsALowerCaseUUIDAndNothingElse(t *testing.T) {
	for _, ok := range []string{"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", "00000000-0000-0000-0000-000000000000"} {
		if !validate.UUID(ok) {
			t.Errorf("%q is an identifier", ok)
		}
	}
	for _, bad := range []string{"", "not-a-uuid", "3F2B8C1E-5D4A-4F6B-9C7D-1A2B3C4D5E6F", "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f\n", " 3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f",
		"3f2b8c1e5d4a4f6b9c7d1a2b3c4d5e6f", "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6"} {
		if validate.UUID(bad) {
			t.Errorf("%q is not an identifier", bad)
		}
	}
}

func TestD_ACorrelationIdHasOneToHundredTwentyEightCharacters(t *testing.T) {
	if !validate.CorrelationID("a") || !validate.CorrelationID(strings.Repeat("c", validate.MaxCorrelationID)) {
		t.Fatal("1 and 128 characters are fine")
	}
	if validate.CorrelationID("") || validate.CorrelationID(strings.Repeat("c", validate.MaxCorrelationID+1)) {
		t.Fatal("none and 129 characters are not")
	}
	if validate.MaxCorrelationID != 128 {
		t.Fatalf("the outbox takes 128: %d", validate.MaxCorrelationID)
	}
}

func TestD_AFieldErrorNamesTheFieldIsAnInvalidRequestAndNeverShowsAValue(t *testing.T) {
	plain := &validate.FieldError{Field: "role"}
	why := &validate.FieldError{Field: "password", Err: errors.New("at least 8 characters")}
	for _, err := range []error{plain, why} {
		var got *validate.FieldError
		if !errors.Is(err, validate.ErrInvalid) || !errors.As(err, &got) {
			t.Fatalf("%v must be an invalid request", err)
		}
	}
	if plain.Error() != "role: is not valid" || why.Error() != "password: at least 8 characters" {
		t.Fatalf("%q %q", plain.Error(), why.Error())
	}
	if plain.Reason() != "is not valid" || why.Reason() != "at least 8 characters" {
		t.Fatalf("the reason is what the caller is told: %q %q", plain.Reason(), why.Reason())
	}
	if errors.Unwrap(why) == nil || errors.Unwrap(plain) != nil {
		t.Fatal("only a field error with a cause unwraps")
	}
}
