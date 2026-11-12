// Package validate holds the checks that every use case of the service shares: an identifier, a correlation id and the error
// that names the field that was refused. It imports only the standard library.
package validate

import (
	"errors"
	"regexp"
)

// ErrInvalid is any part of a request that is not valid; a FieldError says which.
var ErrInvalid = errors.New("the request is not valid")

// MaxCorrelationID is the longest correlation id the outbox takes (1 to 128 characters).
const MaxCorrelationID = 128

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// UUID tells whether s is an identifier, in lower case as the service writes them.
func UUID(s string) bool { return uuid.MatchString(s) }

// CorrelationID tells whether s can be written with an event: 1 to MaxCorrelationID characters.
func CorrelationID(s string) bool { return len(s) >= 1 && len(s) <= MaxCorrelationID }

// FieldError names the field that was refused and, when there is one, why. It never carries the value.
type FieldError struct {
	Field string
	Err   error
}

// Reason is what the caller is told about the field.
func (e *FieldError) Reason() string {
	if e.Err == nil {
		return "is not valid"
	}
	return e.Err.Error()
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Reason() }

// Unwrap gives the cause, if any.
func (e *FieldError) Unwrap() error { return e.Err }

// Is makes every field error an invalid request.
func (e *FieldError) Is(target error) bool { return target == ErrInvalid }
