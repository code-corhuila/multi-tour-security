package createaccount

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	errMissing   = errors.New("is required")
	errBadLength = errors.New("has a length out of range")
	errInvalid   = errors.New("is not valid")
	errMismatch  = errors.New("does not match the password")
)

const (
	maxCustomerName = 50
	maxFullName     = 100
)

// phonePattern is the one of the contract and of the column that will hold it (plan D-04, D-08).
var phonePattern = regexp.MustCompile(`^[0-9+() -]{7,20}$`)

func refuse(field string, err error) error { return &FieldError{Field: field, Err: err} }

// profile checks the data of the person and the role the kind needs, and returns the full name, the phone and the role.
func profile(r rule, c Command) (fullName, phone, role string, err error) {
	role = r.role
	if role == "" {
		if role = strings.TrimSpace(c.Role); !tenantRole(role) {
			return "", "", "", refuse("role", errInvalid)
		}
	}
	if r.hasActor && strings.TrimSpace(c.Actor) == "" {
		return "", "", "", refuse("actor", errMissing)
	}
	if r.selfService {
		first, err := name("firstName", c.FirstName, maxCustomerName)
		if err != nil {
			return "", "", "", err
		}
		last, err := name("lastName", c.LastName, maxCustomerName)
		if err != nil {
			return "", "", "", err
		}
		fullName = first + " " + last
	} else if fullName, err = name("fullName", c.FullName, maxFullName); err != nil {
		return "", "", "", err
	}
	// the customer must give a phone; the other kinds may leave it out
	if c.Phone == "" && !r.selfService {
		return fullName, "", role, nil
	}
	if !phonePattern.MatchString(c.Phone) {
		return "", "", "", refuse("phone", errInvalid)
	}
	return fullName, c.Phone, role, nil
}

func name(field, value string, limit int) (string, error) {
	value = strings.TrimSpace(value)
	n := utf8.RuneCountInString(value)
	if n == 0 {
		return "", refuse(field, errMissing)
	}
	if n > limit {
		return "", refuse(field, errBadLength)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", refuse(field, errInvalid)
	}
	return value, nil
}
