// Package verifyemail activates a pending account with its link and its password (HU-SEC-003, spec R-1).
package verifyemail

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

var (
	// ErrInvalidRequest is a value that cannot be a link or a password.
	ErrInvalidRequest = errors.New("the link or the password is not valid")
	// ErrTenantNotFound is an identifier that names no tenant.
	ErrTenantNotFound = errors.New("the tenant does not exist")
	// ErrBadLink is every link that does nothing: used, expired, replaced, unknown, of another tenant or of an inactive one.
	ErrBadLink = errors.New("the link does not work")
	// ErrWrongPassword is a valid link with a password that is not the account's, or an account that is blocked.
	ErrWrongPassword = errors.New("the password was not accepted")
)

// Request is the confirmation a person makes.
type Request struct {
	TenantIdentifier string
	Token            string
	Password         string
	CorrelationID    string
}

// Service holds the pieces of the use case; a missing one stops it.
type Service struct {
	Tenants       port.Tenants
	Accounts      port.Accounts
	Verifications port.Verifications
	Hasher        port.Hasher
	Clock         func() time.Time
}

// Confirm verifies the e-mail, or says why not with one of the errors above.
func (s *Service) Confirm(ctx context.Context, r Request) error { return errors.New("not implemented") }
