// Package requestlink is the person who asks for a new verification link (HU-SEC-003). Its answer never tells whether the
// account exists, so it returns nothing but a refusal of the request itself.
package requestlink

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// ErrInvalidRequest is an e-mail the service cannot even look up.
var ErrInvalidRequest = errors.New("the e-mail is not valid")

// Service holds the pieces of the use case; a missing one stops it.
type Service struct {
	Tenants       port.Tenants
	Accounts      port.Accounts
	Verifications port.Verifications
	Mailer        port.Mailer
	Random        io.Reader
	Clock         func() time.Time
}

// Request sends a new link when the rules allow it and says nothing of whether it did.
func (s *Service) Request(ctx context.Context, tenantIdentifier, email string) error {
	return errors.New("not implemented")
}
