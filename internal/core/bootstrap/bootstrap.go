// Package bootstrap is the use case that makes the first Platform Administrator, once, from a command and never from a
// route (ADR-004 D5, RN-SEC-001-09). It imports only the standard library and the rest of the core.
package bootstrap

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/password"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

var (
	// ErrInvalidEmail is an address the service would not accept at sign-in either.
	ErrInvalidEmail = errors.New("the e-mail is not valid")
	// ErrWeakPassword is the temporary password, which meets the policy like any other (security-policy.md).
	ErrWeakPassword = password.ErrPolicy
)

// Service holds the pieces of the use case; the composition root fills every one, and a missing one stops it.
type Service struct {
	Admins port.PlatformAdmins
	Hasher port.Hasher
	Clock  func() time.Time
}

// CreateFirst makes the Platform Administrator with a temporary password valid for 72 hours, which serves only to
// choose another at the platform sign-in. It says whether it made one: when a platform account already exists it does
// nothing and that is not an error, so the command can be run again without harm. Only the hash is kept.
func (s *Service) CreateFirst(ctx context.Context, email, temporaryPassword string) (bool, error) {
	if s.Admins == nil || s.Hasher == nil || s.Clock == nil {
		return false, errors.New("the bootstrap is not wired: every piece is needed")
	}
	email = account.NormalizeEmail(email)
	if !account.ValidEmail(email) {
		return false, ErrInvalidEmail
	}
	if err := password.Check(temporaryPassword); err != nil {
		return false, err
	}
	hash, err := s.Hasher.Hash(temporaryPassword)
	if err != nil {
		return false, err
	}
	return s.Admins.CreateFirst(ctx, email, hash, s.Clock().Add(account.TemporaryCredentialLife))
}
