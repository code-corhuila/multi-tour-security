// Package changepassword is the use case of whoever holds a temporary credential and chooses a password of their own
// (PDR section 9, RN-SEC-001-04). It imports only the standard library and the rest of the core.
package changepassword

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/password"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
)

// ErrWeakPassword is a new password that breaks the policy or is the temporary one. It says nothing of any account.
var ErrWeakPassword = errors.New("the password is not acceptable")

// Request comes from the token of the temporary credential: the account is its subject and the tenant its claim.
type Request struct {
	AccountID     string
	TenantID      string
	NewPassword   string
	CorrelationID string
}

// Service holds the pieces of the use case; the composition root fills every one, and a missing one stops it.
type Service struct {
	Accounts port.Accounts
	Hasher   port.Hasher
	Clock    func() time.Time
}

// Change replaces the temporary credential with the password chosen. Every reason it cannot be changed is
// signin.ErrRefused: the account is gone or inactive, it has no temporary credential in force (already changed, or
// expired), the token is of another tenant, or another change won the race.
func (s *Service) Change(ctx context.Context, r Request) error {
	if s.Accounts == nil || s.Hasher == nil || s.Clock == nil {
		return errors.New("the change of password is not wired: every piece is needed")
	}
	if r.AccountID == "" || len(r.CorrelationID) < 1 || len(r.CorrelationID) > 128 {
		return errors.New("the request has no account or no usable correlation id")
	}
	now := s.Clock()
	acct, found, err := s.Accounts.FindByID(ctx, r.AccountID)
	if err != nil {
		return err
	}
	if !found || acct.Status == account.Inactive || !acct.UsesTemporaryCredential(now) || acct.TenantID != r.TenantID {
		return signin.ErrRefused
	}
	// after the account: the holder of a stale token is told the same whatever password they send
	if password.Check(r.NewPassword) != nil {
		return ErrWeakPassword
	}
	if s.Hasher.Compare(acct.PasswordHash, r.NewPassword) {
		return ErrWeakPassword // the point is that the person chooses another
	}
	hash, err := s.Hasher.Hash(r.NewPassword)
	if err != nil {
		return err
	}
	err = s.Accounts.ChangePassword(ctx, acct.ID, hash, now, r.CorrelationID)
	if errors.Is(err, port.ErrNotTemporary) {
		return signin.ErrRefused
	}
	return err
}
