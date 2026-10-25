// Package verifyemail activates a pending account with its link and its password (HU-SEC-003, spec R-1).
package verifyemail

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/verification"
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
	// ErrNotWired is a piece the composition root did not give.
	ErrNotWired = errors.New("verify e-mail is not wired: every piece is needed")
)

const maxPassword = 128

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

// Confirm verifies the e-mail, or says why not with one of the errors above. A bad link changes nothing; a wrong password
// counts as a failed sign-in, so the link cannot be used to guess the password of the account.
func (s *Service) Confirm(ctx context.Context, r Request) error {
	if s.Tenants == nil || s.Accounts == nil || s.Verifications == nil || s.Hasher == nil || s.Clock == nil {
		return ErrNotWired
	}
	if !verification.ValidShape(r.Token) || r.Password == "" || utf8.RuneCountInString(r.Password) > maxPassword {
		return ErrInvalidRequest
	}
	now := s.Clock()
	tn, found, err := s.Tenants.FindByIdentifier(ctx, r.TenantIdentifier)
	switch {
	case err != nil:
		return err
	case !found:
		return ErrTenantNotFound
	case !tn.IsActive():
		return ErrBadLink
	}
	hash := verification.Hash(r.Token)
	link, found, err := s.Verifications.Find(ctx, hash)
	if err != nil {
		return err
	}
	if !found || link.TenantID != tn.TenantID || !link.UsedAt.IsZero() || !link.ReplacedAt.IsZero() || !now.Before(link.ExpiresAt) {
		return ErrBadLink
	}
	acct, found, err := s.Accounts.FindByID(ctx, link.AccountID)
	if err != nil {
		return err
	}
	if !found || acct.TenantID != tn.TenantID || acct.Status != account.Pending {
		return ErrBadLink
	}
	// a blocked account is the same refusal as a wrong password; being pending is what this call is for
	if err := acct.CanAuthenticate(now); err != nil && !errors.Is(err, account.ErrNotVerified) {
		return ErrWrongPassword
	}
	if !s.Hasher.Compare(acct.PasswordHash, r.Password) {
		if _, _, err := s.Accounts.RecordFailure(ctx, acct.ID, now, r.CorrelationID); err != nil {
			return err
		}
		return ErrWrongPassword
	}
	done, err := s.Verifications.Confirm(ctx, hash, now, r.CorrelationID)
	if err != nil {
		return err
	}
	if !done {
		// another request used the link between the check and the write
		return ErrBadLink
	}
	// clearing the failures is the last thing and the account is already verified: if it fails, the person is not told that the
	// verification failed, which a retry would answer as a bad link. The count restarts with the next sign-in.
	_ = s.Accounts.RecordSuccess(ctx, acct.ID)
	return nil
}
