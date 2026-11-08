// Package recoverpassword is the person who forgot a password: asks for a code and then chooses a new password with it
// (HU-SEC-004). Asking never tells whether the account exists, and every refused code is the same refusal. It imports only
// the standard library and the rest of the core.
package recoverpassword

import (
	"context"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/password"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/recovery"
)

var (
	// ErrTenantNotFound is an identifier that names no tenant (only a reset says so; asking answers the same for everyone).
	ErrTenantNotFound = errors.New("the tenant does not exist")
	// ErrCodeRefused is every code that does nothing: wrong, used, expired, retired, of an e-mail with no account, of an
	// inactive account, of another tenant, or of a tenant that is not active.
	ErrCodeRefused = errors.New("the code does not work")
	// ErrNotWired is a piece the composition root did not give.
	ErrNotWired = errors.New("password recovery is not wired: every piece is needed")
)

// FieldError is a field of the request that cannot be what it must be. The names are those of the contract.
type FieldError struct{ Field string }

func (e *FieldError) Error() string { return "the field " + e.Field + " is not valid" }

const (
	platformName = "Multitour"
	// tenantAdministrator is the role whose account opens a whole tenant: its resets are audited (RN-SEC-006-08).
	tenantAdministrator = "TENANT_ADMINISTRATOR"
)

// RequestCode is a person asking for a code. At the platform the identifier is ignored.
type RequestCode struct {
	TenantIdentifier string
	Platform         bool
	Email            string
	CorrelationID    string
}

// Reset is a person choosing a new password with a code.
type Reset struct {
	TenantIdentifier string
	Platform         bool
	Email            string
	Code             string
	NewPassword      string
	Confirmation     string
	CorrelationID    string
}

// Service holds the pieces of the use cases; a missing one stops them.
type Service struct {
	Tenants  port.Tenants
	Accounts port.Accounts
	Codes    port.RecoveryCodes
	Mailer   port.RecoveryMailer
	Hasher   port.Hasher
	// Key is the secret of the HMAC of the codes; it never reaches the database.
	Key    []byte
	Random io.Reader
	Clock  func() time.Time
}

// scope is where the account lives: a tenant that is active, or the platform.
type scope struct {
	tenantID   string
	identifier string
	name       string
}

// where tells what a link names: a tenant that exists and is active, or the platform, is open; a tenant that exists and is
// not active is inactive; an identifier that names none is unknown.
type where int

const (
	open where = iota
	inactive
	unknown
)

// Request sends a code when the rules allow it and says nothing of whether it did: the tenant must be active, the account must
// exist and not be inactive, and it must have received fewer than three codes in the last hour (ADR-004 D10). Only an e-mail
// the service cannot even look up is refused.
func (s *Service) Request(ctx context.Context, r RequestCode) error {
	if s.Tenants == nil || s.Accounts == nil || s.Codes == nil || s.Mailer == nil || s.Random == nil || s.Clock == nil || len(s.Key) == 0 {
		return ErrNotWired
	}
	email := account.NormalizeEmail(r.Email)
	if !account.ValidEmail(email) {
		return &FieldError{Field: "email"}
	}
	at, state, err := s.scope(ctx, r.TenantIdentifier, r.Platform)
	if err != nil || state != open {
		return err
	}
	acct, found, err := s.Accounts.FindByEmail(ctx, at.tenantID, email)
	if err != nil || !found || acct.TenantID != at.tenantID || acct.Status == account.Inactive {
		return err
	}
	now := s.Clock()
	code, err := recovery.New(s.Random, s.Key, acct.ID, now)
	if err != nil {
		return err
	}
	issued, err := s.Codes.Issue(ctx, port.IssueCode{
		AccountID: acct.ID, TenantID: at.tenantID, Limit: recovery.CodesPerWindow, Window: recovery.Window, Now: now, CorrelationID: r.CorrelationID,
		Code: port.NewCode{HMAC: code.HMAC, CreatedAt: code.CreatedAt, ExpiresAt: code.ExpiresAt},
	})
	if err != nil || !issued {
		return err
	}
	// a failed send is recorded on the code and the person asks again: nothing else changes (RN-SEC-006-10)
	mail := port.RecoveryMail{To: email, TenantName: at.name, TenantIdentifier: at.identifier, Code: code.Raw}
	return recovery.Deliver(ctx, s.Mailer, s.Codes, s.Clock, acct.ID, mail, code)
}

// Reset replaces the password, or says why not with one of the errors above. The shape of the request is judged first, so a
// typo in the new password burns no try of the code; and it is judged the same whether the account exists or not, so the
// answer tells nothing about it. A wrong code counts a try and the fifth retires it; every refusal of a code is the same.
func (s *Service) Reset(ctx context.Context, r Reset) error {
	if s.Tenants == nil || s.Accounts == nil || s.Codes == nil || s.Hasher == nil || s.Clock == nil || len(s.Key) == 0 {
		return ErrNotWired
	}
	email := account.NormalizeEmail(r.Email)
	if !account.ValidEmail(email) {
		return &FieldError{Field: "email"}
	}
	if !recovery.ValidShape(r.Code) {
		return &FieldError{Field: "code"}
	}
	var policy error
	switch {
	case password.Check(r.NewPassword) != nil:
		policy = &FieldError{Field: "newPassword"}
	case r.Confirmation != r.NewPassword:
		policy = &FieldError{Field: "newPasswordConfirmation"}
	}
	now := s.Clock()
	at, state, err := s.scope(ctx, r.TenantIdentifier, r.Platform)
	switch {
	case err != nil:
		return err
	case state == unknown:
		return ErrTenantNotFound
	case state == inactive:
		// the shape is judged first for every tenant that exists, so the answer does not tell an inactive one from an active one
		if policy != nil {
			return policy
		}
		return ErrCodeRefused
	}
	acct, found, err := s.Accounts.FindByEmail(ctx, at.tenantID, email)
	if err != nil {
		return err
	}
	if !found || acct.TenantID != at.tenantID || acct.Status == account.Inactive {
		if policy != nil {
			return policy
		}
		return ErrCodeRefused
	}
	roles, err := s.Accounts.RolesOf(ctx, acct.ID)
	if err != nil {
		return err
	}
	administrative := acct.TenantID == "" || slices.Contains(roles, tenantAdministrator)
	fail := func(codeID, reason string) error {
		return s.Codes.RecordFailure(ctx, port.FailedReset{AccountID: acct.ID, TenantID: at.tenantID, CodeID: codeID, Reason: reason,
			Administrative: administrative, Now: now, CorrelationID: r.CorrelationID})
	}
	if policy != nil {
		if administrative {
			if err := fail("", port.ReasonPolicy); err != nil {
				return err
			}
		}
		return policy
	}
	live, found, err := s.Codes.Newest(ctx, acct.ID, now)
	if err != nil {
		return err
	}
	if !found {
		if err := fail("", port.ReasonRetiredCode); err != nil {
			return err
		}
		return ErrCodeRefused
	}
	if !recovery.Equal(live.HMAC, recovery.HMAC(s.Key, acct.ID, r.Code)) {
		if err := fail(live.ID, port.ReasonWrongCode); err != nil {
			return err
		}
		return ErrCodeRefused
	}
	hash, err := s.Hasher.Hash(r.NewPassword)
	if err != nil {
		return err
	}
	done, err := s.Codes.Reset(ctx, port.ResetCommand{
		AccountID: acct.ID, TenantID: at.tenantID, CodeID: live.ID, NewHash: hash, Roles: roles, Administrative: administrative,
		Pending: acct.Status == account.Pending, Now: now, CorrelationID: r.CorrelationID,
	})
	if err != nil {
		return err
	}
	if !done {
		// another request used the code between the check and the write
		return ErrCodeRefused
	}
	return nil
}

// scope finds where the account lives and says whether that place is open, inactive or unknown.
func (s *Service) scope(ctx context.Context, identifier string, platform bool) (scope, where, error) {
	if platform {
		return scope{name: platformName}, open, nil
	}
	tn, found, err := s.Tenants.FindByIdentifier(ctx, identifier)
	switch {
	case err != nil:
		return scope{}, unknown, err
	case !found:
		return scope{}, unknown, nil
	case !tn.IsActive():
		return scope{}, inactive, nil
	}
	return scope{tenantID: tn.TenantID, identifier: tn.Identifier, name: tn.DisplayName()}, open, nil
}
