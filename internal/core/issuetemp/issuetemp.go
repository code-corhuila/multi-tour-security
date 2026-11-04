// Package issuetemp is the use case that gives an internal user a new temporary credential when the first one expired before the
// first sign-in (HU-SEC-005, RN-SEC-003-14 and -15). The password is typed by the issuer; nothing is generated.
package issuetemp

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/password"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

var (
	// ErrInvalid is any field of the request that is not valid; FieldError says which.
	ErrInvalid = errors.New("the request is not valid")
	// ErrNotAuthorized is an issuer that lacks the authority over that user (PDR section 9, G15): it is a business rule, not a 403.
	ErrNotAuthorized = errors.New("the issuer has no authority to issue a credential to that user")

	errMismatch = errors.New("does not match the password")
)

// FieldError names the field that was refused and why, never the value.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string        { return e.Field + ": " + e.Err.Error() }
func (e *FieldError) Unwrap() error        { return e.Err }
func (e *FieldError) Is(target error) bool { return target == ErrInvalid }

const (
	tenantAdministrator   = "TENANT_ADMINISTRATOR"
	platformAdministrator = "PLATFORM_ADMINISTRATOR"
	maxCorrelationID      = 128 // what the outbox takes
)

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Request is one issue. The actor, their role and their tenant are those of the credential, never of the body; the tenant is
// empty for the Platform Administrator.
type Request struct {
	ActorID       string
	ActorRole     string
	ActorTenantID string
	AccountID     string
	Password      string
	Confirmation  string
	CorrelationID string
}

// Service issues through the store the composition root gives it.
type Service struct {
	Store  port.TemporaryCredentials
	Hasher port.Hasher
	Clock  func() time.Time
}

// Issue answers the user as it is now, with the end of the new credential.
func (s *Service) Issue(ctx context.Context, r Request) (port.Registered, error) {
	if s.Store == nil || s.Hasher == nil || s.Clock == nil {
		return port.Registered{}, errors.New("the temporary credential is not wired: the store, the hasher and the clock are needed")
	}
	// the role comes from a token the route already checked: another one, or a correlation id the outbox would refuse, is our mistake
	switch {
	case r.ActorRole != tenantAdministrator && r.ActorRole != platformAdministrator,
		r.ActorRole == tenantAdministrator && r.ActorTenantID == "",
		r.CorrelationID == "" || len(r.CorrelationID) > maxCorrelationID:
		return port.Registered{}, errors.New("the temporary credential was asked with a credential that cannot issue one")
	case !uuid.MatchString(r.ActorID):
		return port.Registered{}, &FieldError{Field: "actorId", Err: errors.New("is not valid")}
	case !uuid.MatchString(r.AccountID):
		return port.Registered{}, &FieldError{Field: "accountId", Err: errors.New("is not valid")}
	case r.Password != r.Confirmation:
		return port.Registered{}, &FieldError{Field: "passwordConfirmation", Err: errMismatch}
	}
	now := s.Clock()
	target, found, err := s.Store.Target(ctx, r.AccountID, now)
	if err != nil {
		return port.Registered{}, err
	}
	// a Tenant Administrator reaches only their own tenant: another tenant's user is not found, not refused
	if !found || (r.ActorRole == tenantAdministrator && target.TenantID != r.ActorTenantID) {
		return port.Registered{}, port.ErrUserNotFound
	}
	if !mayIssue(r.ActorRole, target) {
		return port.Registered{}, ErrNotAuthorized
	}
	// after the authority: whoever may not issue is not told what the password policy says
	if err := password.Check(r.Password); err != nil {
		return port.Registered{}, &FieldError{Field: "password", Err: err}
	}
	if !target.HasTemporary {
		return port.Registered{}, port.ErrNotTemporary // that is the recovery of HU-SEC-004
	}
	// the hash is the expensive step, so it comes after every refusal that costs nothing
	hash, err := s.Hasher.Hash(r.Password)
	if err != nil {
		return port.Registered{}, err
	}
	by := "tenant-administrator/"
	if r.ActorRole == platformAdministrator {
		by = "platform-administrator/"
	}
	return s.Store.Issue(ctx, port.IssueCommand{TenantID: target.TenantID, AccountID: target.AccountID, Hash: hash, By: by + r.ActorID,
		ActorID: r.ActorID, ActorRole: r.ActorRole, CorrelationID: r.CorrelationID, Now: now})
}

// mayIssue is the table of PDR section 9 (G15 and GAP-016): a Tenant Administrator issues to any user of their tenant except the
// first Administrator; the Platform Administrator issues to the first Administrator, and, when no Administrator of the tenant is
// able to sign in, to any of its active Administrators.
func mayIssue(role string, t port.CredentialTarget) bool {
	if role == tenantAdministrator {
		return !t.FirstAdministrator
	}
	return t.FirstAdministrator || (t.Administrator && t.Active && t.AdministratorsAbleToSignIn == 0)
}
