// Package createaccount is the one use case that makes an account in a tenant: the customer who registers, the internal
// user and the first Administrator are three kinds of it (plan D-02). It imports only the standard library and the rest
// of the core.
package createaccount

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/password"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// Kind is who is being created; each kind is a row of the table.
type Kind int

const (
	Customer Kind = iota + 1
	InternalUser
	FirstAdministrator
)

var (
	ErrTenantNotFound  = errors.New("the tenant does not exist")
	ErrTenantNotActive = errors.New("the tenant is not active")
	ErrNotWired        = errors.New("create account is not wired: every piece is needed")
)

// FieldError names the field that was refused and why, never the value.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

// Command is one request. FirstName and LastName are the customer's; FullName is the other kinds'. Role is asked only
// for an internal user, and Actor is who asks for the other two kinds. Confirmation is the customer's only.
type Command struct {
	Kind           Kind
	TenantID       string
	FirstName      string
	LastName       string
	FullName       string
	Email          string
	Phone          string
	Password       string
	Confirmation   string
	Role           string
	Actor          string
	IdempotencyKey string
}

// Service holds the pieces of the use case; the composition root fills every one, and a missing one stops it.
type Service struct {
	Tenants  port.Tenants
	Accounts port.Accounts
	Registry port.AccountRegistry
	Hasher   port.Hasher
	Clock    func() time.Time
	// Verifications, Mailer and Random are needed to create a customer account, which waits for its e-mail to be verified.
	Verifications port.Verifications
	Mailer        port.Mailer
	Random        io.Reader
}

// Create makes the account, or returns the one the same key already made with created false and hashes nothing.
func (s *Service) Create(ctx context.Context, c Command) (port.Registered, bool, error) {
	if s.Tenants == nil || s.Accounts == nil || s.Registry == nil || s.Hasher == nil || s.Clock == nil {
		return port.Registered{}, false, ErrNotWired
	}
	r, ok := rules(c.Kind)
	if !ok {
		return port.Registered{}, false, errors.New("the kind of account is not known")
	}
	if n := len(c.IdempotencyKey); n < 8 || n > 128 {
		return port.Registered{}, false, refuse("idempotencyKey", errBadLength)
	}
	if c.TenantID == "" {
		return port.Registered{}, false, refuse("tenantId", errMissing)
	}
	// the repeat is answered before the body is read, so a retry whose body changed still gets its first account
	scope := r.scope + ":" + c.TenantID
	if prior, found, err := s.Registry.FindKey(ctx, scope, c.IdempotencyKey); err != nil || found {
		return withoutHash(prior), false, err
	}

	fullName, phone, role, err := profile(r, c)
	if err != nil {
		return port.Registered{}, false, err
	}
	if r.selfService && c.Password != c.Confirmation {
		return port.Registered{}, false, refuse("passwordConfirmation", errMismatch)
	}
	if r.activeTenant {
		if err := s.requireActiveTenant(ctx, c.TenantID); err != nil {
			return port.Registered{}, false, err
		}
	}
	// after the tenant: a form for a tenant that does not exist is not told about its password
	if err := password.Check(c.Password); err != nil {
		return port.Registered{}, false, refuse("password", err)
	}
	email := account.NormalizeEmail(c.Email)
	if !account.ValidEmail(email) {
		return port.Registered{}, false, refuse("email", errInvalid)
	}
	if _, taken, err := s.Accounts.FindByEmail(ctx, c.TenantID, email); err != nil || taken {
		if err == nil {
			err = port.ErrEmailTaken
		}
		return port.Registered{}, false, err
	}
	// the hash is the expensive step, so it comes after every refusal that costs nothing
	hash, err := s.Hasher.Hash(c.Password)
	if err != nil {
		return port.Registered{}, false, err
	}
	n := port.NewAccount{TenantID: c.TenantID, EmailNormalized: email, PasswordHash: hash, FullName: fullName, Phone: phone,
		Role: role, CreatedBy: r.createdBy}
	if r.hasActor {
		n.CreatedBy += "/" + strings.TrimSpace(c.Actor)
	}
	if r.temporary {
		n.TemporaryUntil = s.Clock().Add(account.TemporaryCredentialLife)
	}
	made, err := s.Registry.Create(ctx, n, scope, c.IdempotencyKey)
	if errors.Is(err, port.ErrKeyTaken) {
		// another request with the same key won the race: the answer is the repeat of its account
		prior, found, ferr := s.Registry.FindKey(ctx, scope, c.IdempotencyKey)
		if ferr == nil && !found {
			ferr = errors.New("the idempotency key was taken and cannot be read")
		}
		return withoutHash(prior), false, ferr
	}
	return withoutHash(made), err == nil, err
}

// withoutHash is the only way an account leaves the use case: the hash stays with the store and the Hasher.
func withoutHash(r port.Registered) port.Registered {
	r.Account.PasswordHash = ""
	return r
}

func (s *Service) requireActiveTenant(ctx context.Context, tenantID string) error {
	t, found, err := s.Tenants.FindByID(ctx, tenantID)
	switch {
	case err != nil:
		return err
	case !found:
		return ErrTenantNotFound
	case !t.IsActive():
		return ErrTenantNotActive
	}
	return nil
}
