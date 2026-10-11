// Package createaccount is the one use case that makes an account in a tenant: the customer who registers, the internal
// user and the first Administrator are three kinds of it (plan D-02). It imports only the standard library and the rest
// of the core.
package createaccount

import (
	"context"
	"errors"
	"time"

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
}

// Create makes the account, or returns the one the same key already made with created false and hashes nothing.
func (s *Service) Create(ctx context.Context, c Command) (port.Registered, bool, error) {
	return port.Registered{}, false, errors.New("not implemented")
}
