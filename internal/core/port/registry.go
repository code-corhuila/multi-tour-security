package port

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

var (
	// ErrEmailTaken is the e-mail of an account that already exists in the tenant, whatever its status; the store
	// raises it when the unique key of the account refuses a write that a race let through.
	ErrEmailTaken = errors.New("the e-mail is already in use in this tenant")
	// ErrKeyTaken is an idempotency key that another request wrote first; the caller reads it again and answers a repeat.
	ErrKeyTaken = errors.New("the idempotency key already made an account")
)

// NewAccount is what the store writes: an active account, its membership and its role, and the key, all or nothing.
// The e-mail arrives normalized. TemporaryUntil is zero for an ordinary password.
type NewAccount struct {
	TenantID        string
	EmailNormalized string
	PasswordHash    string
	FullName        string
	Phone           string // empty when the person gave none
	Role            string
	TemporaryUntil  time.Time
	CreatedBy       string
}

// Registered is an account as the store keeps it, with the data the answer of a creation shows. The adapter that
// answers builds its own object from it: the hash inside Account is never returned.
type Registered struct {
	Account       account.Account
	Role          string
	FullName      string
	Phone         string
	EmailVerified bool
}

// AccountRegistry is where the accounts of one story are created, and the memory of which key made which account.
type AccountRegistry interface {
	// FindKey returns the account that the key made in the scope, if any.
	FindKey(ctx context.Context, scope, key string) (Registered, bool, error)
	// Create writes the account and the key together. Its only refusals are ErrEmailTaken and ErrKeyTaken.
	Create(ctx context.Context, n NewAccount, scope, key string) (Registered, error)
}
