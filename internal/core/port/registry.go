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
	// Pending makes the account wait for its e-mail to be verified; Link is then the first link, written with it.
	Pending bool
	Link    *NewLink
}

// AddedRole is the internal role the store gives to the account of a Final Customer of the tenant (HU-SEC-008): the account keeps its
// identity, its password and its history, and no account is created.
type AddedRole struct {
	TenantID  string
	AccountID string
	Role      string
}

// Registered is an account as the store keeps it, with the data the answer of a creation shows. The adapter that
// answers builds its own object from it: the hash inside Account is never returned.
type Registered struct {
	Account account.Account
	Role    string
	// Roles are all the roles of the account, sorted; an account that is customer and team member holds two. Role is the first.
	Roles         []string
	FullName      string
	Phone         string
	EmailVerified bool
	CreatedAt     time.Time
	// Changed is the last change of status; zero when the account never changed.
	Changed StatusChange
	// Permissions are the special permissions assigned to the user and held now, sorted; the ones of their profile are not here, and the
	// answer of the routes turns them into the whole set with account.PermissionsFor. Never nil when the store read them.
	Permissions []string
}

// AccountRegistry is where the accounts of one story are created, and the memory of which key made which account.
type AccountRegistry interface {
	// FindKey returns the account that the key made in the scope, if any.
	FindKey(ctx context.Context, scope, key string) (Registered, bool, error)
	// Create writes the account and the key together. Its only refusals are ErrEmailTaken and ErrKeyTaken.
	Create(ctx context.Context, n NewAccount, scope, key string) (Registered, error)
	// AddRole gives the internal role to the account of an active, verified Final Customer that holds no internal role yet, and writes the
	// key with it, all or nothing. Its refusals are ErrEmailTaken (the account is not that any more, or is of another tenant), ErrKeyTaken
	// and ErrRoleNotEnabled.
	AddRole(ctx context.Context, a AddedRole, scope, key string) (Registered, error)
}
