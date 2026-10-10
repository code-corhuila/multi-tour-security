package port

import (
	"context"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

// Accounts is where the accounts live. The tenant is empty for the Platform Administrator, and the e-mail arrives
// normalized by account.NormalizeEmail: the store does not guess.
type Accounts interface {
	FindByEmail(ctx context.Context, tenantID, emailNormalized string) (account.Account, bool, error)
	FindByID(ctx context.Context, id string) (account.Account, bool, error)
	// RecordFailure applies account.AfterFailure atomically and writes the event of a block with the account. The
	// correlation id is 1 to 128 characters: the caller always has one (the request's), and an empty or longer one is
	// an error that leaves the count untouched.
	RecordFailure(ctx context.Context, id string, now time.Time, correlationID string) (account.Account, bool, error)
	RecordSuccess(ctx context.Context, id string) error
	// RolesOf lists the roles of the active membership, by name; an account with none has an empty list.
	RolesOf(ctx context.Context, id string) ([]string, error)
}
