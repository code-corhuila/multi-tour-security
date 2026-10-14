package port

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

// ErrNotTemporary is a change of password on an account with no temporary credential in force.
var ErrNotTemporary = errors.New("the account has no temporary credential in force")

// Accounts is where the accounts live. The tenant is empty for the Platform Administrator, and the e-mail arrives
// normalized by account.NormalizeEmail: the store does not guess.
type Accounts interface {
	FindByEmail(ctx context.Context, tenantID, emailNormalized string) (account.Account, bool, error)
	FindByID(ctx context.Context, id string) (account.Account, bool, error)
	// RecordFailure counts a failure and writes the event of a block with the account, atomically. The adapter does it
	// in one SQL statement that must stay equivalent to account.AfterFailure; TestI_TheStatementAndTheDomainRuleAgree
	// pins them together. The correlation id is 1 to 128 characters: the caller always has one (the request's), and an
	// empty or longer one is an error that leaves the count untouched.
	RecordFailure(ctx context.Context, id string, now time.Time, correlationID string) (account.Account, bool, error)
	RecordSuccess(ctx context.Context, id string) error
	// ChangePassword stores the hash of the first password only while the temporary credential is in force at now, in
	// one statement: it clears the temporary state and the lock, cuts off the older sessions and writes
	// AccountSessionsRevoked. Whoever lost the race, or finds no temporary credential, gets ErrNotTemporary.
	ChangePassword(ctx context.Context, id, hash string, now time.Time, correlationID string) error
	// RolesOf lists the roles of the active membership, by name; an account with none has an empty list.
	RolesOf(ctx context.Context, id string) ([]string, error)
}
