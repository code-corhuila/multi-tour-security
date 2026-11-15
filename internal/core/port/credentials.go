package port

import (
	"context"
	"time"
)

// CredentialTarget is what the store knows about an internal user that decides who may issue them a new temporary credential
// (spec 003, RN-SEC-003-14). Only an internal user of some tenant has one: a customer, the platform account and an id that does
// not exist are not found.
type CredentialTarget struct {
	AccountID string
	TenantID  string
	// Active is the status ACTIVE; HasTemporary is a temporary credential that is in force or has expired, as opposed to the
	// password the person chose; Administrator is the role TENANT_ADMINISTRATOR with an active membership.
	Active        bool
	HasTemporary  bool
	Administrator bool
	// FirstAdministrator is the Administrator that the onboarding saga made: the creator of their membership is a service.
	FirstAdministrator bool
	// AdministratorsAbleToSignIn counts the Tenant Administrators of the same tenant that can sign in at the instant asked:
	// active, not blocked, and with no temporary credential or one still in force.
	AdministratorsAbleToSignIn int
}

// IssueCommand asks to give an account a new temporary credential. By is the issuer as it is recorded with the account and
// ActorID and ActorRole are the same issuer as the event shows them. TenantID is the tenant of the account, read from the
// target, so that the event of a Platform Administrator names the tenant of the user and not the issuer, who has none.
type IssueCommand struct {
	TenantID      string
	AccountID     string
	Hash          string
	By            string
	ActorID       string
	ActorRole     string
	CorrelationID string
	Now           time.Time
}

// TemporaryCredentials is where a new temporary credential is issued (spec 003, RN-SEC-003-14 and -15).
type TemporaryCredentials interface {
	// Target reads the facts of the authority at the instant now. The second answer is false when it is not an internal user.
	Target(ctx context.Context, accountID string, now time.Time) (CredentialTarget, bool, error)
	// Issue replaces the hash, starts the 72 hours, clears the failed sign-ins and the block, keeps who and when and writes
	// AccountTemporaryCredentialIssued (the issuer, the account, the tenant and the instant, never the password), all or
	// nothing, and only while the account is active and still has a temporary credential: otherwise ErrNotTemporary. It
	// answers the user as it is now.
	Issue(ctx context.Context, c IssueCommand) (Registered, error)
}
