package port

import (
	"context"
	"time"
)

// NewLink is a verification link as the store keeps it: only the hash, never the link.
type NewLink struct {
	TokenHash string
	// CreatedAt is the instant of the first link of an account, written with it; Issue takes it from its own clock.
	CreatedAt time.Time
	ExpiresAt time.Time
}

// LinkState is what the store knows of a link; a zero time means the mark is not set.
type LinkState struct {
	AccountID  string
	TenantID   string
	ExpiresAt  time.Time
	UsedAt     time.Time
	ReplacedAt time.Time
}

// Verifications keeps the links that verify the e-mail of a Final Customer account (HU-SEC-003).
type Verifications interface {
	// Issue retires every earlier link of the account and writes the new one, unless the account already received limit
	// links within the window before now; it reports whether it wrote.
	Issue(ctx context.Context, accountID string, link NewLink, now time.Time, limit int, window time.Duration) (bool, error)
	// Find reads a link by its hash.
	Find(ctx context.Context, tokenHash string) (LinkState, bool, error)
	// Confirm marks the link used, makes its account active and verified and writes AccountEmailVerified, all together, only
	// while the link is unused, unreplaced and unexpired; it reports whether it did.
	Confirm(ctx context.Context, tokenHash string, now time.Time, correlationID string) (bool, error)
	// MarkSendFailed records that the link could not be sent and why. The cause never holds the link.
	MarkSendFailed(ctx context.Context, tokenHash string, now time.Time, cause string) error
}

// Mail is one verification e-mail. The adapter builds the link from the tenant and the token.
type Mail struct {
	To               string
	TenantName       string
	TenantIdentifier string
	Token            string
}

// Mailer sends the e-mail that carries a credential, directly and never through an event (ADR-004 D3).
type Mailer interface {
	SendVerification(ctx context.Context, m Mail) error
}
