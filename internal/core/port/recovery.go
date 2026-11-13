package port

import (
	"context"
	"time"
)

// The reasons a reset of an administrative account is refused, as the fact PasswordResetFailed carries them (HU-SEC-004,
// plan D-07). None of them says anything a stranger could use.
const (
	ReasonWrongCode   = "WRONG_CODE"
	ReasonRetiredCode = "RETIRED_CODE"
	ReasonPolicy      = "POLICY"
)

// NewCode is a recovery code as the store keeps it: only its HMAC, never the code.
type NewCode struct {
	HMAC      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IssueCode asks the store to write a new code for an account. TenantID is empty for the Platform Administrator.
type IssueCode struct {
	AccountID     string
	TenantID      string
	Code          NewCode
	Now           time.Time
	Limit         int
	Window        time.Duration
	CorrelationID string
}

// CodeState is the newest live code of an account: unused, not retired and not expired at the instant asked.
type CodeState struct {
	ID         string
	HMAC       string
	WrongTries int
}

// FailedReset is a refused reset. CodeID is empty when there was no live code to count the try against.
type FailedReset struct {
	AccountID      string
	TenantID       string
	CodeID         string
	Reason         string
	Administrative bool
	Now            time.Time
	CorrelationID  string
}

// ResetCommand is a reset the person proved with the code. Roles are the roles of the active membership at that moment.
type ResetCommand struct {
	AccountID      string
	TenantID       string
	CodeID         string
	NewHash        string
	Roles          []string
	Administrative bool
	// Pending is an account whose e-mail was not verified: the code proved the mailbox, so it becomes active and verified.
	Pending       bool
	Now           time.Time
	CorrelationID string
}

// RecoveryCodes keeps the codes that let a person choose a new password (HU-SEC-004).
type RecoveryCodes interface {
	// Issue retires every earlier code of the account and writes the new one with the fact PasswordRecoveryRequested, all
	// together, unless the account already received limit codes within the window before Now; it reports whether it wrote.
	Issue(ctx context.Context, c IssueCode) (bool, error)
	// Newest reads the newest live code of the account at the instant now; the second answer is false when it has none.
	Newest(ctx context.Context, accountID string, now time.Time) (CodeState, bool, error)
	// RecordFailure counts a wrong try against the code and retires it at the fifth, and, for an administrative account,
	// writes PasswordResetFailed with the reason, all together. The count is one conditional statement
	// (wrong_tries = wrong_tries + 1 only while the code is live and has fewer than five), so two concurrent wrong tries
	// count two and a sixth is never counted. It counts nothing when there is no code, or when the code was used or retired
	// after Newest read it, and the administrative fact is written all the same.
	RecordFailure(ctx context.Context, f FailedReset) error
	// Reset is the only call that changes a password and the use case makes no other: the store, not the use case, cuts the
	// sessions, lifts the block and verifies the account. It uses the code, replaces the password, lifts the block of failed sign-ins, ends every session of the account,
	// verifies a pending account and writes the facts, all or nothing, and only while the code is still live; it reports
	// whether it did, so two resets with one code change the password once.
	Reset(ctx context.Context, c ResetCommand) (bool, error)
	// MarkSendFailed records that the code of the account could not be sent and why. The cause never holds the code.
	MarkSendFailed(ctx context.Context, accountID, hmac string, now time.Time, cause string) error
}

// RecoveryMail is one recovery e-mail. The code is the only secret it carries.
type RecoveryMail struct {
	To               string
	TenantName       string
	TenantIdentifier string
	Code             string
}

// RecoveryMailer sends the e-mail that carries a recovery code, directly and never through an event (ADR-004 D3). It is
// apart from Mailer so that the pieces that send links do not have to know about codes.
type RecoveryMailer interface {
	SendRecoveryCode(ctx context.Context, m RecoveryMail) error
}
