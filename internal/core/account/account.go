// Package account is the account of one person inside one tenant: whether it may authenticate, its
// temporary credential and the lock after repeated failures. It imports only the standard library
// (plan D-02 of the piece); persistence, hashing and tokens are the adapters' business.
package account

import (
	"errors"
	"strings"
	"time"
)

// Status of an account (PDR §9: an inactive account cannot authenticate).
type Status int

const (
	Active Status = iota
	Inactive
)

const (
	// TemporaryCredentialLife is how long a temporary credential works (PDR §9, ADR-004 D5).
	TemporaryCredentialLife = 72 * time.Hour
	// MaxFailures within FailureWindow block the account for BlockLife (ADR-004 D10).
	MaxFailures   = 5
	FailureWindow = 15 * time.Minute
	BlockLife     = 15 * time.Minute
)

var (
	ErrInactive         = errors.New("the account is inactive")
	ErrBlocked          = errors.New("the account is blocked")
	ErrTemporaryExpired = errors.New("the temporary credential has expired")
)

// Account holds what the rules below need. TenantID is empty only for the Platform Administrator.
type Account struct {
	ID              string
	TenantID        string
	EmailNormalized string
	PasswordHash    string
	Status          Status
	// TemporaryUntil is zero for an ordinary account.
	TemporaryUntil time.Time
	Failed         int
	FirstFailedAt  time.Time
	BlockedUntil   time.Time
}

// NewWithTemporaryCredential is an account whose password is a temporary one, valid 72 hours from now.
func NewWithTemporaryCredential(id, tenantID, emailNormalized, passwordHash string, now time.Time) Account {
	return Account{
		ID: id, TenantID: tenantID, EmailNormalized: emailNormalized, PasswordHash: passwordHash,
		Status: Active, TemporaryUntil: now.Add(TemporaryCredentialLife),
	}
}

// NormalizeEmail lowers the case and trims the spaces, and nothing else: the rule is not defined in 06-data
// (spec section 6), so the service does not invent more than it can defend. It does not apply Unicode
// normalization, which the standard library cannot do; the sign-in route limits the e-mail to ASCII.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// IsPlatform tells the account of the Platform Administrator, the only one with no tenant.
func (a Account) IsPlatform() bool { return a.TenantID == "" }

// CanAuthenticate tells whether the account may be authenticated now, whatever the password. The order of the
// refusals is inactive, blocked, expired; the adapter gives one and the same answer for all of them, so that a
// person who does not know the password learns nothing of the state of the account (spec RN-SEC-001-02).
func (a Account) CanAuthenticate(now time.Time) error {
	switch {
	case a.Status == Inactive:
		return ErrInactive
	case now.Before(a.BlockedUntil):
		return ErrBlocked
	case !a.TemporaryUntil.IsZero() && !now.Before(a.TemporaryUntil):
		return ErrTemporaryExpired
	}
	return nil
}

// UsesTemporaryCredential tells whether the password of the account is still a temporary one, which only
// allows choosing a password of its own.
func (a Account) UsesTemporaryCredential(now time.Time) bool {
	return !a.TemporaryUntil.IsZero() && now.Before(a.TemporaryUntil)
}

// AfterFailure counts a failed sign-in. The fifth within the window blocks the account and says so, so
// that the block is audited; a failure outside the window opens a new one.
func (a Account) AfterFailure(now time.Time) (Account, bool) {
	// a failure that arrives while the account is blocked changes nothing: it neither lifts the block, nor extends
	// it, nor is audited a second time
	if now.Before(a.BlockedUntil) {
		return a, false
	}
	if a.Failed == 0 || !now.Before(a.FirstFailedAt.Add(FailureWindow)) {
		a.Failed = 1
		a.FirstFailedAt = now
		a.BlockedUntil = time.Time{}
		return a, false
	}
	a.Failed++
	if a.Failed >= MaxFailures {
		a.BlockedUntil = now.Add(BlockLife)
		return a, true
	}
	return a, false
}

// AfterSuccess clears the failures.
func (a Account) AfterSuccess() Account {
	a.Failed = 0
	a.FirstFailedAt = time.Time{}
	a.BlockedUntil = time.Time{}
	return a
}
