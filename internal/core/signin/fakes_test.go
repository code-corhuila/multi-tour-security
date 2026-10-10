package signin_test

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// The fakes keep what the use case does to them, so a test can tell what happened without a database.

const (
	tenantID  = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	otherID   = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	dummyHash = "$2a$12$dummydummydummydummyduGKf1.cwhIEtZQv0nKjv6/oVxRKKUlq"
	password  = "correct horse"
)

var now = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

type fakeTenants struct {
	copies map[string]tenant.Copy
	err    error
	calls  int
}

func (f *fakeTenants) Apply(context.Context, tenant.Copy) (bool, error) { return false, nil }
func (f *fakeTenants) FindByIdentifier(_ context.Context, identifier string) (tenant.Copy, bool, error) {
	f.calls++
	c, ok := f.copies[identifier]
	return c, ok, f.err
}

func (f *fakeTenants) FindByID(context.Context, string) (tenant.Copy, bool, error) {
	return tenant.Copy{}, false, nil
}

type fakeAccounts struct {
	byKey     map[string]account.Account // tenantID + "|" + e-mail
	roles     map[string][]string
	failures  []string // ids of the accounts that got a failure
	correl    []string
	successes []string
	lookups   []string // the tenant of each lookup, "" for the platform

	findErr, failureErr, successErr, rolesErr error
	// blockOnFailure makes RecordFailure answer that this failure was the fifth
	blockOnFailure bool
}

func (f *fakeAccounts) FindByEmail(_ context.Context, tenantID, email string) (account.Account, bool, error) {
	f.lookups = append(f.lookups, tenantID)
	a, ok := f.byKey[tenantID+"|"+email]
	return a, ok, f.findErr
}
func (f *fakeAccounts) FindByID(context.Context, string) (account.Account, bool, error) {
	return account.Account{}, false, nil
}
func (f *fakeAccounts) RecordFailure(_ context.Context, id string, _ time.Time, correlationID string) (account.Account, bool, error) {
	if f.failureErr != nil {
		return account.Account{}, false, f.failureErr
	}
	f.failures = append(f.failures, id)
	f.correl = append(f.correl, correlationID)
	return account.Account{}, f.blockOnFailure, nil
}
func (f *fakeAccounts) RecordSuccess(_ context.Context, id string) error {
	if f.successErr != nil {
		return f.successErr
	}
	f.successes = append(f.successes, id)
	return nil
}
func (f *fakeAccounts) RolesOf(_ context.Context, id string) ([]string, error) {
	return f.roles[id], f.rolesErr
}

type fakeSessions struct {
	opened []string // the hash of each first value
	owners []string
	at     []time.Time
	err    error
}

func (f *fakeSessions) Open(_ context.Context, accountID, hash string, at time.Time) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.opened = append(f.opened, hash)
	f.owners = append(f.owners, accountID)
	f.at = append(f.at, at)
	return "session-1", nil
}
func (f *fakeSessions) Rotate(context.Context, string, string, time.Time) (port.Renewed, error) {
	return port.Renewed{}, errors.New("not used by sign-in")
}
func (f *fakeSessions) RevokeAll(context.Context, string, time.Time, string) error { return nil }

// fakeHasher accepts the hash "hash:" + password and keeps every hash it was asked to compare against.
type fakeHasher struct{ compared []string }

func (f *fakeHasher) Compare(hash, password string) bool {
	f.compared = append(f.compared, hash)
	return hash == "hash:"+password
}

type fakeSigner struct {
	claims []token.Claims
	err    error
}

func (f *fakeSigner) Sign(c token.Claims) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.claims = append(f.claims, c)
	return "signed.access.token", nil
}
