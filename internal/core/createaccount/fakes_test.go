package createaccount_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

const (
	tenantID    = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	otherTenant = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	goodPass    = "Correct-Horse-9"
	idemKey     = "key-0123456789"
	existingID  = "acc-existing"
	hashPrefix  = "hash:"
	actorAdmin  = "acc-admin"
	serviceSub  = "workflow-onboard-tenant"
)

var now = time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)

type fakeTenants struct {
	copies map[string]tenant.Copy
	err    error
	calls  int
}

func (f *fakeTenants) Apply(context.Context, tenant.Copy) (bool, error) { return false, nil }
func (f *fakeTenants) FindByIdentifier(context.Context, string) (tenant.Copy, bool, error) {
	return tenant.Copy{}, false, nil
}
func (f *fakeTenants) FindByID(_ context.Context, id string) (tenant.Copy, bool, error) {
	f.calls++
	c, ok := f.copies[id]
	return c, ok, f.err
}

// fakeAccounts answers only the lookup by e-mail; any other method of the port would panic, which proves it is unused.
type fakeAccounts struct {
	port.Accounts
	byKey map[string]account.Account // tenantID + "|" + e-mail
	err   error
}

func (f *fakeAccounts) FindByEmail(_ context.Context, tenantID, email string) (account.Account, bool, error) {
	a, ok := f.byKey[tenantID+"|"+email]
	return a, ok, f.err
}

type fakeRegistry struct {
	keys     map[string]port.Registered // scope + "|" + key
	created  []port.NewAccount
	scopes   []string
	findErr  error
	createFn func(n port.NewAccount) error // when set, its error is the answer of Create
}

func (f *fakeRegistry) FindKey(_ context.Context, scope, key string) (port.Registered, bool, error) {
	r, ok := f.keys[scope+"|"+key]
	return r, ok, f.findErr
}

func (f *fakeRegistry) Create(_ context.Context, n port.NewAccount, scope, key string) (port.Registered, error) {
	if f.createFn != nil {
		if err := f.createFn(n); err != nil {
			return port.Registered{}, err
		}
	}
	f.created = append(f.created, n)
	f.scopes = append(f.scopes, scope)
	status := account.Active
	if n.Pending {
		status = account.Pending
	}
	r := port.Registered{
		Account: account.Account{ID: "acc-new", TenantID: n.TenantID, EmailNormalized: n.EmailNormalized,
			PasswordHash: n.PasswordHash, Status: status, TemporaryUntil: n.TemporaryUntil},
		Role: n.Role, FullName: n.FullName, Phone: n.Phone,
	}
	if f.keys == nil {
		f.keys = map[string]port.Registered{}
	}
	f.keys[scope+"|"+key] = r
	return r, nil
}

type fakeHasher struct {
	hashed []string
	err    error
}

func (f *fakeHasher) Compare(string, string) bool { return false }
func (f *fakeHasher) Hash(pw string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.hashed = append(f.hashed, pw)
	return hashPrefix + pw, nil
}

// fakeMailer keeps every e-mail it was asked to send; err is the answer of the next sends.
type fakeMailer struct {
	sent []port.Mail
	err  error
}

func (f *fakeMailer) SendVerification(_ context.Context, m port.Mail) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, m)
	return nil
}

// fakeVerifications keeps what the use case reports about a failed send; the rest of the port is not used here.
type fakeVerifications struct {
	port.Verifications
	failedHashes []string
	causes       []string
}

func (f *fakeVerifications) MarkSendFailed(_ context.Context, hash string, _ time.Time, cause string) error {
	f.failedHashes = append(f.failedHashes, hash)
	f.causes = append(f.causes, cause)
	return nil
}

// the same 32 bytes every time, so a test knows the link without reading it from the mail
func fixedRandom() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{7}, 32*10)) }

var errSMTP = errors.New("smtp: connection refused")

type world struct {
	tenants       *fakeTenants
	accounts      *fakeAccounts
	registry      *fakeRegistry
	hasher        *fakeHasher
	mailer        *fakeMailer
	verifications *fakeVerifications
	service       *createaccount.Service
}

func newWorld() *world {
	w := &world{
		tenants:       &fakeTenants{copies: map[string]tenant.Copy{tenantID: {TenantID: tenantID, Identifier: "travesia", Status: tenant.Active}}},
		accounts:      &fakeAccounts{byKey: map[string]account.Account{}},
		registry:      &fakeRegistry{},
		hasher:        &fakeHasher{},
		mailer:        &fakeMailer{},
		verifications: &fakeVerifications{},
	}
	w.service = &createaccount.Service{Tenants: w.tenants, Accounts: w.accounts, Registry: w.registry, Hasher: w.hasher,
		Clock: func() time.Time { return now }, Verifications: w.verifications, Mailer: w.mailer, Random: fixedRandom()}
	return w
}

func customer() createaccount.Command {
	return createaccount.Command{Kind: createaccount.Customer, TenantID: tenantID, FirstName: "Ana", LastName: "Pérez",
		Email: " Ana@Example.COM ", Phone: "+57 300 123 4567", Password: goodPass, Confirmation: goodPass, IdempotencyKey: idemKey}
}

func internalUser() createaccount.Command {
	return createaccount.Command{Kind: createaccount.InternalUser, TenantID: tenantID, FullName: "Luis Gómez",
		Email: "luis@example.com", Password: goodPass, Role: "OPERATIONAL_COLLABORATOR", Actor: actorAdmin, IdempotencyKey: idemKey}
}

func firstAdministrator() createaccount.Command {
	return createaccount.Command{Kind: createaccount.FirstAdministrator, TenantID: tenantID, FullName: "Marta Ruiz",
		Email: "marta@example.com", Password: goodPass, Actor: serviceSub, IdempotencyKey: "saga-1:create-admin"}
}
