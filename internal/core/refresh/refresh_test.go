package refresh_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/refresh"
	"github.com/code-corhuila/multi-tour-security/internal/core/session"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

const (
	tenantID  = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	oldValue  = "old-renewal-value-of-more-than-twenty-characters"
	accountID = "acc-1"
)

var now = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

type fakeSessions struct {
	renewed              port.Renewed
	err                  error
	oldHashes, newHashes []string
}

func (f *fakeSessions) Open(context.Context, string, string, time.Time) (string, error) {
	return "", errors.New("not used")
}
func (f *fakeSessions) Rotate(_ context.Context, oldHash, newHash string, _ time.Time) (port.Renewed, error) {
	f.oldHashes = append(f.oldHashes, oldHash)
	f.newHashes = append(f.newHashes, newHash)
	return f.renewed, f.err
}
func (f *fakeSessions) RevokeAll(context.Context, string, time.Time, string) error { return nil }

type fakeAccounts struct {
	byID     map[string]account.Account
	roles    map[string][]string
	findErr  error
	rolesErr error
}

func (f *fakeAccounts) FindByEmail(context.Context, string, string) (account.Account, bool, error) {
	return account.Account{}, false, nil
}
func (f *fakeAccounts) FindByID(_ context.Context, id string) (account.Account, bool, error) {
	a, ok := f.byID[id]
	return a, ok, f.findErr
}
func (f *fakeAccounts) RecordFailure(context.Context, string, time.Time, string) (account.Account, bool, error) {
	return account.Account{}, false, nil
}
func (f *fakeAccounts) RecordSuccess(context.Context, string) error { return nil }
func (f *fakeAccounts) RolesOf(_ context.Context, id string) ([]string, error) {
	return f.roles[id], f.rolesErr
}

type fakeTenants struct {
	byID map[string]tenant.Copy
	err  error
}

func (f *fakeTenants) Apply(context.Context, tenant.Copy) (bool, error) { return false, nil }
func (f *fakeTenants) FindByIdentifier(context.Context, string) (tenant.Copy, bool, error) {
	return tenant.Copy{}, false, nil
}
func (f *fakeTenants) FindByID(_ context.Context, id string) (tenant.Copy, bool, error) {
	c, ok := f.byID[id]
	return c, ok, f.err
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
	return "new.access.token", nil
}

type world struct {
	sessions *fakeSessions
	accounts *fakeAccounts
	tenants  *fakeTenants
	signer   *fakeSigner
	service  *refresh.Service
}

func newWorld() *world {
	w := &world{
		sessions: &fakeSessions{renewed: port.Renewed{AccountID: accountID, SessionID: "s-1"}},
		accounts: &fakeAccounts{
			byID:  map[string]account.Account{accountID: {ID: accountID, TenantID: tenantID, Status: account.Active}},
			roles: map[string][]string{accountID: {"TENANT_ADMINISTRATOR", "MANAGER"}},
		},
		tenants: &fakeTenants{byID: map[string]tenant.Copy{tenantID: {TenantID: tenantID, Identifier: "travesia-natural", Status: tenant.Active}}},
		signer:  &fakeSigner{},
	}
	w.service = &refresh.Service{Tenants: w.tenants, Accounts: w.accounts, Sessions: w.sessions, Signer: w.signer, Clock: func() time.Time { return now }}
	return w
}

var ctx = context.Background()

func TestA_ARenewalGivesANewPairWithTheRolesOfNowAndTheHashesOfBothValues(t *testing.T) {
	w := newWorld()
	got, err := w.service.Renew(ctx, oldValue)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "new.access.token" || got.RefreshToken == "" || got.RefreshToken == oldValue || got.ExpiresIn != 15*time.Minute {
		t.Fatalf("tokens = %+v", got)
	}
	if !reflect.DeepEqual(w.sessions.oldHashes, []string{session.Hash(oldValue)}) || !reflect.DeepEqual(w.sessions.newHashes, []string{session.Hash(got.RefreshToken)}) {
		t.Fatalf("the store gets the hash of the value used and the hash of the value returned, never a value: %+v", w.sessions)
	}
	c := w.signer.claims[0]
	if c.Subject != accountID || c.TenantID != tenantID || !reflect.DeepEqual(c.Roles, []string{"TENANT_ADMINISTRATOR", "MANAGER"}) ||
		c.Access != "" || !c.IssuedAt.Equal(now) || !c.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("claims = %+v", c)
	}
}

func TestA_TheRolesOfTheNewTokenAreThoseOfNowAndNotThoseOfTheSessionStart(t *testing.T) {
	w := newWorld()
	w.accounts.roles[accountID] = []string{"ANALYST"}
	if _, err := w.service.Renew(ctx, oldValue); err != nil {
		t.Fatal(err)
	}
	if got := w.signer.claims[0].Roles; !reflect.DeepEqual(got, []string{"ANALYST"}) {
		t.Fatalf("roles = %v", got)
	}
}

func TestA_ThePlatformAdministratorRenewsWithoutATenant(t *testing.T) {
	w := newWorld()
	w.accounts.byID["root"] = account.Account{ID: "root", Status: account.Active}
	w.accounts.roles["root"] = []string{"PLATFORM_ADMINISTRATOR"}
	w.sessions.renewed = port.Renewed{AccountID: "root", SessionID: "s-2"}
	if _, err := w.service.Renew(ctx, oldValue); err != nil {
		t.Fatal(err)
	}
	if c := w.signer.claims[0]; c.TenantID != "" || c.Subject != "root" {
		t.Fatalf("claims = %+v", c)
	}
}

func TestA_EveryFailureOfARenewalIsTheSameRefusal(t *testing.T) {
	cases := []struct {
		name string
		edit func(w *world)
	}{
		{"unknown, expired or revoked value", func(w *world) { w.sessions.err = port.ErrRefreshInvalid }},
		{"a value already used", func(w *world) { w.sessions.err = port.ErrRefreshReused }},
		{"account gone", func(w *world) { delete(w.accounts.byID, accountID) }},
		{"account inactive", func(w *world) {
			w.accounts.byID[accountID] = account.Account{ID: accountID, TenantID: tenantID, Status: account.Inactive}
		}},
		{"tenant inactive", func(w *world) {
			w.tenants.byID[tenantID] = tenant.Copy{TenantID: tenantID, Status: tenant.Inactive}
		}},
		{"tenant pending", func(w *world) { w.tenants.byID[tenantID] = tenant.Copy{TenantID: tenantID, Status: tenant.Pending} }},
		{"tenant failed", func(w *world) { w.tenants.byID[tenantID] = tenant.Copy{TenantID: tenantID, Status: tenant.Failed} }},
		{"tenant unknown", func(w *world) { delete(w.tenants.byID, tenantID) }},
		{"account without roles", func(w *world) { w.accounts.roles[accountID] = nil }},
		{"account with no tenant and no platform role", func(w *world) {
			w.accounts.byID[accountID] = account.Account{ID: accountID, Status: account.Active}
		}},
	}
	for _, c := range cases {
		w := newWorld()
		c.edit(w)
		got, err := w.service.Renew(ctx, oldValue)
		if err != signin.ErrRefused || got != (signin.Tokens{}) {
			t.Errorf("%s: %v %+v", c.name, err, got)
		}
		if len(w.signer.claims) != 0 {
			t.Errorf("%s: a refusal signed a token", c.name)
		}
	}
}

func TestA_ARequestThatCannotBeARenewalValueTouchesNothing(t *testing.T) {
	for _, bad := range []string{"", "short", strings.Repeat("v", 19), strings.Repeat("v", 257)} {
		w := newWorld()
		if _, err := w.service.Renew(ctx, bad); !errors.Is(err, signin.ErrInvalidRequest) {
			t.Errorf("%d characters: %v", len(bad), err)
		}
		if len(w.sessions.oldHashes) != 0 {
			t.Errorf("%d characters reached the store", len(bad))
		}
	}
	w := newWorld()
	for _, ok := range []string{strings.Repeat("v", 20), strings.Repeat("v", 256)} {
		if _, err := w.service.Renew(ctx, ok); errors.Is(err, signin.ErrInvalidRequest) {
			t.Errorf("%d characters are allowed", len(ok))
		}
	}
}

func TestA_AFailureOfAStoreOrOfTheSignerIsAnErrorThatIsNotARefusal(t *testing.T) {
	boom := errors.New("connection reset")
	cases := map[string]func(w *world){
		"rotate":       func(w *world) { w.sessions.err = boom },
		"find account": func(w *world) { w.accounts.findErr = boom },
		"read roles":   func(w *world) { w.accounts.rolesErr = boom },
		"find tenant":  func(w *world) { w.tenants.err = boom },
		"sign":         func(w *world) { w.signer.err = boom },
	}
	for name, edit := range cases {
		w := newWorld()
		edit(w)
		got, err := w.service.Renew(ctx, oldValue)
		if err == nil || errors.Is(err, signin.ErrRefused) || got != (signin.Tokens{}) {
			t.Errorf("%s: %v %+v", name, err, got)
		}
	}
}

func TestA_AServiceWithoutOnePieceRefusesToWorkAndNeverPanics(t *testing.T) {
	pieces := map[string]func(s *refresh.Service){
		"tenants":  func(s *refresh.Service) { s.Tenants = nil },
		"accounts": func(s *refresh.Service) { s.Accounts = nil },
		"sessions": func(s *refresh.Service) { s.Sessions = nil },
		"signer":   func(s *refresh.Service) { s.Signer = nil },
		"clock":    func(s *refresh.Service) { s.Clock = nil },
	}
	for name, remove := range pieces {
		w := newWorld()
		remove(w.service)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("without the %s the service panicked: %v", name, r)
				}
			}()
			if _, err := w.service.Renew(ctx, oldValue); err == nil || errors.Is(err, signin.ErrRefused) {
				t.Errorf("without the %s the service answered: %v", name, err)
			}
		}()
	}
}
