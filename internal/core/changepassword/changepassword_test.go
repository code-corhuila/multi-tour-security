package changepassword_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/changepassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/password"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
)

const (
	accountID = "acc-1"
	tenantID  = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	temporary = "Temporary-Pass1!"
	chosen    = "Tr4vesia-Natural"
)

var now = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

type change struct {
	id, hash, correlation string
	at                    time.Time
}

type fakeAccounts struct {
	byID      map[string]account.Account
	changes   []change
	findErr   error
	changeErr error
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
func (f *fakeAccounts) RecordSuccess(context.Context, string) error       { return nil }
func (f *fakeAccounts) RolesOf(context.Context, string) ([]string, error) { return nil, nil }
func (f *fakeAccounts) ChangePassword(_ context.Context, id, hash string, at time.Time, correlation string) error {
	if f.changeErr != nil {
		return f.changeErr
	}
	f.changes = append(f.changes, change{id, hash, correlation, at})
	return nil
}

type fakeHasher struct {
	hashErr error
	hashed  []string
}

func (f *fakeHasher) Compare(hash, pw string) bool { return hash == "hash:"+pw }
func (f *fakeHasher) Hash(pw string) (string, error) {
	if f.hashErr != nil {
		return "", f.hashErr
	}
	f.hashed = append(f.hashed, pw)
	return "hash:" + pw, nil
}

type world struct {
	accounts *fakeAccounts
	hasher   *fakeHasher
	service  *changepassword.Service
}

func newWorld() *world {
	w := &world{
		accounts: &fakeAccounts{byID: map[string]account.Account{accountID: {
			ID: accountID, TenantID: tenantID, Status: account.Active, PasswordHash: "hash:" + temporary, TemporaryUntil: now.Add(time.Hour),
		}}},
		hasher: &fakeHasher{},
	}
	w.service = &changepassword.Service{Accounts: w.accounts, Hasher: w.hasher, Clock: func() time.Time { return now }}
	return w
}

func request(pw string) changepassword.Request {
	return changepassword.Request{AccountID: accountID, TenantID: tenantID, NewPassword: pw, CorrelationID: "corr-1"}
}

var ctx = context.Background()

var _ port.Hasher = (*fakeHasher)(nil)

func TestA_TheFirstPasswordReplacesTheTemporaryOneAndIsStoredOnlyAsAHash(t *testing.T) {
	w := newWorld()
	if err := w.service.Change(ctx, request(chosen)); err != nil {
		t.Fatal(err)
	}
	want := change{accountID, "hash:" + chosen, "corr-1", now}
	if len(w.accounts.changes) != 1 || w.accounts.changes[0] != want {
		t.Fatalf("changes = %+v, want %+v", w.accounts.changes, want)
	}
}

func TestA_APasswordThatBreaksThePolicyOrIsTheTemporaryOneIsAWeakPasswordAndTouchesNothing(t *testing.T) {
	for _, pw := range []string{"sh0rt!A", "no-upper-1!", "Password1!", temporary, ""} {
		w := newWorld()
		err := w.service.Change(ctx, request(pw))
		if !errors.Is(err, changepassword.ErrWeakPassword) {
			t.Errorf("%q: %v", pw, err)
		}
		if len(w.accounts.changes) != 0 || len(w.hasher.hashed) != 0 {
			t.Errorf("%q reached the hasher or the store", pw)
		}
	}
	if !errors.Is(password.Check("sh0rt!A"), password.ErrPolicy) {
		t.Fatal("the policy error is the one the use case translates")
	}
}

func TestA_EveryReasonTheCredentialCannotBeChangedIsTheSameRefusal(t *testing.T) {
	cases := []struct {
		name string
		edit func(w *world)
	}{
		{"account gone", func(w *world) { delete(w.accounts.byID, accountID) }},
		{"account inactive", func(w *world) {
			a := w.accounts.byID[accountID]
			a.Status = account.Inactive
			w.accounts.byID[accountID] = a
		}},
		{"already chose a password", func(w *world) {
			a := w.accounts.byID[accountID]
			a.TemporaryUntil = time.Time{}
			w.accounts.byID[accountID] = a
		}},
		{"temporary credential expired", func(w *world) {
			a := w.accounts.byID[accountID]
			a.TemporaryUntil = now
			w.accounts.byID[accountID] = a
		}},
		{"token of another tenant", func(w *world) {
			a := w.accounts.byID[accountID]
			a.TenantID = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
			w.accounts.byID[accountID] = a
		}},
		{"lost the race to another change", func(w *world) { w.accounts.changeErr = port.ErrNotTemporary }},
	}
	for _, c := range cases {
		w := newWorld()
		c.edit(w)
		if err := w.service.Change(ctx, request(chosen)); err != signin.ErrRefused {
			t.Errorf("%s: %v", c.name, err)
		}
		if len(w.accounts.changes) != 0 {
			t.Errorf("%s: a password was changed", c.name)
		}
	}
}

func TestA_AFailureOfAStoreOrOfTheHasherIsAnErrorThatIsNotARefusal(t *testing.T) {
	boom := errors.New("connection reset")
	cases := map[string]func(w *world){
		"find":   func(w *world) { w.accounts.findErr = boom },
		"change": func(w *world) { w.accounts.changeErr = boom },
		"hash":   func(w *world) { w.hasher.hashErr = boom },
	}
	for name, edit := range cases {
		w := newWorld()
		edit(w)
		err := w.service.Change(ctx, request(chosen))
		if err == nil || errors.Is(err, signin.ErrRefused) || errors.Is(err, changepassword.ErrWeakPassword) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestA_ARequestWithoutTheIdentityOfTheTokenOrAServiceWithoutAPieceNeverPanics(t *testing.T) {
	w := newWorld()
	for _, req := range []changepassword.Request{{NewPassword: chosen, CorrelationID: "c"}, {AccountID: accountID, NewPassword: chosen}} {
		if err := w.service.Change(ctx, req); err == nil || len(w.accounts.changes) != 0 {
			t.Errorf("%+v: %v", req, err)
		}
	}
	for name, remove := range map[string]func(s *changepassword.Service){
		"accounts": func(s *changepassword.Service) { s.Accounts = nil },
		"hasher":   func(s *changepassword.Service) { s.Hasher = nil },
		"clock":    func(s *changepassword.Service) { s.Clock = nil },
	} {
		w := newWorld()
		remove(w.service)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("without the %s the service panicked: %v", name, r)
				}
			}()
			if err := w.service.Change(ctx, request(chosen)); err == nil {
				t.Errorf("without the %s the service answered", name)
			}
		}()
	}
}
