package verifyemail_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/verification"
	"github.com/code-corhuila/multi-tour-security/internal/core/verifyemail"
)

const (
	tenantID = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	otherID  = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	password = "Correct-Horse-9"
)

var (
	now   = time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	ctx   = context.Background()
	token = strings.Repeat("a", 43)
)

type fakeTenants struct{ copies map[string]tenant.Copy }

func (f *fakeTenants) Apply(context.Context, tenant.Copy) (bool, error) { return false, nil }
func (f *fakeTenants) FindByIdentifier(_ context.Context, identifier string) (tenant.Copy, bool, error) {
	c, ok := f.copies[identifier]
	return c, ok, nil
}
func (f *fakeTenants) FindByID(context.Context, string) (tenant.Copy, bool, error) {
	return tenant.Copy{}, false, nil
}

type fakeAccounts struct {
	port.Accounts
	byID      map[string]account.Account
	failures  []string
	successes []string
	correl    []string
}

func (f *fakeAccounts) FindByID(_ context.Context, id string) (account.Account, bool, error) {
	a, ok := f.byID[id]
	return a, ok, nil
}
func (f *fakeAccounts) RecordFailure(_ context.Context, id string, _ time.Time, correlationID string) (account.Account, bool, error) {
	f.failures, f.correl = append(f.failures, id), append(f.correl, correlationID)
	return account.Account{}, false, nil
}
func (f *fakeAccounts) RecordSuccess(_ context.Context, id string) error {
	f.successes = append(f.successes, id)
	return nil
}

type fakeVerifications struct {
	port.Verifications
	links     map[string]port.LinkState
	confirmed []string
	correl    []string
	// raceLost makes Confirm answer that another request used the link first
	raceLost bool
}

func (f *fakeVerifications) Find(_ context.Context, hash string) (port.LinkState, bool, error) {
	l, ok := f.links[hash]
	return l, ok, nil
}
func (f *fakeVerifications) Confirm(_ context.Context, hash string, _ time.Time, correlationID string) (bool, error) {
	f.confirmed, f.correl = append(f.confirmed, hash), append(f.correl, correlationID)
	return !f.raceLost, nil
}

type fakeHasher struct{}

func (fakeHasher) Hash(p string) (string, error) { return "hash:" + p, nil }
func (fakeHasher) Compare(hash, p string) bool   { return hash == "hash:"+p }

type world struct {
	tenants  *fakeTenants
	accounts *fakeAccounts
	links    *fakeVerifications
	service  *verifyemail.Service
}

func newWorld() *world {
	w := &world{
		tenants: &fakeTenants{copies: map[string]tenant.Copy{
			"travesia": {TenantID: tenantID, Identifier: "travesia", Status: tenant.Active},
			"parked":   {TenantID: otherID, Identifier: "parked", Status: tenant.Inactive},
		}},
		accounts: &fakeAccounts{byID: map[string]account.Account{
			"acc-1": {ID: "acc-1", TenantID: tenantID, EmailNormalized: "ana@example.com", PasswordHash: "hash:" + password, Status: account.Pending},
		}},
		links: &fakeVerifications{links: map[string]port.LinkState{
			verification.Hash(token): {AccountID: "acc-1", TenantID: tenantID, ExpiresAt: now.Add(time.Hour)},
		}},
	}
	w.service = &verifyemail.Service{Tenants: w.tenants, Accounts: w.accounts, Verifications: w.links, Hasher: fakeHasher{},
		Clock: func() time.Time { return now }}
	return w
}

func request(identifier, tok, pass string) verifyemail.Request {
	return verifyemail.Request{TenantIdentifier: identifier, Token: tok, Password: pass, CorrelationID: "corr-1"}
}

func nothingChanged(t *testing.T, w *world) {
	t.Helper()
	if len(w.links.confirmed) != 0 || len(w.accounts.failures) != 0 || len(w.accounts.successes) != 0 {
		t.Fatalf("a refusal must change nothing: confirmed=%v failures=%v successes=%v", w.links.confirmed, w.accounts.failures, w.accounts.successes)
	}
}

func TestA_AValidLinkAndThePasswordActivateTheAccount(t *testing.T) {
	w := newWorld()
	if err := w.service.Confirm(ctx, request("travesia", token, password)); err != nil {
		t.Fatal(err)
	}
	if len(w.links.confirmed) != 1 || w.links.confirmed[0] != verification.Hash(token) || w.links.correl[0] != "corr-1" {
		t.Fatalf("the store must get the hash of the link and the correlation id: %v %v", w.links.confirmed, w.links.correl)
	}
	if len(w.accounts.successes) != 1 || w.accounts.successes[0] != "acc-1" || len(w.accounts.failures) != 0 {
		t.Fatalf("a success clears the failures: %v %v", w.accounts.successes, w.accounts.failures)
	}
}

func TestA_AValidLinkWithAWrongPasswordChangesNothingAndCountsAFailure(t *testing.T) {
	w := newWorld()
	err := w.service.Confirm(ctx, request("travesia", token, "not the password"))
	if !errors.Is(err, verifyemail.ErrWrongPassword) {
		t.Fatalf("err = %v", err)
	}
	if len(w.links.confirmed) != 0 || len(w.accounts.successes) != 0 {
		t.Fatal("the account must stay pending and the link must stay valid")
	}
	if len(w.accounts.failures) != 1 || w.accounts.failures[0] != "acc-1" || w.accounts.correl[0] != "corr-1" {
		t.Fatalf("the failure must be counted toward the block: %v", w.accounts.failures)
	}
}

func TestA_ABlockedAccountGetsTheSameRefusalAsAWrongPasswordAndCountsNothing(t *testing.T) {
	w := newWorld()
	blocked := w.accounts.byID["acc-1"]
	blocked.BlockedUntil = now.Add(time.Minute)
	w.accounts.byID["acc-1"] = blocked
	if err := w.service.Confirm(ctx, request("travesia", token, password)); !errors.Is(err, verifyemail.ErrWrongPassword) {
		t.Fatalf("err = %v", err)
	}
	nothingChanged(t, w)
}

func TestA_ABadLinkChangesNothing(t *testing.T) {
	cases := map[string]func(*world){
		"unknown": func(w *world) { delete(w.links.links, verification.Hash(token)) },
		"used": func(w *world) {
			l := w.links.links[verification.Hash(token)]
			l.UsedAt = now.Add(-time.Minute)
			w.links.links[verification.Hash(token)] = l
		},
		"replaced": func(w *world) {
			l := w.links.links[verification.Hash(token)]
			l.ReplacedAt = now.Add(-time.Minute)
			w.links.links[verification.Hash(token)] = l
		},
		"expired": func(w *world) {
			l := w.links.links[verification.Hash(token)]
			l.ExpiresAt = now.Add(-time.Second)
			w.links.links[verification.Hash(token)] = l
		},
		"expiring exactly now": func(w *world) {
			l := w.links.links[verification.Hash(token)]
			l.ExpiresAt = now
			w.links.links[verification.Hash(token)] = l
		},
		"of an account of another tenant": func(w *world) {
			l := w.links.links[verification.Hash(token)]
			l.TenantID = otherID
			w.links.links[verification.Hash(token)] = l
		},
		"of an account that does not exist": func(w *world) { delete(w.accounts.byID, "acc-1") },
		"of an account already verified": func(w *world) {
			a := w.accounts.byID["acc-1"]
			a.Status = account.Active
			w.accounts.byID["acc-1"] = a
		},
		"of an inactive account": func(w *world) {
			a := w.accounts.byID["acc-1"]
			a.Status = account.Inactive
			w.accounts.byID["acc-1"] = a
		},
		"lost to a concurrent confirmation": func(w *world) { w.links.raceLost = true },
	}
	for name, edit := range cases {
		w := newWorld()
		edit(w)
		err := w.service.Confirm(ctx, request("travesia", token, password))
		if !errors.Is(err, verifyemail.ErrBadLink) {
			t.Fatalf("%s: err = %v, want the one answer of a bad link", name, err)
		}
		if name != "lost to a concurrent confirmation" {
			nothingChanged(t, w)
		}
		if len(w.accounts.successes) != 0 {
			t.Fatalf("%s: a bad link must not clear anything", name)
		}
	}
}

func TestA_ALinkOfAnInactiveTenantIsABadLink(t *testing.T) {
	w := newWorld()
	l := w.links.links[verification.Hash(token)]
	l.TenantID = otherID
	w.links.links[verification.Hash(token)] = l
	a := w.accounts.byID["acc-1"]
	a.TenantID = otherID
	w.accounts.byID["acc-1"] = a
	if err := w.service.Confirm(ctx, request("parked", token, password)); !errors.Is(err, verifyemail.ErrBadLink) {
		t.Fatalf("err = %v", err)
	}
	nothingChanged(t, w)
}

func TestA_AnUnknownTenantIsNotFound(t *testing.T) {
	w := newWorld()
	if err := w.service.Confirm(ctx, request("nowhere", token, password)); !errors.Is(err, verifyemail.ErrTenantNotFound) {
		t.Fatalf("err = %v", err)
	}
	nothingChanged(t, w)
}

func TestA_AValueThatCannotBeALinkOrAPasswordIsRefusedBeforeAnyLookup(t *testing.T) {
	for name, r := range map[string]verifyemail.Request{
		"short link":     request("travesia", "short", password),
		"link with =":    request("travesia", strings.Repeat("a", 42)+"=", password),
		"empty password": request("travesia", token, ""),
		"long password":  request("travesia", token, strings.Repeat("p", 129)),
	} {
		w := newWorld()
		if err := w.service.Confirm(ctx, r); !errors.Is(err, verifyemail.ErrInvalidRequest) {
			t.Fatalf("%s: err = %v", name, err)
		}
		nothingChanged(t, w)
	}
}

func TestA_AMissingPieceStopsTheUseCase(t *testing.T) {
	for _, drop := range []func(*verifyemail.Service){
		func(s *verifyemail.Service) { s.Tenants = nil },
		func(s *verifyemail.Service) { s.Accounts = nil },
		func(s *verifyemail.Service) { s.Verifications = nil },
		func(s *verifyemail.Service) { s.Hasher = nil },
		func(s *verifyemail.Service) { s.Clock = nil },
	} {
		w := newWorld()
		drop(w.service)
		err := w.service.Confirm(ctx, request("travesia", token, password))
		if err == nil || errors.Is(err, verifyemail.ErrBadLink) || errors.Is(err, verifyemail.ErrWrongPassword) {
			t.Fatalf("err = %v, want a wiring error", err)
		}
	}
}
