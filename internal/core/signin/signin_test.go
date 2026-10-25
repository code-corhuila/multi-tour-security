package signin_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/session"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

type world struct {
	tenants  *fakeTenants
	accounts *fakeAccounts
	sessions *fakeSessions
	hasher   *fakeHasher
	signer   *fakeSigner
	service  *signin.Service
}

func newWorld() *world {
	w := &world{
		tenants: &fakeTenants{copies: map[string]tenant.Copy{
			"travesia-natural": {TenantID: tenantID, Identifier: "travesia-natural", Status: tenant.Active, OccurredAt: now},
			"parked":           {TenantID: otherID, Identifier: "parked", Status: tenant.Inactive, OccurredAt: now},
			"starting":         {TenantID: "11111111-1111-4111-8111-111111111111", Identifier: "starting", Status: tenant.Pending, OccurredAt: now},
			"broken":           {TenantID: "22222222-2222-4222-8222-222222222222", Identifier: "broken", Status: tenant.Failed, OccurredAt: now},
		}},
		accounts: &fakeAccounts{byKey: map[string]account.Account{}, roles: map[string][]string{}},
		sessions: &fakeSessions{},
		hasher:   &fakeHasher{},
		signer:   &fakeSigner{},
	}
	w.service = &signin.Service{Tenants: w.tenants, Accounts: w.accounts, Sessions: w.sessions, Hasher: w.hasher,
		Signer: w.signer, DummyHash: dummyHash, Clock: func() time.Time { return now }}
	return w
}

// add registers an account of a tenant (empty for the platform) whose password is the constant password.
func (w *world) add(id, tenantID, email string, roles []string, edit func(*account.Account)) {
	a := account.Account{ID: id, TenantID: tenantID, EmailNormalized: email, PasswordHash: "hash:" + password, Status: account.Active}
	if edit != nil {
		edit(&a)
	}
	w.accounts.byKey[tenantID+"|"+email] = a
	w.accounts.roles[id] = roles
}

func request(identifier, email, pass string) signin.Request {
	return signin.Request{TenantIdentifier: identifier, Email: email, Password: pass, CorrelationID: "corr-1"}
}

var ctx = context.Background()

const (
	pendingID = "11111111-1111-4111-8111-111111111111"
	failedID  = "22222222-2222-4222-8222-222222222222"
	own       = "hash:" + password
)

func TestC_SignInReturnsATokenOfTheTenantOfTheLinkWithTheClaimsOfTheSpec(t *testing.T) {
	w := newWorld()
	w.add("acc-1", tenantID, "ana@example.com", []string{"TENANT_ADMINISTRATOR"}, nil)
	got, err := w.service.SignIn(ctx, request("travesia-natural", " Ana@Example.COM ", password))
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "signed.access.token" || got.RefreshToken == "" || got.ExpiresIn != 15*time.Minute {
		t.Fatalf("tokens = %+v", got)
	}
	c := w.signer.claims[0]
	if c.Subject != "acc-1" || c.TenantID != tenantID || !reflect.DeepEqual(c.Roles, []string{"TENANT_ADMINISTRATOR"}) || c.Access != "" {
		t.Fatalf("the claims must be the account's, in the tenant of the link: %+v", c)
	}
	if c.Issuer != token.Issuer || c.Audience != token.Audience || !c.IssuedAt.Equal(now) || !c.NotBefore.Equal(now) ||
		!c.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("iss, aud, iat, nbf and exp of the spec: %+v", c)
	}
	// the special permissions have no store yet (HU-SEC-005): the claim is an empty list, never missing
	if c.Permissions == nil || len(c.Permissions) != 0 {
		t.Fatalf("permissions must be an empty list for now: %#v", c.Permissions)
	}
	if len(w.sessions.opened) != 1 || w.sessions.opened[0] != session.Hash(got.RefreshToken) || w.sessions.owners[0] != "acc-1" ||
		!w.sessions.at[0].Equal(now) {
		t.Fatalf("the session keeps only the hash of the renewal value returned, from now (the store gives it 7 days): %+v", w.sessions)
	}
	if !reflect.DeepEqual(w.accounts.successes, []string{"acc-1"}) || len(w.accounts.failures) != 0 {
		t.Fatalf("a success clears the failures and records none: %+v", w.accounts)
	}
}

// refusal is one way to be refused; wantHash is what the use case must have compared the password with, and
// wantFailures how many failures it must have counted: a failure only for an account that exists and a wrong password.
type refusal struct {
	name         string
	build        func(w *world) signin.Request
	wantHash     string
	wantFailures int
}

func refusals() []refusal {
	ana := "ana@example.com"
	return []refusal{
		{"wrong password", func(w *world) signin.Request {
			w.add("a", tenantID, ana, []string{"ANALYST"}, nil)
			return request("travesia-natural", ana, "wrong")
		}, own, 1},
		{"unknown e-mail", func(w *world) signin.Request { return request("travesia-natural", "nobody@example.com", password) }, dummyHash, 0},
		{"account of another tenant", func(w *world) signin.Request {
			w.add("a", otherID, ana, []string{"ANALYST"}, nil)
			return request("travesia-natural", ana, password)
		}, dummyHash, 0},
		{"unknown tenant", func(w *world) signin.Request { return request("nowhere", ana, password) }, dummyHash, 0},
		{"empty identifier", func(w *world) signin.Request { return request("", ana, password) }, dummyHash, 0},
		{"identifier that is not one", func(w *world) signin.Request { return request("BAD ID/..", ana, password) }, dummyHash, 0},
		{"pending tenant", func(w *world) signin.Request {
			w.add("a", pendingID, ana, []string{"TENANT_ADMINISTRATOR"}, nil)
			return request("starting", ana, password)
		}, dummyHash, 0},
		{"failed tenant", func(w *world) signin.Request {
			w.add("a", failedID, ana, []string{"TENANT_ADMINISTRATOR"}, nil)
			return request("broken", ana, password)
		}, dummyHash, 0},
		{"blocked account, right password", func(w *world) signin.Request {
			w.add("a", tenantID, ana, []string{"ANALYST"}, func(a *account.Account) { a.BlockedUntil = now.Add(time.Second) })
			return request("travesia-natural", ana, password)
		}, own, 0},
		{"blocked account, wrong password", func(w *world) signin.Request {
			w.add("a", tenantID, ana, []string{"ANALYST"}, func(a *account.Account) { a.BlockedUntil = now.Add(time.Second) })
			return request("travesia-natural", ana, "wrong")
		}, own, 1},
		{"inactive account", func(w *world) signin.Request {
			w.add("a", tenantID, ana, []string{"ANALYST"}, func(a *account.Account) { a.Status = account.Inactive })
			return request("travesia-natural", ana, password)
		}, own, 0},
		{"temporary credential expired exactly now", func(w *world) signin.Request {
			w.add("a", tenantID, ana, []string{"ANALYST"}, func(a *account.Account) { a.TemporaryUntil = now })
			return request("travesia-natural", ana, password)
		}, own, 0},
		{"user of an inactive tenant that has another role", func(w *world) signin.Request {
			w.add("a", otherID, ana, []string{"OPERATIONAL_COLLABORATOR"}, nil)
			return request("parked", ana, password)
		}, own, 0},
		{"user of an inactive tenant with no role", func(w *world) signin.Request {
			w.add("a", otherID, ana, nil, nil)
			return request("parked", ana, password)
		}, own, 0},
		{"administrator of an inactive tenant, wrong password", func(w *world) signin.Request {
			w.add("a", otherID, ana, []string{"TENANT_ADMINISTRATOR"}, nil)
			return request("parked", ana, "wrong")
		}, own, 1},
		{"platform account through the route of a tenant", func(w *world) signin.Request {
			w.add("root", "", ana, []string{"PLATFORM_ADMINISTRATOR"}, nil)
			return request("travesia-natural", ana, password)
		}, dummyHash, 0},
	}
}

func TestC_EveryRefusalOfSignInIsTheSameErrorAndCostsOneComparisonAgainstTheRightHash(t *testing.T) {
	for _, c := range refusals() {
		w := newWorld()
		got, err := w.service.SignIn(ctx, c.build(w))
		if err != signin.ErrRefused || got != (signin.Tokens{}) || err.Error() != "the credentials were not accepted" {
			t.Errorf("%s: err = %v, tokens = %+v", c.name, err, got)
			continue
		}
		if !reflect.DeepEqual(w.hasher.compared, []string{c.wantHash}) {
			t.Errorf("%s: compared %v, want exactly one comparison with %q", c.name, w.hasher.compared, c.wantHash)
		}
		if len(w.accounts.failures) != c.wantFailures {
			t.Errorf("%s: %d failures counted, want %d", c.name, len(w.accounts.failures), c.wantFailures)
		}
		if len(w.accounts.successes) != 0 || len(w.signer.claims) != 0 || len(w.sessions.opened) != 0 {
			t.Errorf("%s: a refusal cleared a count or issued something", c.name)
		}
	}
}

func TestC_TheFifthFailureIsAnsweredLikeAnyOtherWrongPassword(t *testing.T) {
	w := newWorld()
	w.add("a", tenantID, "ana@example.com", []string{"ANALYST"}, nil)
	w.accounts.blockOnFailure = true
	got, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", "wrong"))
	if err != signin.ErrRefused || got != (signin.Tokens{}) || !reflect.DeepEqual(w.hasher.compared, []string{own}) {
		t.Fatalf("the block must not show: %v %+v %v", err, got, w.hasher.compared)
	}
}

func TestC_TheEdgesOfTheBlockAndOfTheTemporaryCredentialAreThoseOfTheAccount(t *testing.T) {
	w := newWorld()
	w.add("a", tenantID, "ana@example.com", []string{"ANALYST"}, func(a *account.Account) { a.BlockedUntil = now })
	if _, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); err != nil {
		t.Fatalf("a block that ends exactly now lets the person in: %v", err)
	}
	w = newWorld()
	w.add("a", tenantID, "ana@example.com", []string{"ANALYST"}, func(a *account.Account) { a.TemporaryUntil = now.Add(time.Second) })
	if got, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); err != nil || got.RefreshToken != "" {
		t.Fatalf("a temporary credential one second before its end still works, for a new password only: %v %+v", err, got)
	}
}

func TestA_AnUnknownAccountIsComparedAgainstTheFixedDummyHashAndNeverTheHashOfAnother(t *testing.T) {
	w := newWorld()
	w.add("other", otherID, "ana@example.com", nil, nil)
	_, _ = w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password))
	_, _ = w.service.SignIn(ctx, request("nowhere", "ana@example.com", password))
	if !reflect.DeepEqual(w.hasher.compared, []string{dummyHash, dummyHash}) {
		t.Fatalf("compared = %v", w.hasher.compared)
	}
}

func TestC_AWrongPasswordIsCountedWithTheCorrelationIdAndARightOneIsNot(t *testing.T) {
	w := newWorld()
	w.add("acc-1", tenantID, "ana@example.com", []string{"ANALYST"}, nil)
	_, _ = w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", "wrong"))
	if !reflect.DeepEqual(w.accounts.failures, []string{"acc-1"}) || !reflect.DeepEqual(w.accounts.correl, []string{"corr-1"}) {
		t.Fatalf("a wrong password counts one failure of the account: %+v", w.accounts)
	}
	if _, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); err != nil || len(w.accounts.failures) != 1 {
		t.Fatalf("a right password counts no failure: %v %+v", err, w.accounts)
	}
}

func TestC_FirstSignInWithATemporaryCredentialOnlyAllowsANewPassword(t *testing.T) {
	w := newWorld()
	w.add("acc-1", tenantID, "ana@example.com", []string{"TENANT_ADMINISTRATOR"}, func(a *account.Account) { a.TemporaryUntil = now.Add(time.Hour) })
	got, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password))
	if err != nil {
		t.Fatal(err)
	}
	c := w.signer.claims[0]
	if len(c.Roles) != 0 || c.Access != token.PasswordChangeAccess || c.TenantID != tenantID || !c.ExpiresAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("the token of a temporary credential has no role and serves one route for 10 minutes: %+v", c)
	}
	if got.RefreshToken != "" || len(w.sessions.opened) != 0 || got.ExpiresIn != 10*time.Minute {
		t.Fatalf("a temporary credential gets no renewal value and opens no session: %+v", got)
	}
	if !reflect.DeepEqual(w.accounts.successes, []string{"acc-1"}) {
		t.Fatal("a right password clears the failures even when it only allows choosing another")
	}
}

func TestA_AnInactiveTenantGivesItsAdministratorARestrictedTokenAndNothingElse(t *testing.T) {
	w := newWorld()
	w.add("acc-1", otherID, "boss@example.com", []string{"TENANT_ADMINISTRATOR", "MANAGER"}, nil)
	got, err := w.service.SignIn(ctx, request("parked", "boss@example.com", password))
	if err != nil {
		t.Fatal(err)
	}
	c := w.signer.claims[0]
	if c.Access != token.RestrictedAccess || c.TenantID != otherID || !reflect.DeepEqual(c.Roles, []string{"TENANT_ADMINISTRATOR", "MANAGER"}) ||
		!c.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("the Administrator of an inactive tenant gets a restricted token: %+v", c)
	}
	if got.RefreshToken != "" || len(w.sessions.opened) != 0 || got.ExpiresIn != 15*time.Minute {
		t.Fatalf("a restricted access is not renewed: %+v", got)
	}
	if !reflect.DeepEqual(w.accounts.successes, []string{"acc-1"}) {
		t.Fatal("the success is recorded")
	}
}

func TestA_ATemporaryCredentialOfTheAdministratorOfAnInactiveTenantGetsThePasswordChangeTokenAndNoRole(t *testing.T) {
	w := newWorld()
	w.add("acc-1", otherID, "boss@example.com", []string{"TENANT_ADMINISTRATOR"}, func(a *account.Account) { a.TemporaryUntil = now.Add(time.Hour) })
	if _, err := w.service.SignIn(ctx, request("parked", "boss@example.com", password)); err != nil {
		t.Fatal(err)
	}
	if c := w.signer.claims[0]; c.Access != token.PasswordChangeAccess || len(c.Roles) != 0 {
		t.Fatalf("choosing a password wins over the restriction, and it carries no role: %+v", c)
	}
}

func TestC_ThePlatformAdministratorSignsInWithoutATenantAndNeverConsultsOne(t *testing.T) {
	w := newWorld()
	w.add("root", "", "root@example.com", []string{"PLATFORM_ADMINISTRATOR"}, nil)
	w.add("ana", tenantID, "root@example.com", []string{"ANALYST"}, nil)
	got, err := w.service.SignInPlatform(ctx, request("travesia-natural", "root@example.com", password))
	if err != nil {
		t.Fatal(err)
	}
	if c := w.signer.claims[0]; c.Subject != "root" || c.TenantID != "" || !reflect.DeepEqual(c.Roles, []string{"PLATFORM_ADMINISTRATOR"}) || c.Access != "" {
		t.Fatalf("the platform token has no tenant, whatever the request says: %+v", c)
	}
	if got.RefreshToken == "" || len(w.sessions.opened) != 1 || got.ExpiresIn != 15*time.Minute {
		t.Fatalf("the platform administrator has a session: %+v", got)
	}
	if w.tenants.calls != 0 || !reflect.DeepEqual(w.accounts.lookups, []string{""}) || !reflect.DeepEqual(w.accounts.successes, []string{"root"}) {
		t.Fatalf("the platform looks for an account with no tenant and asks no tenant: calls %d lookups %v", w.tenants.calls, w.accounts.lookups)
	}
}

func TestC_ThePlatformRefusesLikeATenantDoes(t *testing.T) {
	root := "root@example.com"
	cases := []refusal{
		{"unknown e-mail", func(w *world) signin.Request { return request("", "nobody@example.com", password) }, dummyHash, 0},
		{"account of a tenant", func(w *world) signin.Request {
			w.add("ana", tenantID, root, []string{"TENANT_ADMINISTRATOR"}, nil)
			return request("travesia-natural", root, password)
		}, dummyHash, 0},
		{"wrong password", func(w *world) signin.Request {
			w.add("root", "", root, []string{"PLATFORM_ADMINISTRATOR"}, nil)
			return request("", root, "wrong")
		}, own, 1},
		{"blocked", func(w *world) signin.Request {
			w.add("root", "", root, []string{"PLATFORM_ADMINISTRATOR"}, func(a *account.Account) { a.BlockedUntil = now.Add(time.Minute) })
			return request("", root, password)
		}, own, 0},
		{"inactive", func(w *world) signin.Request {
			w.add("root", "", root, []string{"PLATFORM_ADMINISTRATOR"}, func(a *account.Account) { a.Status = account.Inactive })
			return request("", root, password)
		}, own, 0},
		{"account with no tenant and no platform role", func(w *world) signin.Request {
			w.add("odd", "", root, []string{"ANALYST"}, nil)
			return request("", root, password)
		}, own, 0},
	}
	for _, c := range cases {
		w := newWorld()
		got, err := w.service.SignInPlatform(ctx, c.build(w))
		if err != signin.ErrRefused || got != (signin.Tokens{}) {
			t.Errorf("%s: err = %v, tokens = %+v", c.name, err, got)
			continue
		}
		if !reflect.DeepEqual(w.hasher.compared, []string{c.wantHash}) || len(w.accounts.failures) != c.wantFailures || w.tenants.calls != 0 {
			t.Errorf("%s: compared %v, failures %d, tenant calls %d", c.name, w.hasher.compared, len(w.accounts.failures), w.tenants.calls)
		}
	}
}

func TestC_ARequestThatIsNotAnEmailAndAPasswordIsInvalidAndTouchesNothing(t *testing.T) {
	bad := []struct {
		name string
		req  signin.Request
	}{
		{"empty e-mail", request("travesia-natural", "", password)},
		{"two characters", request("travesia-natural", "a@", password)},
		{"no at sign", request("travesia-natural", "ana.example.com", password)},
		{"at sign first", request("travesia-natural", "@example.com", password)},
		{"at sign last", request("travesia-natural", "ana@", password)},
		{"space inside", request("travesia-natural", "an a@example.com", password)},
		{"255 characters", request("travesia-natural", strings.Repeat("a", 250)+"@b.co", password)},
		{"not ASCII", request("travesia-natural", "añá@example.com", password)},
		{"control character", request("travesia-natural", "ana\n@example.com", password)},
		{"empty password", request("travesia-natural", "ana@example.com", "")},
		{"129 characters of password", request("travesia-natural", "ana@example.com", strings.Repeat("p", 129))},
	}
	for _, c := range bad {
		w := newWorld()
		if _, err := w.service.SignIn(ctx, c.req); !errors.Is(err, signin.ErrInvalidRequest) {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if len(w.hasher.compared) != 0 || len(w.accounts.failures) != 0 || len(w.accounts.lookups) != 0 || w.tenants.calls != 0 {
			t.Errorf("%s: an invalid request reached the hasher or a store", c.name)
		}
	}
	for name, pass := range map[string]string{"128 characters": strings.Repeat("p", 128), "multibyte over 72 bytes": strings.Repeat("ñ", 100)} {
		w := newWorld()
		w.add("a", tenantID, "ana@example.com", nil, nil)
		if _, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", pass)); err != signin.ErrRefused {
			t.Errorf("%s is a valid password that does not match: %v", name, err)
		}
	}
}

func TestC_AFailureOfAStoreOrOfTheSignerIsAnErrorThatIsNotARefusalAndIssuesNothing(t *testing.T) {
	boom := errors.New("connection reset")
	cases := []struct {
		name   string
		break_ func(w *world)
		pass   string
	}{
		{"find the account", func(w *world) { w.accounts.findErr = boom }, password},
		{"find the tenant", func(w *world) { w.tenants.err = boom }, password},
		{"record the failure", func(w *world) { w.accounts.failureErr = boom }, "wrong"},
		{"record the success", func(w *world) { w.accounts.successErr = boom }, password},
		{"read the roles", func(w *world) { w.accounts.rolesErr = boom }, password},
		{"open the session", func(w *world) { w.sessions.err = boom }, password},
		{"sign the token", func(w *world) { w.signer.err = boom }, password},
	}
	for _, c := range cases {
		w := newWorld()
		w.add("acc-1", tenantID, "ana@example.com", []string{"ANALYST"}, nil)
		c.break_(w)
		got, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", c.pass))
		if err == nil || errors.Is(err, signin.ErrRefused) || got != (signin.Tokens{}) {
			t.Errorf("%s: err = %v, tokens = %+v", c.name, err, got)
		}
		if c.name == "sign the token" && len(w.sessions.opened) != 0 {
			t.Errorf("a token that cannot be signed opens no session")
		}
	}
}

func TestC_AServiceWithoutOnePieceRefusesToWorkInsteadOfAnsweringWithoutIt(t *testing.T) {
	pieces := map[string]func(s *signin.Service){
		"dummy hash": func(s *signin.Service) { s.DummyHash = "" },
		"hasher":     func(s *signin.Service) { s.Hasher = nil },
		"tenants":    func(s *signin.Service) { s.Tenants = nil },
		"accounts":   func(s *signin.Service) { s.Accounts = nil },
		"sessions":   func(s *signin.Service) { s.Sessions = nil },
		"signer":     func(s *signin.Service) { s.Signer = nil },
		"clock":      func(s *signin.Service) { s.Clock = nil },
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
			if _, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password)); err == nil || errors.Is(err, signin.ErrRefused) {
				t.Errorf("without the %s the service answered: %v", name, err)
			}
			if _, err := w.service.SignInPlatform(ctx, request("", "ana@example.com", password)); err == nil || errors.Is(err, signin.ErrRefused) {
				t.Errorf("without the %s the platform answered: %v", name, err)
			}
		}()
	}
}

func TestA_APendingAccountWithItsPasswordIsToldToVerify(t *testing.T) {
	w := newWorld()
	w.add("acc-1", tenantID, "ana@example.com", []string{"FINAL_CUSTOMER"}, func(a *account.Account) { a.Status = account.Pending })
	_, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password))
	if !errors.Is(err, signin.ErrEmailNotVerified) {
		t.Fatalf("err = %v, want the refusal that asks to verify the e-mail", err)
	}
	if len(w.signer.claims) != 0 || len(w.sessions.opened) != 0 || len(w.accounts.successes) != 0 || len(w.accounts.failures) != 0 {
		t.Fatal("a pending account gets no token, no session, no success and no failure")
	}
}

func TestA_APendingAccountWithAWrongPasswordGetsTheGenericRefusalAndAFailure(t *testing.T) {
	w := newWorld()
	w.add("acc-1", tenantID, "ana@example.com", []string{"FINAL_CUSTOMER"}, func(a *account.Account) { a.Status = account.Pending })
	_, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", "not the password"))
	if !errors.Is(err, signin.ErrRefused) || errors.Is(err, signin.ErrEmailNotVerified) {
		t.Fatalf("err = %v, want the generic refusal", err)
	}
	if len(w.accounts.failures) != 1 {
		t.Fatalf("the wrong password must count as a failure: %v", w.accounts.failures)
	}
}

func TestA_APendingAccountOfAnInactiveTenantIsRefusedGenerically(t *testing.T) {
	w := newWorld()
	w.add("acc-1", otherID, "ana@example.com", []string{"FINAL_CUSTOMER"}, func(a *account.Account) { a.Status = account.Pending })
	_, err := w.service.SignIn(ctx, request("parked", "ana@example.com", password))
	if !errors.Is(err, signin.ErrRefused) || errors.Is(err, signin.ErrEmailNotVerified) {
		t.Fatalf("err = %v, want the generic refusal: an inactive tenant says nothing about its accounts", err)
	}
}

func TestA_APendingAccountThatIsBlockedGetsTheGenericRefusal(t *testing.T) {
	w := newWorld()
	w.add("acc-1", tenantID, "ana@example.com", []string{"FINAL_CUSTOMER"}, func(a *account.Account) {
		a.Status = account.Pending
		a.BlockedUntil = now.Add(time.Minute)
	})
	_, err := w.service.SignIn(ctx, request("travesia-natural", "ana@example.com", password))
	if !errors.Is(err, signin.ErrRefused) || errors.Is(err, signin.ErrEmailNotVerified) {
		t.Fatalf("err = %v, want the generic refusal", err)
	}
}
