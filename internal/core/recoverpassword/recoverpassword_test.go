package recoverpassword_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/recoverpassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/recovery"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

const (
	tenantID = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	otherID  = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	newPass  = "Viaje-2026!nuevo"
	theCode  = "48213907"
)

var (
	now = time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	ctx = context.Background()
	key = []byte(strings.Repeat("k", 32))
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

// fakeAccounts finds an account by tenant and e-mail, as the store does: the same e-mail in another tenant is another account.
type fakeAccounts struct {
	port.Accounts
	accounts []account.Account
	roles    map[string][]string
}

func (f *fakeAccounts) FindByEmail(_ context.Context, tenantID, email string) (account.Account, bool, error) {
	for _, a := range f.accounts {
		if a.TenantID == tenantID && a.EmailNormalized == email {
			return a, true, nil
		}
	}
	return account.Account{}, false, nil
}
func (f *fakeAccounts) RolesOf(_ context.Context, id string) ([]string, error) {
	return f.roles[id], nil
}

type fakeCodes struct {
	issued   []port.IssueCode
	failures []port.FailedReset
	resets   []port.ResetCommand
	marked   []string
	// full makes Issue answer that the account reached the limit
	full bool
	// live is the code Newest finds; nil is none
	live *port.CodeState
	// raceLost makes Reset answer that another request used the code first
	raceLost bool
}

func (f *fakeCodes) Issue(_ context.Context, c port.IssueCode) (bool, error) {
	f.issued = append(f.issued, c)
	return !f.full, nil
}
func (f *fakeCodes) Newest(context.Context, string, time.Time) (port.CodeState, bool, error) {
	if f.live == nil {
		return port.CodeState{}, false, nil
	}
	return *f.live, true, nil
}
func (f *fakeCodes) RecordFailure(_ context.Context, r port.FailedReset) error {
	f.failures = append(f.failures, r)
	return nil
}
func (f *fakeCodes) Reset(_ context.Context, c port.ResetCommand) (bool, error) {
	f.resets = append(f.resets, c)
	return !f.raceLost, nil
}
func (f *fakeCodes) MarkSendFailed(_ context.Context, accountID, hmac string, _ time.Time, cause string) error {
	f.marked = append(f.marked, accountID+"|"+hmac+"|"+cause)
	return nil
}

type fakeMailer struct {
	sent []port.RecoveryMail
	fail error
}

func (f *fakeMailer) SendRecoveryCode(_ context.Context, m port.RecoveryMail) error {
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, m)
	return nil
}

type fakeHasher struct{}

func (fakeHasher) Hash(p string) (string, error) { return "hash:" + p, nil }
func (fakeHasher) Compare(hash, p string) bool   { return hash == "hash:"+p }

type world struct {
	tenants  *fakeTenants
	accounts *fakeAccounts
	codes    *fakeCodes
	mailer   *fakeMailer
	service  *recoverpassword.Service
}

func randomFor(n uint32) *bytes.Reader {
	return bytes.NewReader(binary.BigEndian.AppendUint32(nil, n))
}

func newWorld() *world {
	w := &world{
		tenants: &fakeTenants{copies: map[string]tenant.Copy{
			"travesia": {TenantID: tenantID, Identifier: "travesia", Status: tenant.Active, CommercialName: "Travesía Natural"},
			"parked":   {TenantID: otherID, Identifier: "parked", Status: tenant.Inactive},
		}},
		accounts: &fakeAccounts{
			accounts: []account.Account{
				{ID: "ana", TenantID: tenantID, EmailNormalized: "ana@example.com", PasswordHash: "hash:Old-pass-1!", Status: account.Active},
				{ID: "pending", TenantID: tenantID, EmailNormalized: "pending@example.com", PasswordHash: "hash:Old-pass-1!", Status: account.Pending},
				{ID: "gone", TenantID: tenantID, EmailNormalized: "gone@example.com", PasswordHash: "hash:Old-pass-1!", Status: account.Inactive},
				{ID: "boss", TenantID: tenantID, EmailNormalized: "boss@example.com", PasswordHash: "hash:Old-pass-1!", Status: account.Active},
				{ID: "elsewhere", TenantID: otherID, EmailNormalized: "ana@example.com", PasswordHash: "hash:Old-pass-1!", Status: account.Active},
				{ID: "root", TenantID: "", EmailNormalized: "root@multitour.example", PasswordHash: "hash:Old-pass-1!", Status: account.Active},
			},
			roles: map[string][]string{"ana": {"FINAL_CUSTOMER"}, "boss": {"TENANT_ADMINISTRATOR"}, "root": {"PLATFORM_ADMINISTRATOR"}},
		},
		codes:  &fakeCodes{},
		mailer: &fakeMailer{},
	}
	w.service = &recoverpassword.Service{Tenants: w.tenants, Accounts: w.accounts, Codes: w.codes, Mailer: w.mailer, Hasher: fakeHasher{},
		Key: key, Random: randomFor(48213907), Clock: func() time.Time { return now }}
	return w
}

// live makes the newest live code of the account the one of theCode, as the store would find it.
func (w *world) liveFor(accountID string) {
	w.codes.live = &port.CodeState{ID: "code-1", HMAC: recovery.HMAC(key, accountID, theCode)}
}

func ask(identifier, email string) recoverpassword.RequestCode {
	return recoverpassword.RequestCode{TenantIdentifier: identifier, Email: email, CorrelationID: "corr-1"}
}

func reset(identifier, email, code, pass, confirm string) recoverpassword.Reset {
	return recoverpassword.Reset{TenantIdentifier: identifier, Email: email, Code: code, NewPassword: pass, Confirmation: confirm, CorrelationID: "corr-1"}
}

func field(t *testing.T, err error) string {
	t.Helper()
	var fe *recoverpassword.FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("want a FieldError, got %v", err)
	}
	return fe.Field
}

// ---- asking for a code (RN-SEC-006-01, -02, -03, -09, -10)

func TestA_ACodeIsSentOnlyToAnAccountOfTheTenantUnderTheLimit(t *testing.T) {
	for _, c := range []struct {
		name       string
		identifier string
		email      string
		full       bool
		sent       bool
	}{
		{"an active account", "travesia", "ana@example.com", false, true},
		{"a pending account", "travesia", "pending@example.com", false, true},
		{"the e-mail is normalized", "travesia", "  ANA@Example.com ", false, true},
		{"an inactive account", "travesia", "gone@example.com", false, false},
		{"an e-mail with no account", "travesia", "nobody@example.com", false, false},
		{"an account of another tenant", "travesia", "root@multitour.example", false, false},
		{"a tenant that is not active", "parked", "ana@example.com", false, false},
		{"an unknown tenant", "nowhere", "ana@example.com", false, false},
		{"an account over the limit of three an hour", "travesia", "ana@example.com", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld()
			w.codes.full = c.full
			if err := w.service.Request(ctx, ask(c.identifier, c.email)); err != nil {
				t.Fatalf("the answer never says anything: %v", err)
			}
			if got := len(w.mailer.sent) == 1; got != c.sent {
				t.Fatalf("sent = %v, want %v", got, c.sent)
			}
			if !c.sent {
				return
			}
			m := w.mailer.sent[0]
			if m.Code != theCode || m.To != strings.ToLower(strings.TrimSpace(c.email)) || m.TenantIdentifier != "travesia" || m.TenantName != "Travesía Natural" {
				t.Fatalf("mail = %+v", m)
			}
		})
	}
}

func TestA_ARequestGoesThroughOneCallThatRetiresTheEarlierCodes(t *testing.T) {
	w := newWorld()
	if err := w.service.Request(ctx, ask("travesia", "ana@example.com")); err != nil {
		t.Fatal(err)
	}
	if len(w.codes.issued) != 1 {
		t.Fatalf("issued %d codes", len(w.codes.issued))
	}
	c := w.codes.issued[0]
	if c.AccountID != "ana" || c.TenantID != tenantID || c.Limit != 3 || c.Window != time.Hour || c.CorrelationID != "corr-1" || !c.Now.Equal(now) {
		t.Fatalf("issue = %+v", c)
	}
	if !c.Code.ExpiresAt.Equal(now.Add(30*time.Minute)) || c.Code.HMAC != recovery.HMAC(key, "ana", theCode) {
		t.Fatalf("code = %+v", c.Code)
	}
}

func TestA_ACodeExpiresAfterThirtyMinutes(t *testing.T) {
	w := newWorld()
	_ = w.service.Request(ctx, ask("travesia", "ana@example.com"))
	if got := w.codes.issued[0].Code.ExpiresAt.Sub(w.codes.issued[0].Code.CreatedAt); got != 30*time.Minute {
		t.Fatalf("a code lasts %v", got)
	}
}

func TestA_ARequestForAnAccountRecordsTheFactAndOneForNoAccountRecordsNothing(t *testing.T) {
	// the fact PasswordRecoveryRequested is written by the store inside Issue (RN-SEC-006-09): it is asked only for an account
	w := newWorld()
	_ = w.service.Request(ctx, ask("travesia", "ana@example.com"))
	_ = w.service.Request(ctx, ask("travesia", "nobody@example.com"))
	_ = w.service.Request(ctx, ask("travesia", "gone@example.com"))
	if len(w.codes.issued) != 1 || w.codes.issued[0].AccountID != "ana" {
		t.Fatalf("issued = %+v", w.codes.issued)
	}
}

func TestA_ThePlatformAdministratorAsksAtThePlatform(t *testing.T) {
	w := newWorld()
	r := ask("", "root@multitour.example")
	r.Platform = true
	if err := w.service.Request(ctx, r); err != nil {
		t.Fatal(err)
	}
	if len(w.mailer.sent) != 1 || w.mailer.sent[0].TenantName != "Multitour" || w.codes.issued[0].TenantID != "" {
		t.Fatalf("sent %+v issued %+v", w.mailer.sent, w.codes.issued)
	}
	// a customer's e-mail does not open the platform, and the platform's does not open a tenant
	w2 := newWorld()
	r2 := ask("", "ana@example.com")
	r2.Platform = true
	_ = w2.service.Request(ctx, r2)
	_ = w2.service.Request(ctx, ask("travesia", "root@multitour.example"))
	if len(w2.mailer.sent) != 0 {
		t.Fatal("an account is found only where it lives")
	}
}

func TestA_AMalformedEmailIsARefusedRequest(t *testing.T) {
	w := newWorld()
	if got := field(t, w.service.Request(ctx, ask("travesia", "not-an-email"))); got != "email" {
		t.Fatalf("field = %q", got)
	}
}

func TestA_AFailedSendIsRecordedAndTheAnswerDoesNotChange(t *testing.T) {
	w := newWorld()
	w.mailer.fail = errors.New("535 rejected " + theCode)
	if err := w.service.Request(ctx, ask("travesia", "ana@example.com")); err != nil {
		t.Fatalf("a failed send changes no answer: %v", err)
	}
	if len(w.codes.marked) != 1 || strings.Contains(w.codes.marked[0], theCode) || !strings.HasPrefix(w.codes.marked[0], "ana|"+recovery.HMAC(key, "ana", theCode)+"|") {
		t.Fatalf("marked = %v", w.codes.marked)
	}
}

func TestA_ARequestWithNoPiecesWiredStopsAtOnce(t *testing.T) {
	s := &recoverpassword.Service{}
	if err := s.Request(ctx, ask("travesia", "ana@example.com")); !errors.Is(err, recoverpassword.ErrNotWired) {
		t.Fatalf("err = %v", err)
	}
	if err := s.Reset(ctx, reset("travesia", "ana@example.com", theCode, newPass, newPass)); !errors.Is(err, recoverpassword.ErrNotWired) {
		t.Fatalf("err = %v", err)
	}
}

// ---- resetting (RN-SEC-006-04 to -08, -11, -12)

func TestA_AValidCodeReplacesThePassword(t *testing.T) {
	w := newWorld()
	w.liveFor("ana")
	if err := w.service.Reset(ctx, reset("travesia", "ana@example.com", theCode, newPass, newPass)); err != nil {
		t.Fatal(err)
	}
	if len(w.codes.resets) != 1 || len(w.codes.failures) != 0 {
		t.Fatalf("resets %v failures %v", w.codes.resets, w.codes.failures)
	}
	r := w.codes.resets[0]
	if r.AccountID != "ana" || r.TenantID != tenantID || r.CodeID != "code-1" || r.NewHash != "hash:"+newPass || r.CorrelationID != "corr-1" ||
		!r.Now.Equal(now) || r.Administrative || r.Pending || len(r.Roles) != 1 || r.Roles[0] != "FINAL_CUSTOMER" {
		t.Fatalf("reset = %+v", r)
	}
}

func TestA_AResetEndsEveryOtherSessionInTheSameStepAsTheChange(t *testing.T) {
	// the cut of the sessions, the block and the facts are written by the store inside Reset: the use case makes no other call
	w := newWorld()
	w.liveFor("ana")
	_ = w.service.Reset(ctx, reset("travesia", "ana@example.com", theCode, newPass, newPass))
	if len(w.codes.resets) != 1 || len(w.codes.failures) != 0 || len(w.codes.issued) != 0 {
		t.Fatal("one Reset call and nothing else")
	}
}

func TestA_ABadPasswordOrConfirmationChangesNothing(t *testing.T) {
	for _, c := range []struct{ name, pass, confirm, field string }{
		{"too short", "Ab1!", "Ab1!", "newPassword"},
		{"no special character", "Viaje2026nuevo", "Viaje2026nuevo", "newPassword"},
		{"a common password", "Password1!", "Password1!", "newPassword"},
		{"the confirmation differs", newPass, newPass + "x", "newPasswordConfirmation"},
		{"no confirmation", newPass, "", "newPasswordConfirmation"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld()
			w.liveFor("ana")
			err := w.service.Reset(ctx, reset("travesia", "ana@example.com", theCode, c.pass, c.confirm))
			if got := field(t, err); got != c.field {
				t.Fatalf("field = %q, want %q", got, c.field)
			}
			if len(w.codes.resets) != 0 || len(w.codes.failures) != 0 {
				t.Fatalf("nothing changes and no try of the code is burned: %v %v", w.codes.resets, w.codes.failures)
			}
		})
	}
}

func TestA_AMalformedEmailOrCodeIsARefusedRequestAndLooksNothingUp(t *testing.T) {
	for _, c := range []struct{ email, code, field string }{
		{"not-an-email", theCode, "email"},
		{"ana@example.com", "1234567", "code"},
		{"ana@example.com", "1234567a", "code"},
		{"ana@example.com", "", "code"},
	} {
		w := newWorld()
		w.liveFor("ana")
		if got := field(t, w.service.Reset(ctx, reset("travesia", c.email, c.code, newPass, newPass))); got != c.field {
			t.Fatalf("field = %q, want %q", got, c.field)
		}
		if len(w.codes.failures) != 0 || len(w.codes.resets) != 0 {
			t.Fatal("a malformed request is not an attempt on an account")
		}
	}
}

func TestA_AnUnknownTenantIsNotFound(t *testing.T) {
	w := newWorld()
	if err := w.service.Reset(ctx, reset("nowhere", "ana@example.com", theCode, newPass, newPass)); !errors.Is(err, recoverpassword.ErrTenantNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestA_EveryRefusedCodeIsTheSameRefusal(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(*world)
		email string
		code  string
		ident string
	}{
		{"a wrong code", func(w *world) { w.liveFor("ana") }, "ana@example.com", "00000000", "travesia"},
		{"no live code (used, expired or retired)", func(w *world) {}, "ana@example.com", theCode, "travesia"},
		{"an e-mail with no account", func(w *world) {}, "nobody@example.com", theCode, "travesia"},
		{"an inactive account", func(w *world) { w.liveFor("gone") }, "gone@example.com", theCode, "travesia"},
		{"a tenant that is not active", func(w *world) { w.liveFor("ana") }, "ana@example.com", theCode, "parked"},
		{"the code of another account", func(w *world) { w.liveFor("elsewhere") }, "ana@example.com", theCode, "travesia"},
		{"a code lost to a concurrent reset", func(w *world) { w.liveFor("ana"); w.codes.raceLost = true }, "ana@example.com", theCode, "travesia"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld()
			c.setup(w)
			err := w.service.Reset(ctx, reset(c.ident, c.email, c.code, newPass, newPass))
			if !errors.Is(err, recoverpassword.ErrCodeRefused) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestA_TheFifthWrongTryRetiresTheCode(t *testing.T) {
	// the count and the retirement are the store's, in one conditional statement; the use case asks for each wrong try
	w := newWorld()
	w.liveFor("ana")
	err := w.service.Reset(ctx, reset("travesia", "ana@example.com", "00000000", newPass, newPass))
	if !errors.Is(err, recoverpassword.ErrCodeRefused) {
		t.Fatalf("err = %v", err)
	}
	if len(w.codes.resets) != 0 || len(w.codes.failures) != 1 {
		t.Fatalf("resets %v failures %v", w.codes.resets, w.codes.failures)
	}
	f := w.codes.failures[0]
	if f.AccountID != "ana" || f.CodeID != "code-1" || f.Reason != port.ReasonWrongCode || f.Administrative || f.CorrelationID != "corr-1" || !f.Now.Equal(now) {
		t.Fatalf("failure = %+v", f)
	}
}

func TestA_AnAdministrativeResetRecordsItsOutcome(t *testing.T) {
	for _, c := range []struct {
		name   string
		email  string
		id     string
		ident  string
		plat   bool
		setup  func(*world)
		code   string
		pass   string
		reason string
	}{
		{"a wrong code of a Tenant Administrator", "boss@example.com", "boss", "travesia", false, func(w *world) { w.liveFor("boss") }, "00000000", newPass, port.ReasonWrongCode},
		{"no live code of a Tenant Administrator", "boss@example.com", "boss", "travesia", false, func(w *world) {}, theCode, newPass, port.ReasonRetiredCode},
		{"a password that breaks the policy", "boss@example.com", "boss", "travesia", false, func(w *world) { w.liveFor("boss") }, theCode, "weak", port.ReasonPolicy},
		{"a wrong code of the Platform Administrator", "root@multitour.example", "root", "", true, func(w *world) { w.liveFor("root") }, "00000000", newPass, port.ReasonWrongCode},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld()
			c.setup(w)
			r := reset(c.ident, c.email, c.code, c.pass, c.pass)
			r.Platform = c.plat
			if err := w.service.Reset(ctx, r); err == nil {
				t.Fatal("it must be refused")
			}
			if len(w.codes.failures) != 1 || !w.codes.failures[0].Administrative || w.codes.failures[0].Reason != c.reason || w.codes.failures[0].AccountID != c.id {
				t.Fatalf("failures = %+v", w.codes.failures)
			}
		})
	}
}

func TestA_ASuccessfulAdministrativeResetIsMarkedAdministrative(t *testing.T) {
	w := newWorld()
	w.liveFor("boss")
	if err := w.service.Reset(ctx, reset("travesia", "boss@example.com", theCode, newPass, newPass)); err != nil {
		t.Fatal(err)
	}
	if r := w.codes.resets[0]; !r.Administrative || len(r.Roles) != 1 || r.Roles[0] != "TENANT_ADMINISTRATOR" {
		t.Fatalf("reset = %+v", r)
	}
	w2 := newWorld()
	w2.liveFor("root")
	r := reset("", "root@multitour.example", theCode, newPass, newPass)
	r.Platform = true
	if err := w2.service.Reset(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := w2.codes.resets[0]; !got.Administrative || got.TenantID != "" {
		t.Fatalf("reset = %+v", got)
	}
}

func TestA_ACustomerFailureIsNotAnAdministrativeFact(t *testing.T) {
	w := newWorld()
	w.liveFor("ana")
	_ = w.service.Reset(ctx, reset("travesia", "ana@example.com", theCode, "weak", "weak"))
	if len(w.codes.failures) != 0 {
		t.Fatalf("a customer's refused policy is not recorded: %+v", w.codes.failures)
	}
}

func TestA_AResetOfAPendingAccountVerifiesIt(t *testing.T) {
	w := newWorld()
	w.liveFor("pending")
	if err := w.service.Reset(ctx, reset("travesia", "pending@example.com", theCode, newPass, newPass)); err != nil {
		t.Fatal(err)
	}
	if !w.codes.resets[0].Pending {
		t.Fatalf("the code proved the mailbox: %+v", w.codes.resets[0])
	}
}

func TestA_TheNewPasswordIsOnlyEverHandedToTheStoreAsAHash(t *testing.T) {
	w := newWorld()
	w.liveFor("ana")
	_ = w.service.Reset(ctx, reset("travesia", "ana@example.com", theCode, newPass, newPass))
	if got := w.codes.resets[0].NewHash; got == newPass || !strings.HasPrefix(got, "hash:") {
		t.Fatalf("hash = %q", got)
	}
}

func TestA_ACodeIsBoundToItsAccount(t *testing.T) {
	// the digits are right, but the HMAC the store holds was made for another account: it is a wrong code
	w := newWorld()
	w.codes.live = &port.CodeState{ID: "code-1", HMAC: recovery.HMAC(key, "elsewhere", theCode)}
	err := w.service.Reset(ctx, reset("travesia", "ana@example.com", theCode, newPass, newPass))
	if !errors.Is(err, recoverpassword.ErrCodeRefused) || len(w.codes.resets) != 0 || len(w.codes.failures) != 1 || w.codes.failures[0].Reason != port.ReasonWrongCode {
		t.Fatalf("err %v resets %v failures %v", err, w.codes.resets, w.codes.failures)
	}
}

func TestA_ABadPasswordIsTheSameAnswerWhetherTheAccountExistsOrNot(t *testing.T) {
	// the shape of the request is judged the same for every e-mail and every tenant that exists, so the answer tells nothing
	for _, c := range []struct{ name, ident, email string }{
		{"an account", "travesia", "ana@example.com"},
		{"an e-mail with no account", "travesia", "nobody@example.com"},
		{"an inactive account", "travesia", "gone@example.com"},
		{"a tenant that is not active", "parked", "ana@example.com"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld()
			w.liveFor("ana")
			if got := field(t, w.service.Reset(ctx, reset(c.ident, c.email, theCode, "weak", "weak"))); got != "newPassword" {
				t.Fatalf("field = %q", got)
			}
			if len(w.codes.failures) != 0 || len(w.codes.resets) != 0 {
				t.Fatalf("nothing is recorded for a customer or for no account: %v %v", w.codes.failures, w.codes.resets)
			}
		})
	}
}

func TestA_ANonAdministrativeAccountNeverLeavesAnAdministrativeFact(t *testing.T) {
	w := newWorld()
	w.liveFor("ana")
	_ = w.service.Reset(ctx, reset("travesia", "ana@example.com", "00000000", newPass, newPass))
	_ = w.service.Reset(ctx, reset("travesia", "pending@example.com", theCode, newPass, newPass))
	for _, f := range w.codes.failures {
		if f.Administrative {
			t.Fatalf("a customer's failure is marked administrative: %+v", f)
		}
	}
}
