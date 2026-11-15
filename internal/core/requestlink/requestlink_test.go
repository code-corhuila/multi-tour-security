package requestlink_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/requestlink"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/verification"
)

const (
	tenantID = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	otherID  = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
)

var (
	now = time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	ctx = context.Background()
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
	byKey   map[string]account.Account
	lookups int
}

func (f *fakeAccounts) FindByEmail(_ context.Context, tenantID, email string) (account.Account, bool, error) {
	f.lookups++
	a, ok := f.byKey[tenantID+"|"+email]
	return a, ok, nil
}

// fakeVerifications behaves as the store must: it refuses a link over the limit and retires the earlier ones.
type fakeVerifications struct {
	port.Verifications
	issued  []port.NewLink
	owners  []string
	retired []string // hashes of the links replaced by a later one
	limits  []int
	windows []time.Duration
	failed  []string
	causes  []string
	// already is how many links the account received in the window before the test starts
	already int
}

func (f *fakeVerifications) Issue(_ context.Context, accountID string, link port.NewLink, _ time.Time, limit int, window time.Duration) (bool, error) {
	f.limits, f.windows = append(f.limits, limit), append(f.windows, window)
	if f.already+len(f.issued) >= limit {
		return false, nil
	}
	for _, earlier := range f.issued {
		f.retired = append(f.retired, earlier.TokenHash)
	}
	f.issued, f.owners = append(f.issued, link), append(f.owners, accountID)
	return true, nil
}

func (f *fakeVerifications) MarkSendFailed(_ context.Context, hash string, _ time.Time, cause string) error {
	f.failed, f.causes = append(f.failed, hash), append(f.causes, cause)
	return nil
}

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

// countingRandom gives a different value to every link, as a real source does
type countingRandom struct{ n byte }

func (c *countingRandom) Read(p []byte) (int, error) {
	c.n++
	copy(p, bytes.Repeat([]byte{c.n}, len(p)))
	return len(p), nil
}

type world struct {
	tenants  *fakeTenants
	accounts *fakeAccounts
	links    *fakeVerifications
	mailer   *fakeMailer
	service  *requestlink.Service
}

func pending(id, email string) account.Account {
	return account.Account{ID: id, TenantID: tenantID, EmailNormalized: email, PasswordHash: "hash", Status: account.Pending}
}

func newWorld() *world {
	w := &world{
		tenants: &fakeTenants{copies: map[string]tenant.Copy{
			"travesia": {TenantID: tenantID, Identifier: "travesia", Status: tenant.Active, CommercialName: "Travesía Natural SAS"},
			"parked":   {TenantID: otherID, Identifier: "parked", Status: tenant.Inactive},
		}},
		accounts: &fakeAccounts{byKey: map[string]account.Account{tenantID + "|ana@example.com": pending("acc-1", "ana@example.com")}},
		links:    &fakeVerifications{},
		mailer:   &fakeMailer{},
	}
	w.service = &requestlink.Service{Tenants: w.tenants, Accounts: w.accounts, Verifications: w.links, Mailer: w.mailer,
		Random: io.Reader(&countingRandom{}), Clock: func() time.Time { return now }}
	return w
}

func TestA_ALinkIsSentOnlyToAPendingAccountUnderTheLimit(t *testing.T) {
	w := newWorld()
	if err := w.service.Request(ctx, "travesia", " Ana@Example.COM "); err != nil {
		t.Fatal(err)
	}
	if len(w.mailer.sent) != 1 || len(w.links.issued) != 1 {
		t.Fatalf("sent=%d issued=%d, want one of each", len(w.mailer.sent), len(w.links.issued))
	}
	mail := w.mailer.sent[0]
	if mail.To != "ana@example.com" || mail.TenantName != "Travesía Natural SAS" || mail.TenantIdentifier != "travesia" ||
		w.links.owners[0] != "acc-1" || w.links.issued[0].TokenHash != verification.Hash(mail.Token) ||
		!w.links.issued[0].ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("mail=%+v issued=%+v owner=%v", mail, w.links.issued[0], w.links.owners)
	}
}

func TestA_NothingIsSentToAnyoneElseAndTheAnswerIsAlwaysNil(t *testing.T) {
	verified := pending("acc-2", "luis@example.com")
	verified.Status = account.Active
	inactive := pending("acc-3", "eva@example.com")
	inactive.Status = account.Inactive
	cases := []struct{ name, tenant, email string }{
		{"already verified", "travesia", "luis@example.com"},
		{"inactive account", "travesia", "eva@example.com"},
		{"unknown e-mail", "travesia", "nobody@example.com"},
		{"unknown tenant", "nowhere", "ana@example.com"},
		{"inactive tenant", "parked", "ana@example.com"},
	}
	for _, c := range cases {
		w := newWorld()
		w.accounts.byKey[tenantID+"|luis@example.com"] = verified
		w.accounts.byKey[tenantID+"|eva@example.com"] = inactive
		w.accounts.byKey[otherID+"|ana@example.com"] = pending("acc-4", "ana@example.com")
		if err := w.service.Request(ctx, c.tenant, c.email); err != nil {
			t.Fatalf("%s: err = %v, the answer must not tell this apart", c.name, err)
		}
		if len(w.mailer.sent) != 0 || len(w.links.issued) != 0 {
			t.Fatalf("%s: nothing may be sent or written", c.name)
		}
	}
}

func TestA_AFourthLinkInAnHourIsNotSent(t *testing.T) {
	w := newWorld()
	w.links.already = 1 // the link of the creation counts
	for i := 0; i < 4; i++ {
		if err := w.service.Request(ctx, "travesia", "ana@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if len(w.mailer.sent) != 2 {
		t.Fatalf("sent %d links, want 2 more after the one of the creation", len(w.mailer.sent))
	}
	for i := range w.links.limits {
		if w.links.limits[i] != 3 || w.links.windows[i] != time.Hour {
			t.Fatalf("the limit asked of the store was %d in %s, want 3 in one hour", w.links.limits[i], w.links.windows[i])
		}
	}
}

func TestA_ANewLinkRetiresTheEarlierOnes(t *testing.T) {
	w := newWorld()
	for i := 0; i < 2; i++ {
		if err := w.service.Request(ctx, "travesia", "ana@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if len(w.links.retired) != 1 || w.links.retired[0] != w.links.issued[0].TokenHash || w.links.issued[0].TokenHash == w.links.issued[1].TokenHash {
		t.Fatalf("the second link must retire the first and differ from it: retired=%v", w.links.retired)
	}
}

func TestA_AFailedSendIsRecordedAndChangesNothing(t *testing.T) {
	w := newWorld()
	w.mailer.err = errors.New("smtp: connection refused")
	if err := w.service.Request(ctx, "travesia", "ana@example.com"); err != nil {
		t.Fatalf("a failed send is recorded, not answered: %v", err)
	}
	if len(w.links.failed) != 1 || w.links.failed[0] != w.links.issued[0].TokenHash || w.accounts.byKey[tenantID+"|ana@example.com"].Status != account.Pending {
		t.Fatalf("failed=%v", w.links.failed)
	}
}

func TestA_AnInvalidEmailIsRefusedBeforeAnyLookup(t *testing.T) {
	for _, email := range []string{"", "ab", "no-at-sign", "a b@example.com", "é@example.com"} {
		w := newWorld()
		if err := w.service.Request(ctx, "travesia", email); !errors.Is(err, requestlink.ErrInvalidRequest) {
			t.Fatalf("%q: err = %v", email, err)
		}
		if w.accounts.lookups != 0 {
			t.Fatalf("%q: the account was looked up", email)
		}
	}
}

func TestA_AMissingPieceStopsTheUseCase(t *testing.T) {
	for _, drop := range []func(*requestlink.Service){
		func(s *requestlink.Service) { s.Tenants = nil },
		func(s *requestlink.Service) { s.Accounts = nil },
		func(s *requestlink.Service) { s.Verifications = nil },
		func(s *requestlink.Service) { s.Mailer = nil },
		func(s *requestlink.Service) { s.Random = nil },
		func(s *requestlink.Service) { s.Clock = nil },
	} {
		w := newWorld()
		drop(w.service)
		if err := w.service.Request(ctx, "travesia", "ana@example.com"); err == nil || errors.Is(err, requestlink.ErrInvalidRequest) {
			t.Fatalf("err = %v, want a wiring error", err)
		}
	}
}
