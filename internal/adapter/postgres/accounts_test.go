package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	tenant      = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	otherTenant = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	missingID   = "00000000-0000-4000-8000-000000000000"
)

var (
	ctx  = context.Background()
	base = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
)

func setup(t *testing.T) (*postgres.Accounts, *pgxpool.Pool, string) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewAccounts(pool), pool, pgtest.MustAccount(t, pool, tenant, "ana@example.com", "TENANT_ADMINISTRATOR", "MANAGER")
}

func events(t *testing.T, pool *pgxpool.Pool, kind string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE event_type = $1`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func fail(t *testing.T, accounts *postgres.Accounts, id string, at time.Time) (account.Account, bool) {
	t.Helper()
	got, blocked, err := accounts.RecordFailure(ctx, id, at, "corr-1")
	if err != nil {
		t.Fatalf("RecordFailure at %v: %v", at, err)
	}
	return got, blocked
}

func TestI_TheFifthFailureInTheWindowBlocksInOneStatementAndLeavesItsEvent(t *testing.T) {
	accounts, pool, id := setup(t)
	for i := 0; i < 4; i++ {
		got, blocked := fail(t, accounts, id, base.Add(time.Duration(i)*time.Minute))
		if blocked || got.Failed != i+1 {
			t.Fatalf("failure %d: failed=%d blocked=%v", i+1, got.Failed, blocked)
		}
		if n := events(t, pool, "AccountBlocked"); n != 0 {
			t.Fatalf("a failure that does not block leaves no event, got %d", n)
		}
	}
	at := base.Add(4 * time.Minute)
	got, blocked := fail(t, accounts, id, at)
	if !blocked || got.Failed != 5 || !got.BlockedUntil.Equal(at.Add(account.BlockLife)) {
		t.Fatalf("the fifth must block for 15 minutes: %+v blocked=%v", got, blocked)
	}
	var tenantID, aggregate, correlation, status, payload string
	var occurred time.Time
	err := pool.QueryRow(ctx, `SELECT tenant_id::text, aggregate_id::text, correlation_id, status, payload::text, occurred_at
		FROM security.outbox_event WHERE event_type = 'AccountBlocked'`).Scan(&tenantID, &aggregate, &correlation, &status, &payload, &occurred)
	if err != nil || tenantID != tenant || aggregate != id || correlation != "corr-1" || status != "PENDING" || !occurred.Equal(at) {
		t.Fatalf("the event must name the tenant, the account, the correlation and the instant of the block: %q %q %q %q %v %v",
			tenantID, aggregate, correlation, status, occurred, err)
	}
	for _, secret := range []string{"ana@example.com", pgtest.ValidHash, "password", "$2a$"} {
		if strings.Contains(payload, secret) {
			t.Fatalf("the payload of the event carries %q: %s", secret, payload)
		}
	}
}

func TestI_TheBlockOfAPlatformAccountLeavesAnEventWithNoTenant(t *testing.T) {
	accounts, pool, _ := setup(t)
	root := pgtest.MustAccount(t, pool, "", "root@example.com", "PLATFORM_ADMINISTRATOR")
	for i := 0; i < 5; i++ {
		fail(t, accounts, root, base.Add(time.Duration(i)*time.Second))
	}
	var withoutTenant int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountBlocked' AND tenant_id IS NULL
		AND aggregate_id = $1::uuid`, root).Scan(&withoutTenant); err != nil || withoutTenant != 1 {
		t.Fatalf("a platform block must leave one event with no tenant: %d %v", withoutTenant, err)
	}
}

func TestI_TheCountAndTheEventAreOneStatementSoARefusedEventLeavesNoCount(t *testing.T) {
	for _, correlation := range []string{"", strings.Repeat("c", 129)} {
		accounts, pool, id := setup(t)
		for i := 0; i < 4; i++ {
			fail(t, accounts, id, base.Add(time.Duration(i)*time.Second))
		}
		if _, _, err := accounts.RecordFailure(ctx, id, base.Add(5*time.Second), correlation); err == nil {
			t.Fatalf("a correlation id of %d characters was accepted", len(correlation))
		}
		got, _, _ := accounts.FindByID(ctx, id)
		if got.Failed != 4 || !got.BlockedUntil.IsZero() {
			t.Fatalf("the block was counted although its event was refused: %+v", got)
		}
		if n := events(t, pool, "AccountBlocked"); n != 0 {
			t.Fatalf("an event was written for a refused block: %d", n)
		}
	}
}

func TestI_AFailureWhileBlockedChangesNothingAndLeavesNoSecondEvent(t *testing.T) {
	accounts, pool, id := setup(t)
	var blockedUntil time.Time
	for i := 0; i < 5; i++ {
		got, _ := fail(t, accounts, id, base.Add(time.Duration(i)*time.Second))
		blockedUntil = got.BlockedUntil
	}
	got, blocked := fail(t, accounts, id, base.Add(5*time.Minute))
	if blocked || got.Failed != 5 || !got.BlockedUntil.Equal(blockedUntil) {
		t.Fatalf("a failure during the block must be a no-op: %+v blocked=%v", got, blocked)
	}
	if n := events(t, pool, "AccountBlocked"); n != 1 {
		t.Fatalf("the block is audited once, got %d events", n)
	}
}

func TestI_TheEdgesOfTheWindowAndOfTheBlockAreThoseOfTheDomain(t *testing.T) {
	accounts, pool, _ := setup(t)
	one := func(email string) string { return pgtest.MustAccount(t, pool, tenant, email, "ANALYST") }

	inside := one("inside@example.com")
	fail(t, accounts, inside, base)
	if got, _ := fail(t, accounts, inside, base.Add(account.FailureWindow-time.Second)); got.Failed != 2 {
		t.Errorf("one second before the end of the window the failure counts in it: %+v", got)
	}
	exact := one("exact@example.com")
	fail(t, accounts, exact, base)
	if got, _ := fail(t, accounts, exact, base.Add(account.FailureWindow)); got.Failed != 1 || !got.FirstFailedAt.Equal(base.Add(account.FailureWindow)) {
		t.Errorf("at the exact end of the window a new one opens: %+v", got)
	}
	blocked := one("blocked@example.com")
	for i := 0; i < 5; i++ {
		fail(t, accounts, blocked, base)
	}
	if got, _ := fail(t, accounts, blocked, base.Add(account.BlockLife-time.Second)); got.Failed != 5 {
		t.Errorf("one second before the end of the block the failure is a no-op: %+v", got)
	}
	if got, _ := fail(t, accounts, blocked, base.Add(account.BlockLife)); got.Failed != 1 || !got.BlockedUntil.IsZero() {
		t.Errorf("at the exact end of the block the account counts again: %+v", got)
	}
}

func TestI_AFailureAfterTheWindowOpensANewOne(t *testing.T) {
	accounts, _, id := setup(t)
	fail(t, accounts, id, base)
	fail(t, accounts, id, base.Add(time.Minute))
	later := base.Add(account.FailureWindow + time.Second)
	got, blocked := fail(t, accounts, id, later)
	if blocked || got.Failed != 1 || !got.FirstFailedAt.Equal(later) {
		t.Fatalf("a failure outside the window starts a new count: %+v", got)
	}
}

func TestI_ConcurrentFailuresAreEachCountedOnceAndBlockExactlyOnce(t *testing.T) {
	accounts, pool, id := setup(t)
	var wg sync.WaitGroup
	var blocks atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, blocked, err := accounts.RecordFailure(ctx, id, base.Add(time.Duration(i)*time.Second), "c")
			if err != nil || got.Failed < 1 || got.Failed > account.MaxFailures {
				t.Errorf("call %d: %+v %v", i, got, err)
			}
			if blocked {
				blocks.Add(1)
			}
		}(i)
	}
	wg.Wait()
	got, found, err := accounts.FindByID(ctx, id)
	if err != nil || !found || got.Failed != account.MaxFailures || got.BlockedUntil.IsZero() {
		t.Fatalf("twenty concurrent failures must stop at the block: %+v %v", got, err)
	}
	if blocks.Load() != 1 || events(t, pool, "AccountBlocked") != 1 {
		t.Fatalf("the block is reported and audited once: %d reports, %d events", blocks.Load(), events(t, pool, "AccountBlocked"))
	}
}

func TestI_TheStatementAndTheDomainRuleAgree(t *testing.T) {
	accounts, _, id := setup(t)
	want := account.Account{}
	for _, minutes := range []int{0, 1, 2, 3, 4, 5, 10, 25, 26, 27, 28, 29, 30, 50, 51} {
		at := base.Add(time.Duration(minutes) * time.Minute)
		var wantBlocked bool
		want, wantBlocked = want.AfterFailure(at)
		got, blocked := fail(t, accounts, id, at)
		if blocked != wantBlocked || got.Failed != want.Failed || !got.FirstFailedAt.Equal(want.FirstFailedAt) ||
			!got.BlockedUntil.Equal(want.BlockedUntil) {
			t.Fatalf("minute %d: SQL %+v blocked=%v, domain %+v blocked=%v", minutes, got, blocked, want, wantBlocked)
		}
	}
}

func TestI_ASuccessClearsTheFailuresAndTheBlockOfThatAccountOnly(t *testing.T) {
	accounts, pool, id := setup(t)
	other := pgtest.MustAccount(t, pool, tenant, "other@example.com", "ANALYST")
	for i := 0; i < 5; i++ {
		fail(t, accounts, id, base)
	}
	fail(t, accounts, other, base)
	if err := accounts.RecordSuccess(ctx, id); err != nil {
		t.Fatal(err)
	}
	got, _, _ := accounts.FindByID(ctx, id)
	if got.Failed != 0 || !got.FirstFailedAt.IsZero() || !got.BlockedUntil.IsZero() {
		t.Fatalf("a success must clear the count and the block: %+v", got)
	}
	if left, _, _ := accounts.FindByID(ctx, other); left.Failed != 1 {
		t.Fatalf("a success of one account touched another: %+v", left)
	}
	if n := events(t, pool, "AccountBlocked"); n != 1 {
		t.Fatalf("a success writes no event, got %d", n)
	}
}

func TestI_AnAccountIsFoundByItsTenantAndEmailAndOnlyThere(t *testing.T) {
	accounts, pool, id := setup(t)
	got, found, err := accounts.FindByEmail(ctx, tenant, "ana@example.com")
	if err != nil || !found || got.ID != id || got.TenantID != tenant || got.EmailNormalized != "ana@example.com" ||
		got.PasswordHash != pgtest.ValidHash || got.Status != account.Active {
		t.Fatalf("not found where it is: %+v %v %v", got, found, err)
	}
	if !got.TemporaryUntil.IsZero() || !got.FirstFailedAt.IsZero() || !got.BlockedUntil.IsZero() || got.Failed != 0 {
		t.Errorf("a null column must be the zero value: %+v", got)
	}
	if _, found, _ := accounts.FindByEmail(ctx, otherTenant, "ana@example.com"); found {
		t.Error("the account of another tenant was found")
	}
	if _, found, _ := accounts.FindByEmail(ctx, "", "ana@example.com"); found {
		t.Error("a tenant account was found as the platform's")
	}
	if _, found, _ := accounts.FindByEmail(ctx, tenant, "ANA@example.com"); found {
		t.Error("the caller normalizes the e-mail: the adapter does not guess")
	}
	root := pgtest.MustAccount(t, pool, "", "root@example.com", "PLATFORM_ADMINISTRATOR")
	if got, found, _ := accounts.FindByEmail(ctx, "", "root@example.com"); !found || got.ID != root || !got.IsPlatform() {
		t.Errorf("the platform account was not found: %+v", got)
	}
}

func TestI_AnInactiveAccountAndATemporaryCredentialAreRead(t *testing.T) {
	accounts, pool, _ := setup(t)
	until := base.Add(72 * time.Hour)
	inactive, err := pgtest.AccountWith(ctx, pool, tenant, "off@example.com", pgtest.ValidHash, pgtest.Options{Inactive: true}, "ANALYST")
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := pgtest.AccountWith(ctx, pool, tenant, "new@example.com", pgtest.ValidHash, pgtest.Options{TemporaryUntil: until}, "ANALYST")
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := accounts.FindByID(ctx, inactive); got.Status != account.Inactive {
		t.Errorf("the status was not read: %+v", got)
	}
	if got, _, _ := accounts.FindByID(ctx, temporary); !got.TemporaryUntil.Equal(until) || !got.UsesTemporaryCredential(base) {
		t.Errorf("the temporary credential was not read: %+v", got)
	}
}

func TestI_AMissingAccountIsNotFoundAndAnInvalidIdIsAnError(t *testing.T) {
	accounts, _, _ := setup(t)
	if _, found, err := accounts.FindByID(ctx, missingID); found || err != nil {
		t.Errorf("a missing account is found=false with no error: %v %v", found, err)
	}
	if _, found, err := accounts.FindByID(ctx, "not-a-uuid"); found || err == nil {
		t.Errorf("an id that is not a UUID is an error and not a silent miss: %v %v", found, err)
	}
	if _, _, err := accounts.RecordFailure(ctx, missingID, base, "c"); !errors.Is(err, postgres.ErrAccountNotFound) {
		t.Errorf("a failure on a missing account is ErrAccountNotFound, got %v", err)
	}
	if err := accounts.RecordSuccess(ctx, missingID); !errors.Is(err, postgres.ErrAccountNotFound) {
		t.Errorf("a success on a missing account is ErrAccountNotFound, got %v", err)
	}
}

func TestI_TheRolesComeFromTheActiveMembershipOrderedByName(t *testing.T) {
	accounts, pool, id := setup(t)
	roles, err := accounts.RolesOf(ctx, id)
	if err != nil || len(roles) != 2 || roles[0] != "MANAGER" || roles[1] != "TENANT_ADMINISTRATOR" {
		t.Fatalf("roles = %v, %v", roles, err)
	}
	none := pgtest.MustAccount(t, pool, tenant, "none@example.com")
	if roles, err := accounts.RolesOf(ctx, none); err != nil || roles == nil || len(roles) != 0 {
		t.Errorf("an account with no role has an empty list and no error: %v %v", roles, err)
	}
	off, err := pgtest.AccountWith(ctx, pool, tenant, "off@example.com", pgtest.ValidHash, pgtest.Options{MembershipInactive: true}, "MANAGER")
	if err != nil {
		t.Fatal(err)
	}
	if roles, _ := accounts.RolesOf(ctx, off); len(roles) != 0 {
		t.Errorf("the roles of an inactive membership are not given: %v", roles)
	}
}

func TestI_TheTableRefusesAClearPasswordAndARepeatedEmail(t *testing.T) {
	_, pool, _ := setup(t)
	code := func(err error) string {
		var pg *pgconn.PgError
		if errors.As(err, &pg) {
			return pg.Code
		}
		return "not a PostgreSQL error: " + errString(err)
	}
	_, err := pgtest.Account(ctx, pool, tenant, "clear@example.com", "plain-password")
	if code(err) != "23514" {
		t.Errorf("a password that is not a bcrypt hash must break the CHECK (23514), got %s", code(err))
	}
	_, err = pgtest.Account(ctx, pool, tenant, "ana@example.com", pgtest.ValidHash)
	if code(err) != "23505" {
		t.Errorf("an e-mail repeated in a tenant must break the unique (23505), got %s", code(err))
	}
	pgtest.MustAccount(t, pool, "", "root@example.com", "PLATFORM_ADMINISTRATOR")
	_, err = pgtest.Account(ctx, pool, "", "root@example.com", pgtest.ValidHash)
	if code(err) != "23505" {
		t.Errorf("an e-mail repeated among the platform accounts must break the unique (23505), got %s", code(err))
	}
}

func errString(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}
