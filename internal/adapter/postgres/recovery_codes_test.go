package postgres_test

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The tests below cover the store of the recovery codes (spec 006-hu-sec-004, RN-SEC-006-02, -03, -05, -07, -08, -09, -10, -11, -12).

var recoveredHash = "$2a$12$" + strings.Repeat("Z", 53)

type recoveryWorld struct {
	store *postgres.RecoveryCodes
	pool  *pgxpool.Pool
	ana   string // an active customer
	pend  string // a pending customer
	boss  string // a Tenant Administrator
	gone  string // an inactive account
	root  string // the Platform Administrator, with no tenant
}

func recoverySetup(t *testing.T) recoveryWorld {
	t.Helper()
	pool := pgtest.Open(t)
	make := func(tenantID, email string, o pgtest.Options, roles ...string) string {
		id, err := pgtest.AccountWith(ctx, pool, tenantID, email, pgtest.ValidHash, o, roles...)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	return recoveryWorld{
		store: postgres.NewRecoveryCodes(pool), pool: pool,
		ana:  make(tenant, "ana@example.com", pgtest.Options{}, "FINAL_CUSTOMER"),
		pend: make(tenant, "pending@example.com", pgtest.Options{Pending: true}, "FINAL_CUSTOMER"),
		boss: make(tenant, "boss@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR"),
		gone: make(tenant, "gone@example.com", pgtest.Options{Inactive: true}, "FINAL_CUSTOMER"),
		root: make("", "root@multitour.example", pgtest.Options{}, "PLATFORM_ADMINISTRATOR"),
	}
}

// codeN is a code as the store keeps it: a distinct 64-character HMAC, created at the given instant, valid 30 minutes.
func codeN(n int, at time.Time) port.NewCode {
	return port.NewCode{HMAC: fmt.Sprintf("%064x", n), CreatedAt: at, ExpiresAt: at.Add(30 * time.Minute)}
}

func (w recoveryWorld) issue(t *testing.T, account string, tenantID string, n int, at time.Time) bool {
	t.Helper()
	ok, err := w.store.Issue(ctx, port.IssueCode{AccountID: account, TenantID: tenantID, Code: codeN(n, at), Now: at, Limit: 3, Window: time.Hour, CorrelationID: "corr-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return ok
}

func (w recoveryWorld) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := w.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (w recoveryWorld) events(t *testing.T) map[string]int {
	t.Helper()
	rows, err := w.pool.Query(ctx, `SELECT event_type, count(*) FROM security.outbox_event GROUP BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			t.Fatal(err)
		}
		got[kind] = n
	}
	return got
}

func (w recoveryWorld) tries(t *testing.T, account string) (int, bool) {
	t.Helper()
	var tries int
	var retired *time.Time
	if err := w.pool.QueryRow(ctx, `SELECT wrong_tries, retired_at FROM security.recovery_code WHERE identity_id = $1::uuid ORDER BY created_at DESC LIMIT 1`, account).Scan(&tries, &retired); err != nil {
		t.Fatal(err)
	}
	return tries, retired != nil
}

func (w recoveryWorld) fail(t *testing.T, account, codeID, reason string, admin bool, at time.Time) {
	t.Helper()
	if err := w.store.RecordFailure(ctx, port.FailedReset{AccountID: account, TenantID: tenant, CodeID: codeID, Reason: reason, Administrative: admin, Now: at, CorrelationID: "corr-2"}); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
}

// tryReset is reset that returns the error, so that a goroutine can report it with t.Errorf (t.Fatalf is only for the test's own).
func (w recoveryWorld) tryReset(account, codeID string, pending, admin bool, at time.Time) (bool, error) {
	return w.store.Reset(ctx, port.ResetCommand{AccountID: account, TenantID: tenant, CodeID: codeID, NewHash: recoveredHash, Roles: []string{"FINAL_CUSTOMER"},
		Administrative: admin, Pending: pending, Now: at, CorrelationID: "corr-3"})
}

func (w recoveryWorld) reset(t *testing.T, account, codeID string, pending, admin bool, at time.Time) bool {
	t.Helper()
	ok, err := w.tryReset(account, codeID, pending, admin, at)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	return ok
}

func (w recoveryWorld) live(t *testing.T, account string, at time.Time) port.CodeState {
	t.Helper()
	state, found, err := w.store.Newest(ctx, account, at)
	if err != nil || !found {
		t.Fatalf("Newest: %+v %v %v", state, found, err)
	}
	return state
}

func TestI_OnlyTheHMACOfTheCodeIsStored(t *testing.T) {
	w := recoverySetup(t)
	if !w.issue(t, w.ana, tenant, 1, base) {
		t.Fatal("the first code was not written")
	}
	var hmac string
	var tries int
	var expires time.Time
	if err := w.pool.QueryRow(ctx, `SELECT code_hmac, wrong_tries, expires_at FROM security.recovery_code`).Scan(&hmac, &tries, &expires); err != nil {
		t.Fatal(err)
	}
	if hmac != codeN(1, base).HMAC || tries != 0 || !expires.Equal(base.Add(30*time.Minute)) {
		t.Fatalf("row = %s %d %v", hmac, tries, expires)
	}
}

func TestI_IssuingWritesTheCodeAndTheFactTogether(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	var kind, eventTenant, aggregate, correlation, payload string
	var happened time.Time
	if err := w.pool.QueryRow(ctx, `SELECT event_type, tenant_id::text, aggregate_id::text, correlation_id, payload::text, occurred_at FROM security.outbox_event`).
		Scan(&kind, &eventTenant, &aggregate, &correlation, &payload, &happened); err != nil {
		t.Fatalf("exactly one event is written: %v", err)
	}
	if kind != "PasswordRecoveryRequested" || eventTenant != tenant || aggregate != w.ana || correlation != "corr-1" || !happened.Equal(base) {
		t.Fatalf("event = %s %s %s %s %v", kind, eventTenant, aggregate, correlation, happened)
	}
	if strings.Contains(payload, codeN(1, base).HMAC) || strings.Contains(strings.ToLower(payload), "hmac") || !strings.Contains(payload, "accountId") {
		t.Fatalf("the fact carries the code: %s", payload)
	}
}

func TestI_ANewCodeRetiresTheEarlierOnes(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	w.issue(t, w.ana, tenant, 2, base.Add(time.Minute))
	if got := w.live(t, w.ana, base.Add(2*time.Minute)); got.HMAC != codeN(2, base).HMAC {
		t.Fatalf("the live code is %+v, want the newest", got)
	}
	if n := w.count(t, `SELECT count(*) FROM security.recovery_code WHERE retired_at IS NOT NULL`); n != 1 {
		t.Fatalf("retired codes = %d, want the first one", n)
	}
}

func TestI_AnAccountReceivesThreeCodesAnHourAndTheFourthWritesNothing(t *testing.T) {
	w := recoverySetup(t)
	for n := 1; n <= 3; n++ {
		if !w.issue(t, w.ana, tenant, n, base.Add(time.Duration(n)*time.Minute)) {
			t.Fatalf("code %d was refused", n)
		}
	}
	if w.issue(t, w.ana, tenant, 4, base.Add(10*time.Minute)) {
		t.Fatal("a fourth code in an hour was written")
	}
	if n := w.count(t, `SELECT count(*) FROM security.recovery_code`); n != 3 {
		t.Fatalf("codes = %d, want 3", n)
	}
	if got := w.events(t)["PasswordRecoveryRequested"]; got != 3 {
		t.Fatalf("facts = %d: a refused code leaves no fact", got)
	}
	if !w.issue(t, w.ana, tenant, 5, base.Add(time.Hour+4*time.Minute)) {
		t.Fatal("after an hour the limit is not in force any more")
	}
	// the limit is the account's: another account is not slowed down
	if !w.issue(t, w.boss, tenant, 6, base.Add(10*time.Minute)) {
		t.Fatal("another account was limited")
	}
}

func TestI_ConcurrentRequestsTakeTurnsAndOnlyThreeAreWritten(t *testing.T) {
	w := recoverySetup(t)
	var wrote atomic.Int32
	var wg sync.WaitGroup
	for n := 1; n <= 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ok, err := w.store.Issue(ctx, port.IssueCode{AccountID: w.ana, TenantID: tenant, Code: codeN(n, base), Now: base, Limit: 3, Window: time.Hour, CorrelationID: "c"})
			if err != nil {
				t.Errorf("Issue: %v", err)
			}
			if ok {
				wrote.Add(1)
			}
		}(n)
	}
	wg.Wait()
	if wrote.Load() != 3 || w.count(t, `SELECT count(*) FROM security.recovery_code`) != 3 {
		t.Fatalf("written = %d", wrote.Load())
	}
	if n := w.count(t, `SELECT count(*) FROM security.recovery_code WHERE retired_at IS NULL`); n != 1 {
		t.Fatalf("live codes = %d, want one: a new code retires the earlier ones", n)
	}
}

func TestI_AnInactiveAccountOrOneThatDoesNotExistGetsNoCode(t *testing.T) {
	w := recoverySetup(t)
	if w.issue(t, w.gone, tenant, 1, base) {
		t.Fatal("an inactive account got a code")
	}
	if w.issue(t, "00000000-0000-4000-8000-0000000000ff", tenant, 2, base) {
		t.Fatal("an account that does not exist got a code")
	}
	if w.count(t, `SELECT count(*) FROM security.recovery_code`) != 0 || len(w.events(t)) != 0 {
		t.Fatal("nothing is written for them")
	}
}

func TestI_ThePlatformAdministratorGetsACodeAndItsFactHasNoTenant(t *testing.T) {
	w := recoverySetup(t)
	if !w.issue(t, w.root, "", 1, base) {
		t.Fatal("the Platform Administrator got no code")
	}
	var eventTenant *string
	if err := w.pool.QueryRow(ctx, `SELECT tenant_id::text FROM security.outbox_event WHERE event_type = 'PasswordRecoveryRequested'`).Scan(&eventTenant); err != nil {
		t.Fatal(err)
	}
	if eventTenant != nil {
		t.Fatalf("the fact of the platform names the tenant %s", *eventTenant)
	}
}

func TestI_OnlyALiveCodeIsFound(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	at := base.Add(10 * time.Minute)
	live := w.live(t, w.ana, at)
	if _, found, _ := w.store.Newest(ctx, w.ana, base.Add(30*time.Minute)); found {
		t.Fatal("a code is found at the instant it expires")
	}
	if _, found, _ := w.store.Newest(ctx, w.boss, at); found {
		t.Fatal("the code of another account was found")
	}
	if !w.reset(t, w.ana, live.ID, false, false, at) {
		t.Fatal("the reset did not run")
	}
	if _, found, _ := w.store.Newest(ctx, w.ana, at); found {
		t.Fatal("a used code is found")
	}
}

func TestI_AWrongTryCountsAndTheFifthRetiresTheCode(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	code := w.live(t, w.ana, base)
	for want := 1; want <= 5; want++ {
		w.fail(t, w.ana, code.ID, port.ReasonWrongCode, false, base.Add(time.Duration(want)*time.Second))
		got, retired := w.tries(t, w.ana)
		if got != want || retired != (want == 5) {
			t.Fatalf("after %d tries: counted %d, retired %v", want, got, retired)
		}
	}
	// a sixth is not counted and is not an error
	w.fail(t, w.ana, code.ID, port.ReasonWrongCode, false, base.Add(time.Minute))
	if got, _ := w.tries(t, w.ana); got != 5 {
		t.Fatalf("a sixth try was counted: %d", got)
	}
	if _, found, _ := w.store.Newest(ctx, w.ana, base.Add(time.Minute)); found {
		t.Fatal("a retired code is still live")
	}
}

func TestI_ConcurrentWrongTriesCountEachOne(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	code := w.live(t, w.ana, base)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.store.RecordFailure(ctx, port.FailedReset{AccountID: w.ana, TenantID: tenant, CodeID: code.ID, Reason: port.ReasonWrongCode, Now: base, CorrelationID: "c"}); err != nil {
				t.Errorf("RecordFailure: %v", err)
			}
		}()
	}
	wg.Wait()
	if got, retired := w.tries(t, w.ana); got != 4 || retired {
		t.Fatalf("counted %d retired %v, want four tries and a live code", got, retired)
	}
}

func TestI_ARefusalOfAnotherKindCountsNoTryEvenWithALiveCode(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.boss, tenant, 1, base)
	live := w.live(t, w.boss, base)
	w.fail(t, w.boss, "", port.ReasonPolicy, true, base)
	w.fail(t, w.boss, live.ID, port.ReasonPolicy, true, base)
	w.fail(t, w.boss, live.ID, port.ReasonRetiredCode, true, base)
	if got, _ := w.tries(t, w.boss); got != 0 {
		t.Fatalf("a refusal that is not a wrong code counted %d", got)
	}
}

func TestI_AWrongTryNeverCountsAgainstTheCodeOfAnotherAccount(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	w.issue(t, w.boss, tenant, 2, base)
	w.fail(t, w.boss, w.live(t, w.ana, base).ID, port.ReasonWrongCode, false, base)
	if got, _ := w.tries(t, w.ana); got != 0 {
		t.Fatalf("the code of one account counted a try of another: %d", got)
	}
}

func TestI_EightConcurrentWrongTriesCountFiveAndRetireTheCode(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	code := w.live(t, w.ana, base)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.store.RecordFailure(ctx, port.FailedReset{AccountID: w.ana, CodeID: code.ID, Reason: port.ReasonWrongCode, Now: base, CorrelationID: "c"}); err != nil {
				t.Errorf("RecordFailure: %v", err)
			}
		}()
	}
	wg.Wait()
	if got, retired := w.tries(t, w.ana); got != 5 || !retired {
		t.Fatalf("counted %d retired %v, want exactly five and a retired code", got, retired)
	}
}

func TestI_TheFactOfAFailedResetIsWrittenOnlyForAnAdministrativeAccount(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	w.issue(t, w.boss, tenant, 2, base)
	w.fail(t, w.ana, w.live(t, w.ana, base).ID, port.ReasonWrongCode, false, base)
	if w.events(t)["PasswordResetFailed"] != 0 {
		t.Fatal("a customer's failure wrote a fact")
	}
	// an administrator's failure writes it, with a code, and also with none (the code was retired or never lived)
	w.fail(t, w.boss, w.live(t, w.boss, base).ID, port.ReasonWrongCode, true, base)
	w.fail(t, w.boss, "", port.ReasonRetiredCode, true, base)
	if got := w.events(t)["PasswordResetFailed"]; got != 2 {
		t.Fatalf("facts = %d, want 2", got)
	}
	var reason, payload, eventTenant string
	if err := w.pool.QueryRow(ctx, `SELECT payload->>'reason', payload::text, tenant_id::text FROM security.outbox_event
		WHERE event_type = 'PasswordResetFailed' AND payload->>'reason' = 'RETIRED_CODE'`).Scan(&reason, &payload, &eventTenant); err != nil {
		t.Fatal(err)
	}
	if reason != port.ReasonRetiredCode || eventTenant != tenant || !strings.Contains(payload, w.boss) || w.count(t, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'PasswordResetFailed' AND reason = payload->>'reason'`) != 2 {
		t.Fatalf("fact = %s %s %s", reason, eventTenant, payload)
	}
}

func TestI_AResetChangesThePasswordCutsTheSessionsLiftsTheBlockAndWritesTheFacts(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	if _, err := w.pool.Exec(ctx, `UPDATE security.identity SET failed_count = 4, first_failed_at = $2, blocked_until = $3 WHERE identity_id = $1::uuid`,
		w.ana, base, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	at := base.Add(5 * time.Minute)
	if !w.reset(t, w.ana, w.live(t, w.ana, at).ID, false, false, at) {
		t.Fatal("the reset did not run")
	}
	var hash string
	var failed int
	var blocked, cutoff *time.Time
	var status string
	if err := w.pool.QueryRow(ctx, `SELECT password_hash, failed_count, blocked_until, sessions_revoked_from, identity_status FROM security.identity WHERE identity_id = $1::uuid`, w.ana).
		Scan(&hash, &failed, &blocked, &cutoff, &status); err != nil {
		t.Fatal(err)
	}
	if hash != recoveredHash || failed != 0 || blocked != nil || cutoff == nil || !cutoff.Equal(at) || status != "ACTIVE" {
		t.Fatalf("account = %s %d %v %v %s", hash, failed, blocked, cutoff, status)
	}
	var used *time.Time
	if err := w.pool.QueryRow(ctx, `SELECT used_at FROM security.recovery_code`).Scan(&used); err != nil || used == nil || !used.Equal(at) {
		t.Fatalf("used_at = %v %v", used, err)
	}
	got := w.events(t)
	if got["AccountSessionsRevoked"] != 1 || got["PasswordReset"] != 1 || got["AccountEmailVerified"] != 0 || got["PasswordRecoveryRequested"] != 1 {
		t.Fatalf("events = %v", got)
	}
	requireRevocationsCarryTheTenant(t, w.pool)
	var reason, accountID, roles string
	if err := w.pool.QueryRow(ctx, `SELECT payload->>'reason', payload->>'accountId' FROM security.outbox_event WHERE event_type = 'AccountSessionsRevoked'`).Scan(&reason, &accountID); err != nil ||
		reason != "PASSWORD_RESET" || accountID != w.ana {
		t.Fatalf("revocation = %s %s %v", reason, accountID, err)
	}
	if err := w.pool.QueryRow(ctx, `SELECT payload->'roles'::text FROM security.outbox_event WHERE event_type = 'PasswordReset'`).Scan(&roles); err != nil || !strings.Contains(roles, "FINAL_CUSTOMER") {
		t.Fatalf("roles = %s %v", roles, err)
	}
}

func TestI_AResetOfAPendingAccountVerifiesItAndWritesTheVerifiedFact(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.pend, tenant, 1, base)
	at := base.Add(time.Minute)
	if !w.reset(t, w.pend, w.live(t, w.pend, at).ID, true, false, at) {
		t.Fatal("the reset did not run")
	}
	var status string
	var verified bool
	var verifiedAt *time.Time
	if err := w.pool.QueryRow(ctx, `SELECT identity_status, email_verified, email_verified_at FROM security.identity WHERE identity_id = $1::uuid`, w.pend).Scan(&status, &verified, &verifiedAt); err != nil {
		t.Fatal(err)
	}
	if status != "ACTIVE" || !verified || verifiedAt == nil || !verifiedAt.Equal(at) {
		t.Fatalf("account = %s %v %v", status, verified, verifiedAt)
	}
	if got := w.events(t); got["AccountEmailVerified"] != 1 || got["PasswordReset"] != 1 {
		t.Fatalf("events = %v", got)
	}
	// commercial-reservation reads the tenant from the payload, not only from the envelope (spec 006, RN-SEC-006-11)
	var payloadTenant string
	if err := w.pool.QueryRow(ctx, `SELECT payload->>'tenantId' FROM security.outbox_event WHERE event_type = 'AccountEmailVerified'`).Scan(&payloadTenant); err != nil || payloadTenant != tenant {
		t.Fatalf("the payload of the fact carries the tenant %q (%v), want %q", payloadTenant, err, tenant)
	}
}

func TestI_AnActiveAccountIsNotMarkedVerifiedByAReset(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	// the use case says the account is pending but the row is not: the statement trusts the row, never the flag
	if !w.reset(t, w.ana, w.live(t, w.ana, base).ID, true, false, base) {
		t.Fatal("the reset did not run")
	}
	if w.events(t)["AccountEmailVerified"] != 0 {
		t.Fatal("an active account was announced as verified")
	}
}

func TestI_TwoResetsWithOneCodeChangeThePasswordOnce(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	code := w.live(t, w.ana, base)
	var done atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := w.tryReset(w.ana, code.ID, false, false, base.Add(time.Minute))
			if err != nil {
				t.Errorf("Reset: %v", err)
			}
			if ok {
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	if done.Load() != 1 {
		t.Fatalf("%d resets ran with one code", done.Load())
	}
	if got := w.events(t); got["PasswordReset"] != 1 || got["AccountSessionsRevoked"] != 1 {
		t.Fatalf("events = %v", got)
	}
}

func TestI_AResetWithAUsedRetiredOrExpiredCodeChangesNothing(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(w recoveryWorld, id string)
		at    time.Duration
	}{
		{"used", func(w recoveryWorld, id string) { w.reset(t, w.ana, id, false, false, base) }, time.Minute},
		{"retired", func(w recoveryWorld, id string) {
			for i := 0; i < 5; i++ {
				w.fail(t, w.ana, id, port.ReasonWrongCode, false, base)
			}
		}, time.Minute},
		{"expired", func(w recoveryWorld, id string) {}, 30 * time.Minute},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := recoverySetup(t)
			w.issue(t, w.ana, tenant, 1, base)
			var id string
			if err := w.pool.QueryRow(ctx, `SELECT recovery_id::text FROM security.recovery_code`).Scan(&id); err != nil {
				t.Fatal(err)
			}
			c.setup(w, id)
			before := w.events(t)["PasswordReset"]
			if w.reset(t, w.ana, id, false, false, base.Add(c.at)) {
				t.Fatal("the reset ran")
			}
			var hash string
			if err := w.pool.QueryRow(ctx, `SELECT password_hash FROM security.identity WHERE identity_id = $1::uuid`, w.ana).Scan(&hash); err != nil {
				t.Fatal(err)
			}
			if after := w.events(t)["PasswordReset"]; after != before {
				t.Fatalf("a fact was written: %d -> %d", before, after)
			}
			if c.name != "used" && hash == recoveredHash {
				t.Fatal("the password changed")
			}
		})
	}
}

func TestI_AResetOfAnInactiveAccountChangesNothingAndKeepsTheCode(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	var id string
	if err := w.pool.QueryRow(ctx, `SELECT recovery_id::text FROM security.recovery_code`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, w.ana); err != nil {
		t.Fatal(err)
	}
	if w.reset(t, w.ana, id, false, false, base.Add(time.Minute)) {
		t.Fatal("an inactive account was reset")
	}
	var used *time.Time
	if err := w.pool.QueryRow(ctx, `SELECT used_at FROM security.recovery_code`).Scan(&used); err != nil || used != nil {
		t.Fatalf("the code was used although nothing changed: %v %v", used, err)
	}
}

func TestI_TheCodeOfAnotherAccountResetsNothing(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	if w.reset(t, w.boss, w.live(t, w.ana, base).ID, false, false, base.Add(time.Minute)) {
		t.Fatal("the code of one account reset another")
	}
}

func TestI_TheFactNamesTheTenantOfTheAccountRowWhateverTheCallerSays(t *testing.T) {
	w := recoverySetup(t)
	ok, err := w.store.Issue(ctx, port.IssueCode{AccountID: w.ana, TenantID: "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b", Code: codeN(1, base), Now: base, Limit: 3, Window: time.Hour, CorrelationID: "c"})
	if err != nil || !ok {
		t.Fatalf("Issue: %v %v", ok, err)
	}
	w.fail(t, w.boss, "", port.ReasonRetiredCode, true, base)
	if n := w.count(t, `SELECT count(*) FROM security.outbox_event WHERE tenant_id IS DISTINCT FROM $1::uuid`, tenant); n != 0 {
		t.Fatalf("%d facts name a tenant that is not the one of their account", n)
	}
}

func TestI_ASessionsRevokedFactKeepsTheReasonInItsColumnToo(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	w.reset(t, w.ana, w.live(t, w.ana, base).ID, false, false, base.Add(time.Minute))
	if n := w.count(t, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountSessionsRevoked' AND reason = 'PASSWORD_RESET'`); n != 1 {
		t.Fatalf("the reason is not in its column: %d", n)
	}
}

func TestI_ThePlatformAdministratorResetHasNoTenantInItsFacts(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.root, "", 1, base)
	ok, err := w.store.Reset(ctx, port.ResetCommand{AccountID: w.root, CodeID: w.live(t, w.root, base).ID, NewHash: recoveredHash, Roles: []string{"PLATFORM_ADMINISTRATOR"},
		Administrative: true, Now: base.Add(time.Minute), CorrelationID: "corr-9"})
	if err != nil || !ok {
		t.Fatalf("Reset: %v %v", ok, err)
	}
	n := w.count(t, `SELECT count(*) FROM security.outbox_event WHERE tenant_id IS NOT NULL AND event_type IN ('PasswordReset', 'AccountSessionsRevoked', 'PasswordRecoveryRequested')`)
	if n != 0 {
		t.Fatalf("%d facts of the platform name a tenant", n)
	}
}

func TestI_NoFactCarriesTheCodeTheHashOrAPassword(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.boss, tenant, 1, base)
	w.fail(t, w.boss, w.live(t, w.boss, base).ID, port.ReasonWrongCode, true, base)
	w.reset(t, w.boss, w.live(t, w.boss, base).ID, false, true, base.Add(time.Minute))
	rows, err := w.pool.Query(ctx, `SELECT payload::text FROM security.outbox_event`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{codeN(1, base).HMAC, recoveredHash, pgtest.ValidHash, "newpassword", "password_hash", "passwordhash", "hmac", "code_hmac"} {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(secret)) {
				t.Fatalf("a fact carries %q: %s", secret, payload)
			}
		}
	}
}

func TestI_AFailedSendIsRecordedWithItsCauseAndAnUnknownCodeIsAnError(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.ana, tenant, 1, base)
	at := base.Add(time.Second)
	if err := w.store.MarkSendFailed(ctx, w.ana, codeN(1, base).HMAC, at, "smtp: 550 refused\x00"); err != nil {
		t.Fatal(err)
	}
	var failedAt *time.Time
	var cause string
	if err := w.pool.QueryRow(ctx, `SELECT send_failed_at, send_error FROM security.recovery_code`).Scan(&failedAt, &cause); err != nil {
		t.Fatal(err)
	}
	if failedAt == nil || !failedAt.Equal(at) || cause != "smtp: 550 refused" {
		t.Fatalf("recorded = %v %q", failedAt, cause)
	}
	if err := w.store.MarkSendFailed(ctx, w.ana, codeN(99, base).HMAC, at, "x"); err == nil {
		t.Fatal("a code that does not exist was marked")
	}
	// the same digits sent to another account are another code: marking the first account's leaves the other alone
	w.issue(t, w.boss, tenant, 1, base)
	if err := w.store.MarkSendFailed(ctx, w.boss, codeN(1, base).HMAC, at, "other"); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, `SELECT count(*) FROM security.recovery_code WHERE send_error = 'other'`); n != 1 {
		t.Fatalf("the mark reached %d rows", n)
	}
}
