package postgres_test

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/session"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func sessionsSetup(t *testing.T) (*postgres.Sessions, *pgxpool.Pool, string) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewSessions(pool), pool, pgtest.MustAccount(t, pool, tenant, "ana@example.com", "TENANT_ADMINISTRATOR")
}

func value(t *testing.T) (string, string) {
	t.Helper()
	v, h, err := session.NewRefreshValue()
	if err != nil {
		t.Fatal(err)
	}
	return v, h
}

func open(t *testing.T, s *postgres.Sessions, account string, at time.Time) (id, plain, hash string) {
	t.Helper()
	plain, hash = value(t)
	id, err := s.Open(ctx, account, hash, at)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return id, plain, hash
}

// count runs a query that gives one number and fails the test when the query itself fails, so that a typo in a
// column cannot make an assertion of "zero" pass.
func count(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func instant(t *testing.T, pool *pgxpool.Pool, query string, args ...any) *time.Time {
	t.Helper()
	var at *time.Time
	if err := pool.QueryRow(ctx, query, args...).Scan(&at); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return at
}

func TestI_ASessionIsOpenedForSevenDaysAndOnlyTheHashOfItsValueIsStored(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	id, plain, hash := open(t, sessions, account, base)
	var created, expires, valueExpires time.Time
	var stored string
	err := pool.QueryRow(ctx, `SELECT s.created_at, s.expires_at, r.expires_at, r.token_hash FROM security.session s
		JOIN security.refresh_token r USING (session_id) WHERE s.session_id = $1::uuid`, id).Scan(&created, &expires, &valueExpires, &stored)
	if err != nil || !created.Equal(base) || !expires.Equal(base.Add(session.Life)) || !valueExpires.Equal(expires) || stored != hash {
		t.Fatalf("the session starts at the instant given, lasts 7 days and keeps the hash: %v %v %v %q %v", created, expires, valueExpires, stored, err)
	}
	for _, table := range []string{"session", "refresh_token", "outbox_event", "identity"} {
		if n := count(t, pool, `SELECT count(*) FROM security.`+table+` t WHERE t::text LIKE '%' || $1 || '%'`, plain); n != 0 {
			t.Errorf("the value in clear appears in %s", table)
		}
	}
}

func TestI_ARenewalStoresTheNextHashConsumesTheOldOneAndKeepsTheEndOfTheSession(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	id, _, hash := open(t, sessions, account, base)
	_, next := value(t)
	at := base.Add(time.Hour)
	got, err := sessions.Rotate(ctx, hash, next, at)
	if err != nil || got.AccountID != account || got.SessionID != id {
		t.Fatalf("Rotate = %+v, %v", got, err)
	}
	if consumed := instant(t, pool, `SELECT consumed_at FROM security.refresh_token WHERE token_hash = $1`, hash); consumed == nil || !consumed.Equal(at) {
		t.Fatalf("the old value is consumed at the instant of the renewal, got %v", consumed)
	}
	var expires, sessionExpires time.Time
	if err := pool.QueryRow(ctx, `SELECT r.expires_at, s.expires_at FROM security.refresh_token r JOIN security.session s USING (session_id)
		WHERE r.token_hash = $1 AND r.consumed_at IS NULL`, next).Scan(&expires, &sessionExpires); err != nil {
		t.Fatalf("the next hash must be the one alive: %v", err)
	}
	if !expires.Equal(sessionExpires) || !sessionExpires.Equal(base.Add(session.Life)) {
		t.Fatalf("a renewal does not slide the session: value %v session %v", expires, sessionExpires)
	}
}

func TestI_TheSecondUseOfAValueIsRefusedAndRevokesOnlyThatSession(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	idA, _, hashA := open(t, sessions, account, base)
	_, _, hashB := open(t, sessions, account, base)
	_, next := value(t)
	if _, err := sessions.Rotate(ctx, hashA, next, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reuse := base.Add(2 * time.Minute)
	_, other := value(t)
	if _, err := sessions.Rotate(ctx, hashA, other, reuse); !errors.Is(err, port.ErrRefreshReused) {
		t.Fatalf("a consumed value used again is ErrRefreshReused, got %v", err)
	}
	if revoked := instant(t, pool, `SELECT revoked_at FROM security.session WHERE session_id = $1::uuid`, idA); revoked == nil || !revoked.Equal(reuse) {
		t.Fatalf("the reuse leaves the session revoked at its instant although the call failed, got %v", revoked)
	}
	_, third := value(t)
	if _, err := sessions.Rotate(ctx, next, third, base.Add(3*time.Minute)); !errors.Is(err, port.ErrRefreshInvalid) {
		t.Fatalf("the value that was alive in the revoked session no longer renews, got %v", err)
	}
	_, fourth := value(t)
	if _, err := sessions.Rotate(ctx, hashB, fourth, base.Add(4*time.Minute)); err != nil {
		t.Fatalf("the other session of the account is not touched, got %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM security.outbox_event`); n != 0 {
		t.Fatalf("a reuse revokes one session and writes no cutoff event, got %d", n)
	}
}

func TestI_ReusingAConsumedValueIsReusedEvenWhenTheSessionIsAlreadyRevokedOrExpired(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	id, _, hash := open(t, sessions, account, base)
	_, next := value(t)
	if _, err := sessions.Rotate(ctx, hash, next, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	first := base.Add(2 * time.Minute)
	if _, err := pool.Exec(ctx, `UPDATE security.session SET revoked_at = $2 WHERE session_id = $1::uuid`, id, first); err != nil {
		t.Fatal(err)
	}
	_, other := value(t)
	if _, err := sessions.Rotate(ctx, hash, other, base.Add(3*time.Minute)); !errors.Is(err, port.ErrRefreshReused) {
		t.Errorf("a consumed value is Reused in a revoked session, got %v", err)
	}
	if revoked := instant(t, pool, `SELECT revoked_at FROM security.session WHERE session_id = $1::uuid`, id); !revoked.Equal(first) {
		t.Errorf("the first revocation stands, got %v", revoked)
	}
	if _, err := sessions.Rotate(ctx, hash, other, base.Add(session.Life+time.Hour)); !errors.Is(err, port.ErrRefreshReused) {
		t.Errorf("a consumed value is Reused in an expired session, got %v", err)
	}
}

func TestI_AnExpiredValueAnExpiredSessionAndAnUnknownValueAreInvalidAndConsumeNothing(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	id, _, hash := open(t, sessions, account, base)
	_, next := value(t)
	if _, err := sessions.Rotate(ctx, hash, next, base.Add(session.Life)); !errors.Is(err, port.ErrRefreshInvalid) {
		t.Errorf("at the exact end of the session the value is invalid, got %v", err)
	}
	if consumed := instant(t, pool, `SELECT consumed_at FROM security.refresh_token WHERE token_hash = $1`, hash); consumed != nil {
		t.Errorf("a refused renewal consumes nothing, got %v", consumed)
	}
	if revoked := instant(t, pool, `SELECT revoked_at FROM security.session WHERE session_id = $1::uuid`, id); revoked != nil {
		t.Errorf("an expired value is not a reuse and revokes nothing, got %v", revoked)
	}
	if _, err := sessions.Rotate(ctx, hash, next, base.Add(session.Life-time.Second)); err != nil {
		t.Errorf("one second before the end it still renews, got %v", err)
	}
	_, unknown := value(t)
	_, again := value(t)
	if _, err := sessions.Rotate(ctx, unknown, again, base); !errors.Is(err, port.ErrRefreshInvalid) {
		t.Errorf("an unknown value is invalid, got %v", err)
	}
	if _, err := sessions.Rotate(ctx, "not-a-hash", again, base); !errors.Is(err, port.ErrRefreshInvalid) {
		t.Errorf("a value that is not a hash is invalid, got %v", err)
	}
}

func TestI_ARevokedSessionCannotRenew(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	id, _, hash := open(t, sessions, account, base)
	if _, err := pool.Exec(ctx, `UPDATE security.session SET revoked_at = $2 WHERE session_id = $1::uuid`, id, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, next := value(t)
	if _, err := sessions.Rotate(ctx, hash, next, base.Add(time.Hour)); !errors.Is(err, port.ErrRefreshInvalid) {
		t.Fatalf("a revoked session is invalid, got %v", err)
	}
}

func TestI_ASessionOpenedUpToTheCutoffCannotRenewAndOneOpenedAfterIt(t *testing.T) {
	sessions, _, account := sessionsSetup(t)
	cutoff := base.Add(time.Hour)
	_, _, before := open(t, sessions, account, cutoff.Add(-time.Second))
	_, _, exact := open(t, sessions, account, cutoff)
	_, _, after := open(t, sessions, account, cutoff.Add(time.Microsecond))
	if err := sessions.RevokeAll(ctx, account, cutoff, "corr-1"); err != nil {
		t.Fatal(err)
	}
	for name, hash := range map[string]string{"one second before": before, "exactly at": exact} {
		_, next := value(t)
		if _, err := sessions.Rotate(ctx, hash, next, cutoff.Add(time.Minute)); !errors.Is(err, port.ErrRefreshInvalid) {
			t.Errorf("a session opened %s the cutoff cannot renew, got %v", name, err)
		}
	}
	_, next := value(t)
	if _, err := sessions.Rotate(ctx, after, next, cutoff.Add(time.Minute)); err != nil {
		t.Errorf("a session opened after the cutoff renews, got %v", err)
	}
}

func TestI_AnInactiveAccountCannotRenewAndItsValueIsNotConsumed(t *testing.T) {
	pool := pgtest.Open(t)
	sessions := postgres.NewSessions(pool)
	id, err := pgtest.Account(ctx, pool, tenant, "off@example.com", pgtest.ValidHash, "ANALYST")
	if err != nil {
		t.Fatal(err)
	}
	sid, _, hash := open(t, sessions, id, base)
	if _, err := pool.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	_, next := value(t)
	if _, err := sessions.Rotate(ctx, hash, next, base.Add(time.Minute)); !errors.Is(err, port.ErrRefreshInvalid) {
		t.Fatalf("an inactive account cannot renew, got %v", err)
	}
	if consumed := instant(t, pool, `SELECT consumed_at FROM security.refresh_token WHERE token_hash = $1`, hash); consumed != nil {
		t.Errorf("the refused renewal consumed the value: %v", consumed)
	}
	if revoked := instant(t, pool, `SELECT revoked_at FROM security.session WHERE session_id = $1::uuid`, sid); revoked != nil {
		t.Errorf("an inactive account is Invalid and not a reuse: %v", revoked)
	}
}

func TestI_ARenewalThatCannotStoreItsNextValueLeavesTheOldOneAlive(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	_, _, hash := open(t, sessions, account, base)
	_, taken := value(t)
	if _, err := sessions.Open(ctx, account, taken, base); err != nil {
		t.Fatal(err)
	}
	for name, next := range map[string]string{"not a hash": "short", "the old hash": hash, "a hash already stored": taken} {
		if _, err := sessions.Rotate(ctx, hash, next, base.Add(time.Minute)); err == nil {
			t.Errorf("a renewal with %s as the next value succeeded", name)
		}
	}
	if consumed := instant(t, pool, `SELECT consumed_at FROM security.refresh_token WHERE token_hash = $1`, hash); consumed != nil {
		t.Errorf("a failed renewal consumed the old value: %v", consumed)
	}
	if n := count(t, pool, `SELECT count(*) FROM security.refresh_token`); n != 2 {
		t.Errorf("a failed renewal stored a value: %d rows", n)
	}
}

func TestI_TheCutoffAndItsEventAreWrittenTogetherForATenantAccountAndAPlatformAccount(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	root := pgtest.MustAccount(t, pool, "", "root@example.com", "PLATFORM_ADMINISTRATOR")
	cutoff := base.Add(time.Hour)
	for _, id := range []string{account, root} {
		if err := sessions.RevokeAll(ctx, id, cutoff, "corr-1"); err != nil {
			t.Fatal(err)
		}
		if from := instant(t, pool, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id); from == nil || !from.Equal(cutoff) {
			t.Fatalf("the cutoff of %s is %v", id, from)
		}
	}
	var tenantID *string
	var version int
	var occurred time.Time
	var correlation, status, payload string
	err := pool.QueryRow(ctx, `SELECT tenant_id::text, event_version, occurred_at, correlation_id, status, payload::text FROM security.outbox_event
		WHERE event_type = 'AccountSessionsRevoked' AND aggregate_id = $1::uuid`, account).Scan(&tenantID, &version, &occurred, &correlation, &status, &payload)
	if err != nil || tenantID == nil || *tenantID != tenant || version != 1 || !occurred.Equal(cutoff) || correlation != "corr-1" || status != "PENDING" {
		t.Fatalf("event of the tenant account: %v %v %v %v %q %q %v", tenantID, version, occurred, correlation, status, payload, err)
	}
	var body struct {
		AccountID, RevokedFrom string
	}
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		t.Fatal(err)
	}
	if at, err := time.Parse(time.RFC3339Nano, body.RevokedFrom); err != nil || !at.Equal(cutoff) || !strings.HasSuffix(body.RevokedFrom, "Z") {
		t.Fatalf("the payload names the cutoff in UTC: %q %v", body.RevokedFrom, err)
	}
	for _, secret := range []string{"ana@example.com", pgtest.ValidHash} {
		if strings.Contains(payload, secret) {
			t.Fatalf("the payload carries %q", secret)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountSessionsRevoked'
		AND aggregate_id = $1::uuid AND tenant_id IS NULL`, root); n != 1 {
		t.Fatalf("a platform account leaves one event with no tenant, got %d", n)
	}
}

func TestI_ARefusedEventLeavesNoCutoffAndAMissingAccountIsReported(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	for _, correlation := range []string{"", strings.Repeat("c", 129)} {
		if err := sessions.RevokeAll(ctx, account, base, correlation); err == nil {
			t.Fatalf("a correlation id of %d characters was accepted", len(correlation))
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM security.identity WHERE sessions_revoked_from IS NOT NULL`); n != 0 {
		t.Fatalf("the cutoff was written although its event was refused: %d", n)
	}
	if err := sessions.RevokeAll(ctx, missingID, base, "c"); !errors.Is(err, postgres.ErrAccountNotFound) {
		t.Fatalf("revoking a missing account is ErrAccountNotFound, got %v", err)
	}
}

func TestI_ACutoffNeverMovesBackwardsAndEveryCallLeavesItsEventWithTheEffectiveCutoff(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	later := base.Add(2 * time.Hour)
	for _, cutoff := range []time.Time{later, base, later} {
		if err := sessions.RevokeAll(ctx, account, cutoff, "c"); err != nil {
			t.Fatal(err)
		}
	}
	if from := instant(t, pool, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, account); !from.Equal(later) {
		t.Fatalf("an older cutoff must not lift a newer one, got %v", from)
	}
	if n := count(t, pool, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountSessionsRevoked'`); n != 3 {
		t.Fatalf("each call leaves its event (the event is safe to repeat), got %d", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM security.outbox_event WHERE payload->>'revokedFrom' LIKE '2026-10-10T12:00:00%'`); n != 3 {
		t.Fatalf("every event names the cutoff in force, got %d", n)
	}
}

func TestI_ConcurrentRenewalsOfOneValueGiveOneWinnerAndNineReuses(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	id, _, hash := open(t, sessions, account, base)
	hashes := make([]string, 10)
	for i := range hashes {
		_, hashes[i] = value(t)
	}
	var wins, reused atomic.Int32
	var wg sync.WaitGroup
	for _, next := range hashes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch _, err := sessions.Rotate(ctx, hash, next, base.Add(time.Minute)); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, port.ErrRefreshReused):
				reused.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || reused.Load() != 9 {
		t.Fatalf("one winner and nine reuses, got %d and %d", wins.Load(), reused.Load())
	}
	if revoked := instant(t, pool, `SELECT revoked_at FROM security.session WHERE session_id = $1::uuid`, id); revoked == nil {
		t.Error("the losers detected the reuse and the session must be revoked")
	}
	if n := count(t, pool, `SELECT count(*) FROM security.refresh_token`); n != 2 {
		t.Errorf("only the winner stored a value, got %d rows", n)
	}
}

func TestI_TheTablesRefuseAValueThatIsNotAHashAndASessionForAMissingAccount(t *testing.T) {
	sessions, pool, account := sessionsSetup(t)
	code := func(err error) string {
		var pg *pgconn.PgError
		if errors.As(err, &pg) {
			return pg.Code
		}
		return "not a PostgreSQL error: " + errString(err)
	}
	if _, err := sessions.Open(ctx, account, "a-clear-value", base); code(err) != "23514" {
		t.Errorf("a value that is not a hash must break the CHECK (23514), got %s", code(err))
	}
	if n := count(t, pool, `SELECT count(*) FROM security.session`); n != 0 {
		t.Errorf("the session of a refused value must not remain: %d", n)
	}
	if _, err := sessions.Open(ctx, missingID, session.Hash("x"), base); code(err) != "23503" {
		t.Errorf("a session for a missing account must break the foreign key (23503), got %s", code(err))
	}
}
