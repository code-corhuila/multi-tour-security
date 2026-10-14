package postgres_test

import (
	"errors"
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

// the shape the table accepts, and not the one of pgtest.ValidHash
var chosenHash = "$2a$12$" + strings.Repeat("b", 53)

func temporaryAccount(t *testing.T, until time.Time) (*postgres.Accounts, *pgxpool.Pool, string) {
	t.Helper()
	pool := pgtest.Open(t)
	id, err := pgtest.AccountWith(ctx, pool, tenant, "new@example.com", pgtest.ValidHash, pgtest.Options{TemporaryUntil: until}, "TENANT_ADMINISTRATOR")
	if err != nil {
		t.Fatal(err)
	}
	return postgres.NewAccounts(pool), pool, id
}

func TestI_TheFirstPasswordReplacesTheHashClearsTheTemporaryStateAndTheLockAndCutsOffOlderSessions(t *testing.T) {
	accounts, pool, id := temporaryAccount(t, base.Add(time.Hour))
	for i := 0; i < 3; i++ {
		fail(t, accounts, id, base)
	}
	if err := accounts.ChangePassword(ctx, id, chosenHash, base.Add(time.Minute), "corr-9"); err != nil {
		t.Fatal(err)
	}
	got, found, err := accounts.FindByID(ctx, id)
	if err != nil || !found || got.PasswordHash != chosenHash || !got.TemporaryUntil.IsZero() || got.Failed != 0 || !got.FirstFailedAt.IsZero() || !got.BlockedUntil.IsZero() {
		t.Fatalf("the account after the change: %+v %v", got, err)
	}
	if from := instant(t, pool, `SELECT sessions_revoked_from FROM security.identity WHERE identity_id = $1::uuid`, id); from == nil || !from.Equal(base.Add(time.Minute)) {
		t.Fatalf("older sessions are cut off from the change: %v", from)
	}
	var tenantID, correlation string
	var occurred time.Time
	err = pool.QueryRow(ctx, `SELECT tenant_id::text, correlation_id, occurred_at FROM security.outbox_event
		WHERE event_type = 'AccountSessionsRevoked' AND aggregate_id = $1::uuid`, id).Scan(&tenantID, &correlation, &occurred)
	if err != nil || tenantID != tenant || correlation != "corr-9" || !occurred.Equal(base.Add(time.Minute)) {
		t.Fatalf("the revocation leaves its event in the same statement: %q %q %v %v", tenantID, correlation, occurred, err)
	}
	if n := events(t, pool, "AccountSessionsRevoked"); n != 1 {
		t.Fatalf("one event, got %d", n)
	}
}

func TestI_ASessionOpenedBeforeTheChangeCannotRenewAfterIt(t *testing.T) {
	accounts, pool, id := temporaryAccount(t, base.Add(time.Hour))
	sessions := postgres.NewSessions(pool)
	_, _, hash := open(t, sessions, id, base)
	if err := accounts.ChangePassword(ctx, id, chosenHash, base.Add(time.Minute), "c"); err != nil {
		t.Fatal(err)
	}
	_, next := value(t)
	if _, err := sessions.Rotate(ctx, hash, next, base.Add(2*time.Minute)); !errors.Is(err, port.ErrRefreshInvalid) {
		t.Fatalf("a session of the old password cannot renew, got %v", err)
	}
}

func TestI_APasswordIsChangedOnlyWhileTheTemporaryCredentialIsInForce(t *testing.T) {
	cases := map[string]struct {
		until time.Time
		at    time.Time
	}{
		"expired exactly now": {base, base},
		"expired before":      {base.Add(-time.Hour), base},
		"never was temporary": {time.Time{}, base},
	}
	for name, c := range cases {
		accounts, pool, id := temporaryAccount(t, c.until)
		err := accounts.ChangePassword(ctx, id, chosenHash, c.at, "c")
		if !errors.Is(err, port.ErrNotTemporary) {
			t.Errorf("%s: %v", name, err)
		}
		got, _, _ := accounts.FindByID(ctx, id)
		if got.PasswordHash != pgtest.ValidHash || events(t, pool, "AccountSessionsRevoked") != 0 {
			t.Errorf("%s: a refused change left a mark: %+v", name, got)
		}
	}
	accounts, _, _ := temporaryAccount(t, base.Add(time.Hour))
	if err := accounts.ChangePassword(ctx, missingID, chosenHash, base, "c"); !errors.Is(err, port.ErrNotTemporary) {
		t.Errorf("a missing account has no temporary credential in force: %v", err)
	}
}

func TestI_ARefusedEventOrAHashThatIsNotOneLeavesThePasswordAsItWas(t *testing.T) {
	for name, c := range map[string]struct{ hash, correlation string }{
		"empty correlation id":  {chosenHash, ""},
		"correlation id of 129": {chosenHash, strings.Repeat("c", 129)},
		"a password in clear":   {"plain-password", "c"},
	} {
		accounts, pool, id := temporaryAccount(t, base.Add(time.Hour))
		if err := accounts.ChangePassword(ctx, id, c.hash, base, c.correlation); err == nil {
			t.Errorf("%s: the change was accepted", name)
		}
		got, _, _ := accounts.FindByID(ctx, id)
		if got.PasswordHash != pgtest.ValidHash || got.TemporaryUntil.IsZero() || events(t, pool, "AccountSessionsRevoked") != 0 {
			t.Errorf("%s: the change was half done: %+v", name, got)
		}
	}
}

func TestI_TwoChangesAtOnceMakeOneWinnerAndOneRefusal(t *testing.T) {
	accounts, _, id := temporaryAccount(t, base.Add(time.Hour))
	start := make(chan struct{})
	var wg sync.WaitGroup
	var won, lost atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch err := accounts.ChangePassword(ctx, id, chosenHash, base, "c"); {
			case err == nil:
				won.Add(1)
			case errors.Is(err, port.ErrNotTemporary):
				lost.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if won.Load() != 1 || lost.Load() != 7 {
		t.Fatalf("one winner and seven refusals, got %d and %d", won.Load(), lost.Load())
	}
}
