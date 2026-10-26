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

// The tests below cover the store of the verification links (spec 004-hu-sec-003, RN-SEC-004-02, -04 to -08).

func TestI_ActivationAndTheFactAreWrittenTogether(t *testing.T) {
	store, pool, id := verificationSetup(t)
	l := linkN(1, base)
	issue(t, store, id, l, base)
	at := base.Add(time.Hour)
	done, err := store.Confirm(ctx, l.TokenHash, at, "corr-77")
	if err != nil || !done {
		t.Fatalf("Confirm: %v %v", done, err)
	}
	var status string
	var verified bool
	var verifiedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT identity_status, email_verified, email_verified_at FROM security.identity WHERE identity_id = $1::uuid`, id).
		Scan(&status, &verified, &verifiedAt); err != nil {
		t.Fatal(err)
	}
	if status != "ACTIVE" || !verified || verifiedAt == nil || !verifiedAt.Equal(at) {
		t.Fatalf("account = %s verified=%v at=%v", status, verified, verifiedAt)
	}
	state, _, _ := store.Find(ctx, l.TokenHash)
	if !state.UsedAt.Equal(at) {
		t.Fatalf("used at %v, want %v", state.UsedAt, at)
	}
	var kind, correlation, payload string
	var eventTenant, aggregate string
	var happened time.Time
	if err := pool.QueryRow(ctx, `SELECT event_type, tenant_id::text, aggregate_id::text, correlation_id, payload::text, occurred_at
		FROM security.outbox_event`).Scan(&kind, &eventTenant, &aggregate, &correlation, &payload, &happened); err != nil {
		t.Fatalf("exactly one event is written: %v", err)
	}
	if kind != "AccountEmailVerified" || eventTenant != tenant || aggregate != id || correlation != "corr-77" || !happened.Equal(at) {
		t.Fatalf("event = %s %s %s %s %v", kind, eventTenant, aggregate, correlation, happened)
	}
	for _, want := range []string{id, "ana@example.com"} {
		if !strings.Contains(payload, want) {
			t.Fatalf("payload %s lacks %s", payload, want)
		}
	}
	if strings.Contains(payload, l.TokenHash) || strings.Contains(payload, "token") || strings.Contains(payload, "password") {
		t.Fatalf("the fact carries no link and no password: %s", payload)
	}
}

func TestI_ALinkThatDoesNotWorkChangesNothing(t *testing.T) {
	setups := map[string]func(*postgres.Verifications, *pgxpool.Pool, string, port.NewLink){
		"used": func(s *postgres.Verifications, _ *pgxpool.Pool, _ string, l port.NewLink) {
			if done, err := s.Confirm(ctx, l.TokenHash, base.Add(time.Minute), "c"); err != nil || !done {
				t.Fatalf("first use: %v %v", done, err)
			}
		},
		"replaced": func(s *postgres.Verifications, _ *pgxpool.Pool, id string, _ port.NewLink) {
			issue(t, s, id, linkN(2, base.Add(time.Minute)), base.Add(time.Minute))
		},
		"inactive account": func(_ *postgres.Verifications, p *pgxpool.Pool, id string, _ port.NewLink) {
			if _, err := p.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, id); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range setups {
		store, pool, id := verificationSetup(t)
		l := linkN(1, base)
		issue(t, store, id, l, base)
		setup(store, pool, id, l)
		before := rows(t, pool, "outbox_event")
		done, err := store.Confirm(ctx, l.TokenHash, base.Add(2*time.Minute), "c")
		if err != nil || done {
			t.Fatalf("%s: Confirm = %v, %v, want a plain no", name, done, err)
		}
		if after := rows(t, pool, "outbox_event"); after != before {
			t.Fatalf("%s: a refusal wrote an event", name)
		}
	}
}

func TestI_AnExpiredOrUnknownLinkChangesNothing(t *testing.T) {
	store, pool, id := verificationSetup(t)
	l := linkN(1, base)
	issue(t, store, id, l, base)
	for name, c := range map[string]struct {
		hash string
		at   time.Time
	}{
		"expired":              {l.TokenHash, l.ExpiresAt.Add(time.Second)},
		"expiring exactly now": {l.TokenHash, l.ExpiresAt},
		"unknown":              {linkN(99, base).TokenHash, base.Add(time.Minute)},
	} {
		done, err := store.Confirm(ctx, c.hash, c.at, "c")
		if err != nil || done {
			t.Fatalf("%s: Confirm = %v, %v", name, done, err)
		}
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT identity_status FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&status); err != nil || status != "PENDING" {
		t.Fatalf("the account must stay pending: %s %v", status, err)
	}
	if rows(t, pool, "outbox_event") != 0 {
		t.Fatal("a refusal wrote an event")
	}
}

func TestI_TwoConfirmationsOfOneLinkActivateOnce(t *testing.T) {
	store, pool, id := verificationSetup(t)
	l := linkN(1, base)
	issue(t, store, id, l, base)
	var done atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.Confirm(ctx, l.TokenHash, base.Add(time.Minute), "c")
			if err != nil {
				t.Error(err)
			}
			if ok {
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	if done.Load() != 1 || rows(t, pool, "outbox_event") != 1 {
		t.Fatalf("%d confirmations won and %d events were written, want one of each", done.Load(), rows(t, pool, "outbox_event"))
	}
}

func TestI_TheFailureOfASendIsStoredWithoutTheLink(t *testing.T) {
	store, pool, id := verificationSetup(t)
	l := linkN(1, base)
	issue(t, store, id, l, base)
	at := base.Add(time.Minute)
	if err := store.MarkSendFailed(ctx, l.TokenHash, at, "smtp: connection refused"); err != nil {
		t.Fatal(err)
	}
	var failedAt *time.Time
	var cause *string
	if err := pool.QueryRow(ctx, `SELECT send_failed_at, send_error FROM security.email_verification`).Scan(&failedAt, &cause); err != nil {
		t.Fatal(err)
	}
	if failedAt == nil || !failedAt.Equal(at) || cause == nil || *cause != "smtp: connection refused" {
		t.Fatalf("failure = %v %v", failedAt, cause)
	}
	if err := store.MarkSendFailed(ctx, linkN(99, base).TokenHash, at, "x"); err == nil {
		t.Fatal("recording a failure of a link that does not exist must be an error, not a silent no")
	}
}

func TestI_ALinkAskedForWhileAnotherIsConfirmedNeverDeadlocksAndEndsConsistent(t *testing.T) {
	pool := pgtest.Open(t)
	store := postgres.NewVerifications(pool)
	for round := 0; round < 12; round++ {
		id, err := pgtest.AccountWith(ctx, pool, tenant, fmt.Sprintf("r%d@example.com", round), pgtest.ValidHash, pgtest.Options{Pending: true}, "FINAL_CUSTOMER")
		if err != nil {
			t.Fatal(err)
		}
		first, second := linkN(1000+round*2, base), linkN(1001+round*2, base)
		issue(t, store, id, first, base)
		var wg sync.WaitGroup
		var confirmed, reissued bool
		wg.Add(2)
		go func() {
			defer wg.Done()
			ok, err := store.Confirm(ctx, first.TokenHash, base.Add(time.Minute), "c")
			if err != nil {
				t.Errorf("round %d: Confirm: %v", round, err)
			}
			confirmed = ok
		}()
		go func() {
			defer wg.Done()
			ok, err := store.Issue(ctx, id, second, base.Add(time.Minute), 3, time.Hour)
			if err != nil {
				t.Errorf("round %d: Issue: %v", round, err)
			}
			reissued = ok
		}()
		wg.Wait()
		if confirmed == reissued {
			t.Fatalf("round %d: confirmed=%v reissued=%v: exactly one may win, the other must find the account already changed", round, confirmed, reissued)
		}
	}
}

func TestI_AnAccountThatBecomesInactiveWhileItsLinkIsConfirmedStaysInactive(t *testing.T) {
	store, pool, id := verificationSetup(t)
	l := linkN(1, base)
	issue(t, store, id, l, base)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	result := make(chan bool, 1)
	go func() {
		ok, err := store.Confirm(ctx, l.TokenHash, base.Add(time.Minute), "c")
		if err != nil {
			t.Error(err)
		}
		result <- ok
	}()
	time.Sleep(300 * time.Millisecond) // the confirmation is now waiting for the row that the transaction holds
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if <-result {
		t.Fatal("a link verified an account that was inactivated at the same time")
	}
	var status string
	var verified bool
	if err := pool.QueryRow(ctx, `SELECT identity_status, email_verified FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&status, &verified); err != nil {
		t.Fatal(err)
	}
	if status != "INACTIVE" || verified || rows(t, pool, "outbox_event") != 0 {
		t.Fatalf("status=%s verified=%v events=%d: nothing may change", status, verified, rows(t, pool, "outbox_event"))
	}
	state, _, _ := store.Find(ctx, l.TokenHash)
	if !state.UsedAt.IsZero() {
		t.Fatal("a refused confirmation must not burn the link")
	}
}

func TestI_ARefusedConfirmationLeavesTheAccountPendingAndTheLinkUnused(t *testing.T) {
	store, pool, id := verificationSetup(t)
	l := linkN(1, base)
	issue(t, store, id, l, base)
	if done, err := store.Confirm(ctx, l.TokenHash, l.ExpiresAt, "c"); err != nil || done {
		t.Fatalf("Confirm = %v %v", done, err)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT identity_status FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&status); err != nil || status != "PENDING" {
		t.Fatalf("status = %s %v", status, err)
	}
	if state, _, _ := store.Find(ctx, l.TokenHash); !state.UsedAt.IsZero() {
		t.Fatal("an expired link must not be marked used")
	}
}

func TestI_ACauseWithAnEmbeddedNulIsStoredWithoutIt(t *testing.T) {
	store, pool, id := verificationSetup(t)
	l := linkN(1, base)
	issue(t, store, id, l, base)
	if err := store.MarkSendFailed(ctx, l.TokenHash, base, "refused\x00by server"); err != nil {
		t.Fatalf("a failed send must be recorded even when the cause has a NUL: %v", err)
	}
	var cause string
	if err := pool.QueryRow(ctx, `SELECT send_error FROM security.email_verification`).Scan(&cause); err != nil || cause != "refusedby server" {
		t.Fatalf("cause = %q %v", cause, err)
	}
}
