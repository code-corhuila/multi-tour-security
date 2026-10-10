package postgres_test

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
	"github.com/jackc/pgx/v5/pgxpool"
)

func seed(t *testing.T, pool *pgxpool.Pool, status string, occurred, next time.Time, tenantID string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx, `INSERT INTO security.outbox_event (tenant_id, event_type, aggregate_id, payload, correlation_id, occurred_at, status, next_attempt_at)
		VALUES (NULLIF($1, '')::uuid, 'AccountBlocked', gen_random_uuid(), '{"accountId":"a"}'::jsonb, 'corr', $2, $3, $4) RETURNING outbox_event_id::text`,
		tenantID, occurred, status, next).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestI_TheListGivesTheDuePendingEventsTheOneDueForLongestFirstWithItsTotal(t *testing.T) {
	pool := pgtest.Open(t)
	store := postgres.NewOutbox(pool)
	late := seed(t, pool, "PENDING", base.Add(-time.Hour), base.Add(-time.Minute), tenant)
	oldest := seed(t, pool, "PENDING", base.Add(-3*time.Hour), base.Add(-time.Hour), "")
	sameDueOlder := seed(t, pool, "PENDING", base.Add(-4*time.Hour), base.Add(-time.Minute), tenant)
	seed(t, pool, "PENDING", base.Add(-time.Hour), base.Add(time.Minute), tenant) // not due yet
	seed(t, pool, "PUBLISHED", base.Add(-time.Hour), base.Add(-time.Hour), tenant)
	seed(t, pool, "FAILED", base.Add(-time.Hour), base.Add(-time.Hour), tenant)

	events, total, err := store.ListDue(ctx, base, 1, 20)
	if err != nil || total != 3 || len(events) != 3 {
		t.Fatalf("total %d, %d events: %v", total, len(events), err)
	}
	if events[0].ID != oldest || events[1].ID != sameDueOlder || events[2].ID != late {
		t.Fatalf("order by next attempt, then by the time it happened: %s %s %s", events[0].ID, events[1].ID, events[2].ID)
	}
	if events[0].TenantID != "" || events[2].TenantID != tenant || events[0].Status != outbox.Pending || events[0].Version != 1 {
		t.Fatalf("mapping: %+v %+v", events[0], events[2])
	}
	var payload map[string]string
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil || payload["accountId"] != "a" {
		t.Fatalf("payload = %s %v", events[0].Payload, err)
	}
}

func TestI_ThePagesAreDisjointAndTheLastOneIsShort(t *testing.T) {
	pool := pgtest.Open(t)
	store := postgres.NewOutbox(pool)
	for i := 0; i < 5; i++ {
		seed(t, pool, "PENDING", base.Add(-time.Hour), base.Add(-time.Duration(i+1)*time.Minute), tenant)
	}
	seen := map[string]bool{}
	for page, want := range map[int]int{1: 2, 2: 2, 3: 1, 4: 0} {
		events, total, err := store.ListDue(ctx, base, page, 2)
		if err != nil || total != 5 || len(events) != want {
			t.Fatalf("page %d: %d events, total %d: %v", page, len(events), total, err)
		}
		for _, e := range events {
			if seen[e.ID] {
				t.Fatalf("event %s is on two pages", e.ID)
			}
			seen[e.ID] = true
		}
	}
}

func TestI_TheEventsTheServiceWritesItselfAreTheOnesTheListGives(t *testing.T) {
	accounts, pool, id := setup(t)
	for i := 0; i < 5; i++ {
		fail(t, accounts, id, base.Add(time.Duration(i)*time.Second))
	}
	// the event is due from the instant the database wrote it, which is its own clock and not the one of the test
	events, total, err := postgres.NewOutbox(pool).ListDue(ctx, time.Now().Add(time.Minute), 1, 20)
	if err != nil || total != 1 || events[0].Type != "AccountBlocked" || events[0].AggregateID != id || events[0].TenantID != tenant || events[0].CorrelationID != "corr-1" {
		t.Fatalf("%+v %d %v", events, total, err)
	}
}

func TestI_AnEventIsChangedUnderItsRowLockSoConcurrentReportsAreAllCounted(t *testing.T) {
	pool := pgtest.Open(t)
	store := postgres.NewOutbox(pool)
	id := seed(t, pool, "PENDING", base.Add(-time.Hour), base.Add(-time.Minute), tenant)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, found, err := store.Modify(ctx, id, func(e outbox.Event) outbox.Event {
				return e.WithFailedAttempt("boom", base, outbox.DefaultPolicy)
			}); err != nil || !found {
				t.Errorf("%v %v", found, err)
			}
		}()
	}
	wg.Wait()
	var attempts int
	var status string
	if err := pool.QueryRow(ctx, `SELECT attempts, status FROM security.outbox_event WHERE outbox_event_id = $1::uuid`, id).Scan(&attempts, &status); err != nil || attempts != 12 || status != "PENDING" {
		t.Fatalf("twelve reports at once are twelve attempts: %d %s %v", attempts, status, err)
	}
}

func TestI_TheTwentiethAttemptMarksTheEventFailedAndAPublishedOneStaysPublished(t *testing.T) {
	pool := pgtest.Open(t)
	store := postgres.NewOutbox(pool)
	id := seed(t, pool, "PENDING", base.Add(-time.Hour), base.Add(-time.Minute), "")
	var last outbox.Event
	for i := 0; i < 20; i++ {
		var err error
		if last, _, err = store.Modify(ctx, id, func(e outbox.Event) outbox.Event { return e.WithFailedAttempt("boom", base, outbox.DefaultPolicy) }); err != nil {
			t.Fatal(err)
		}
	}
	if last.Status != outbox.Failed || last.Attempts != 20 || last.LastError != "boom" {
		t.Fatalf("%+v", last)
	}
	published, _, err := store.Modify(ctx, id, func(e outbox.Event) outbox.Event { return e.Published(base) })
	if err != nil || published.Status != outbox.Published || published.PublishedAt.IsZero() {
		t.Fatalf("a delivery that did succeed is true: %+v %v", published, err)
	}
	if again, _, _ := store.Modify(ctx, id, func(e outbox.Event) outbox.Event { return e.WithFailedAttempt("late", base, outbox.DefaultPolicy) }); again.Attempts != 20 || again.LastError != "boom" {
		t.Fatalf("a late report does not touch it: %+v", again)
	}
}

func TestI_AnEventThatDoesNotExistIsNotFoundAndAnIdThatIsNotAUUIDIsAnError(t *testing.T) {
	store := postgres.NewOutbox(pgtest.Open(t))
	if _, found, err := store.Modify(ctx, missingID, func(e outbox.Event) outbox.Event { return e }); found || err != nil {
		t.Fatalf("a missing event is found=false with no error: %v %v", found, err)
	}
	if _, found, err := store.Modify(ctx, "not-a-uuid", func(e outbox.Event) outbox.Event { return e }); found || err == nil {
		t.Fatalf("an id that is not a UUID is an error and not a silent miss: %v %v", found, err)
	}
}
