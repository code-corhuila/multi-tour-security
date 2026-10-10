package postgres_test

import (
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
)

func TestI_TwentyFiveReportsAtOnceStopAtTheLimitAndGiveTheEventUpOnce(t *testing.T) {
	pool := pgtest.Open(t)
	store := postgres.NewOutbox(pool)
	id := seed(t, pool, "PENDING", base.Add(-time.Hour), base.Add(-time.Minute), tenant)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, _, err := store.Modify(ctx, id, func(e outbox.Event) outbox.Event { return e.WithFailedAttempt("boom", base, outbox.DefaultPolicy) }); err != nil {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	var attempts int
	var status string
	if err := pool.QueryRow(ctx, `SELECT attempts, status FROM security.outbox_event WHERE outbox_event_id = $1::uuid`, id).Scan(&attempts, &status); err != nil || attempts != 20 || status != "FAILED" {
		t.Fatalf("the 20th report gives the event up and the other five do not touch it: %d %s %v", attempts, status, err)
	}
}

func TestI_APublishAmongManyReportsAlwaysEndsPublishedAndNeverGoesBack(t *testing.T) {
	pool := pgtest.Open(t)
	store := postgres.NewOutbox(pool)
	id := seed(t, pool, "PENDING", base.Add(-time.Hour), base.Add(-time.Minute), tenant)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			change := func(e outbox.Event) outbox.Event { return e.WithFailedAttempt("boom", base, outbox.DefaultPolicy) }
			if i == 15 {
				change = func(e outbox.Event) outbox.Event { return e.Published(base) }
			}
			if _, _, err := store.Modify(ctx, id, change); err != nil {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	var attempts int
	var status string
	var published *time.Time
	if err := pool.QueryRow(ctx, `SELECT attempts, status, published_at FROM security.outbox_event WHERE outbox_event_id = $1::uuid`, id).Scan(&attempts, &status, &published); err != nil {
		t.Fatal(err)
	}
	if status != "PUBLISHED" || published == nil || attempts > 20 {
		t.Fatalf("a delivery that did succeed is true whatever the reports around it: %d %s %v", attempts, status, published)
	}
}
