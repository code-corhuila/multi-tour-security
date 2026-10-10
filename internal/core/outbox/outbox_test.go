package outbox_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
)

const eventID = "6b9f2c1e-7a3d-4c58-9e10-2f4a8b7c6d5e"

var now = time.Date(2026, 10, 10, 10, 0, 0, 123456789, time.UTC)

func pending(attempts int) outbox.Event {
	return outbox.Event{ID: eventID, Type: "AccountBlocked", Version: 1, AggregateID: eventID, CorrelationID: "c",
		OccurredAt: now.Add(-time.Hour), Status: outbox.Pending, Attempts: attempts, NextAttemptAt: now}
}

func TestD_TheWaitAfterAFailureDoublesFrom5SecondsUpTo15Minutes(t *testing.T) {
	want := map[int]time.Duration{0: 5 * time.Second, 1: 5 * time.Second, 2: 10 * time.Second, 3: 20 * time.Second, 4: 40 * time.Second,
		5: 80 * time.Second, 8: 640 * time.Second, 9: 15 * time.Minute, 19: 15 * time.Minute, 500: 15 * time.Minute}
	for attempts, wait := range want {
		if got := outbox.DefaultPolicy.WaitAfter(attempts); got != wait {
			t.Errorf("after %d attempts the wait is %v, want %v", attempts, got, wait)
		}
	}
	if p := outbox.DefaultPolicy; p.MaxAttempts != 20 || p.Base != 5*time.Second || p.Cap != 15*time.Minute {
		t.Fatalf("the policy of ADR-004 D10 is 5 s, 15 min and 20 attempts: %+v", p)
	}
}

func TestD_AFailedAttemptCountsKeepsTheErrorAndWaitsLonger(t *testing.T) {
	got := pending(2).WithFailedAttempt("consumer said 503", now, outbox.DefaultPolicy)
	if got.Attempts != 3 || got.Status != outbox.Pending || got.LastError != "consumer said 503" || !got.NextAttemptAt.Equal(now.Truncate(time.Microsecond).Add(20*time.Second)) {
		t.Fatalf("event = %+v", got)
	}
}

func TestD_TheTwentiethFailedAttemptGivesTheEventUp(t *testing.T) {
	at := now.Truncate(time.Microsecond)
	if got := pending(18).WithFailedAttempt("x", now, outbox.DefaultPolicy); got.Status != outbox.Pending || got.Attempts != 19 {
		t.Fatalf("the 19th still waits: %+v", got)
	}
	got := pending(19).WithFailedAttempt("x", now, outbox.DefaultPolicy)
	if got.Status != outbox.Failed || got.Attempts != 20 || !got.NextAttemptAt.Equal(at) {
		t.Fatalf("the 20th fails the event: %+v", got)
	}
}

func TestD_AReportThatComesLateDoesNotTouchAnEventThatIsNoLongerPending(t *testing.T) {
	for _, status := range []outbox.Status{outbox.Published, outbox.Failed} {
		e := pending(3)
		e.Status = status
		if got := e.WithFailedAttempt("late", now, outbox.DefaultPolicy); got.Attempts != 3 || got.LastError != "" {
			t.Errorf("%s: %+v", status, got)
		}
	}
}

func TestD_PublishingIsRepeatableAndTrueEvenForAnEventThatWasGivenUp(t *testing.T) {
	first := pending(1).Published(now)
	if first.Status != outbox.Published || !first.PublishedAt.Equal(now.Truncate(time.Microsecond)) {
		t.Fatalf("published = %+v", first)
	}
	if again := first.Published(now.Add(time.Hour)); again.PublishedAt != first.PublishedAt {
		t.Fatalf("a repeat keeps the first instant: %+v", again)
	}
	failed := pending(20)
	failed.Status = outbox.Failed
	if got := failed.Published(now); got.Status != outbox.Published {
		t.Fatalf("a delivery that did succeed is true even if the event was given up: %+v", got)
	}
}

type fakeStore struct {
	events  map[string]outbox.Event
	due     []outbox.Event
	total   int
	err     error
	gotPage [2]int
}

func (f *fakeStore) ListDue(_ context.Context, _ time.Time, page, limit int) ([]outbox.Event, int, error) {
	f.gotPage = [2]int{page, limit}
	return f.due, f.total, f.err
}

func (f *fakeStore) Modify(_ context.Context, id string, change func(outbox.Event) outbox.Event) (outbox.Event, bool, error) {
	e, ok := f.events[id]
	if !ok || f.err != nil {
		return outbox.Event{}, false, f.err
	}
	e = change(e)
	f.events[id] = e
	return e, true, nil
}

func service(store *fakeStore) *outbox.Service {
	return &outbox.Service{Store: store, Clock: func() time.Time { return now }, Policy: outbox.DefaultPolicy}
}

var ctx = context.Background()

func TestA_TheListIsAPageWithItsTotalAndOnlyAValidPageIsServed(t *testing.T) {
	store := &fakeStore{due: []outbox.Event{pending(0)}, total: 41}
	got, err := service(store).ListDue(ctx, 2, 20)
	if err != nil || got.Page != 2 || got.Limit != 20 || got.Total != 41 || got.TotalPages != 3 || len(got.Data) != 1 || store.gotPage != [2]int{2, 20} {
		t.Fatalf("%+v %v", got, err)
	}
	if empty, _ := service(&fakeStore{}).ListDue(ctx, 1, 20); empty.TotalPages != 0 || empty.Data == nil {
		t.Fatalf("an empty list has no pages and an empty array: %+v", empty)
	}
	for _, bad := range [][2]int{{0, 20}, {-1, 20}, {1, 0}, {1, 101}, {1, -5}} {
		if _, err := service(&fakeStore{}).ListDue(ctx, bad[0], bad[1]); !errors.Is(err, outbox.ErrInvalid) {
			t.Errorf("page %d limit %d: %v", bad[0], bad[1], err)
		}
	}
}

func TestA_AnEventIsMarkedPublishedByItsIdAndAnIdThatCannotExistIsNotFound(t *testing.T) {
	store := &fakeStore{events: map[string]outbox.Event{eventID: pending(1)}}
	got, err := service(store).MarkPublished(ctx, eventID)
	if err != nil || got.Status != outbox.Published {
		t.Fatalf("%+v %v", got, err)
	}
	for _, id := range []string{"", "not-a-uuid", "6B9F2C1E-7A3D-4C58-9E10-2F4A8B7C6D5E ", "6b9f2c1e7a3d4c589e102f4a8b7c6d5e", "00000000-0000-4000-8000-000000000000"} {
		if _, err := service(store).MarkPublished(ctx, id); !errors.Is(err, outbox.ErrNotFound) {
			t.Errorf("%q: %v", id, err)
		}
	}
	boom := errors.New("connection reset")
	if _, err := service(&fakeStore{events: map[string]outbox.Event{eventID: pending(1)}, err: boom}).MarkPublished(ctx, eventID); !errors.Is(err, boom) {
		t.Errorf("a store failure passes through: %v", err)
	}
}

func TestA_AFailedAttemptIsRecordedWithATrimmedErrorAndTheRetryPolicy(t *testing.T) {
	store := &fakeStore{events: map[string]outbox.Event{eventID: pending(0)}}
	got, err := service(store).RecordFailedAttempt(ctx, eventID, "  consumer answered 503  ")
	if err != nil || got.Attempts != 1 || got.LastError != "consumer answered 503" || !got.NextAttemptAt.After(now) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := service(store).RecordFailedAttempt(ctx, "not-a-uuid", "x"); !errors.Is(err, outbox.ErrNotFound) {
		t.Errorf("an id that cannot exist: %v", err)
	}
}

func TestA_AnErrorThatCouldDisguiseALogLineOrIsOutOfSizeIsInvalidAndTouchesNothing(t *testing.T) {
	bad := map[string]string{
		"empty": "", "blank": "   ", "1001 characters": strings.Repeat("e", 1001),
		"bidi override": "ok‮evil", "zero-width space": "ok​evil", "line separator": "ok evil", "paragraph separator": "ok evil",
		"tab": "ok\tevil", "newline": "ok\nevil", "carriage return": "ok\revil", "NUL": "ok\x00evil", "no-break space": "ok evil",
		"private use": "okevil", "invalid UTF-8": "ok\xffevil", "unassigned": "ok\U000e0fffevil",
	}
	for name, text := range bad {
		store := &fakeStore{events: map[string]outbox.Event{eventID: pending(0)}}
		if _, err := service(store).RecordFailedAttempt(ctx, eventID, text); !errors.Is(err, outbox.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if store.events[eventID].Attempts != 0 {
			t.Errorf("%s: the attempt was counted", name)
		}
	}
	for name, text := range map[string]string{"1000 characters": strings.Repeat("e", 1000), "1000 multibyte": strings.Repeat("ñ", 1000), "inner spaces": "a b  c"} {
		store := &fakeStore{events: map[string]outbox.Event{eventID: pending(0)}}
		if _, err := service(store).RecordFailedAttempt(ctx, eventID, text); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestA_AServiceWithoutOnePieceRefusesToWorkAndNeverPanics(t *testing.T) {
	for name, s := range map[string]*outbox.Service{
		"store":  {Clock: func() time.Time { return now }, Policy: outbox.DefaultPolicy},
		"clock":  {Store: &fakeStore{}, Policy: outbox.DefaultPolicy},
		"policy": {Store: &fakeStore{}, Clock: func() time.Time { return now }},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("without the %s the service panicked: %v", name, r)
				}
			}()
			if _, err := s.ListDue(ctx, 1, 20); err == nil {
				t.Errorf("without the %s the list answered", name)
			}
			if _, err := s.MarkPublished(ctx, eventID); err == nil {
				t.Errorf("without the %s the mark answered", name)
			}
			if _, err := s.RecordFailedAttempt(ctx, eventID, "x"); err == nil {
				t.Errorf("without the %s the attempt answered", name)
			}
		}()
	}
}
