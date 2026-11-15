package supportdecision_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportdecision"
)

// The Tenant Administrator sees the requests of their tenant and decides them (HU-SEC-007 part A, security spec 009: RN-SEC-009-03, -04, -07).

const (
	tenantID = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	otherID  = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	platform = "44444444-4444-4444-8444-444444444444"
	admin    = "22222222-2222-4222-8222-222222222222"
	requestA = "55555555-5555-4555-8555-555555555555"
)

var now = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

type fakeStore struct {
	items           map[string]supportaccess.Access
	decided         []supportaccess.Access
	lost            bool // Decide answers that the request is not pending any more
	err             error
	expiredFor      []string
	approvedExpired []string // the author and the tenant of each expiry of approved accesses
	listed          []string
	statuses        []string
	limit           int
	skip            int
	lookups         int
}

func (f *fakeStore) Create(context.Context, supportaccess.Access, string) (supportaccess.Access, bool, error) {
	return supportaccess.Access{}, false, errors.New("not used by the decision")
}
func (f *fakeStore) FindByKey(context.Context, string, string) (supportaccess.Access, bool, error) {
	return supportaccess.Access{}, false, errors.New("not used by the decision")
}
func (f *fakeStore) ListByRequester(context.Context, string, string, int, int) ([]supportaccess.Access, int, error) {
	return nil, 0, errors.New("not used by the decision")
}
func (f *fakeStore) ExpirePending(context.Context, string, time.Time) error {
	return errors.New("not used by the decision")
}

func (f *fakeStore) ExpireApproved(_ context.Context, requestedBy, tenant string, _ time.Time) error {
	f.approvedExpired = append(f.approvedExpired, requestedBy+"|"+tenant)
	return f.err
}

func (f *fakeStore) FindForTenant(_ context.Context, tenant, id string) (supportaccess.Access, bool, error) {
	f.lookups++
	a, ok := f.items[id]
	if !ok || a.TenantID != tenant {
		return supportaccess.Access{}, false, f.err
	}
	return a, true, f.err
}

func (f *fakeStore) ListByTenant(_ context.Context, tenant, status string, limit, offset int) ([]supportaccess.Access, int, error) {
	f.listed, f.statuses, f.limit, f.skip = append(f.listed, tenant), append(f.statuses, status), limit, offset
	var out []supportaccess.Access
	for _, a := range f.items {
		if a.TenantID == tenant {
			out = append(out, a)
		}
	}
	return out, len(out), f.err
}

func (f *fakeStore) ExpirePendingOfTenant(_ context.Context, tenant string, _ time.Time) error {
	f.expiredFor = append(f.expiredFor, tenant)
	return f.err
}

func (f *fakeStore) Decide(_ context.Context, a supportaccess.Access) (bool, error) {
	if f.err != nil || f.lost {
		return false, f.err
	}
	f.decided = append(f.decided, a)
	f.items[a.ID] = a
	return true, nil
}

func pending(t *testing.T, at time.Time) supportaccess.Access {
	t.Helper()
	a, err := supportaccess.New(tenantID, platform, "The cash closing does not show the transfers", []string{"CASH"}, 4, at)
	if err != nil {
		t.Fatal(err)
	}
	a.ID = requestA
	return a
}

type world struct {
	service *supportdecision.Service
	store   *fakeStore
}

func newWorld(t *testing.T) *world {
	w := &world{store: &fakeStore{items: map[string]supportaccess.Access{requestA: pending(t, now)}}}
	w.service = &supportdecision.Service{Store: w.store, Clock: func() time.Time { return now.Add(time.Hour) }}
	return w
}

var ctx = context.Background()

func decision() supportdecision.Decision {
	return supportdecision.Decision{TenantID: tenantID, ActorID: admin, ID: requestA}
}

func fieldOf(err error) string {
	var fe *supportdecision.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func TestA_AnAdministratorApprovesAPendingRequestOfTheirTenantAndTheHoursRunFromNow(t *testing.T) {
	w := newWorld(t)
	got, err := w.service.Approve(ctx, decision())
	if err != nil {
		t.Fatal(err)
	}
	approvedAt := now.Add(time.Hour)
	if got.Status != supportaccess.Approved || got.DecidedBy != admin || !got.DecidedAt.Equal(approvedAt) || !got.ExpiresAt.Equal(approvedAt.Add(4*time.Hour)) {
		t.Fatalf("approved = %+v", got)
	}
	if len(w.store.decided) != 1 || w.store.decided[0].ID != requestA {
		t.Fatalf("decided = %+v", w.store.decided)
	}
}

func TestA_AnAdministratorRejectsWithAReason(t *testing.T) {
	w := newWorld(t)
	c := decision()
	c.Reason = "Nobody asked for this support"
	got, err := w.service.Reject(ctx, c)
	if err != nil || got.Status != supportaccess.Rejected || got.DecisionReason != c.Reason || got.DecidedBy != admin {
		t.Fatalf("rejected = %+v %v", got, err)
	}
	for _, bad := range []string{"", "  ", strings.Repeat("x", 501)} {
		w := newWorld(t)
		c.Reason = bad
		if _, err := w.service.Reject(ctx, c); fieldOf(err) != "reason" {
			t.Errorf("reason %q: err = %v", bad, err)
		}
		if len(w.store.decided) != 0 {
			t.Errorf("reason %q: a decision was stored", bad)
		}
	}
}

func TestA_OnlyAnAdministratorOfTheTenantDecides(t *testing.T) {
	w := newWorld(t)
	c := decision()
	c.TenantID = otherID
	if _, err := w.service.Approve(ctx, c); !errors.Is(err, supportdecision.ErrNotFound) {
		t.Errorf("another tenant: %v", err)
	}
	c = decision()
	c.ID = "66666666-6666-4666-8666-666666666666"
	if _, err := w.service.Approve(ctx, c); !errors.Is(err, supportdecision.ErrNotFound) {
		t.Errorf("a request that does not exist: %v", err)
	}
	c = decision()
	c.ID = "../x"
	if _, err := w.service.Approve(ctx, c); !errors.Is(err, supportdecision.ErrNotFound) {
		t.Errorf("an id that is not one: %v", err)
	}
	if len(w.store.decided) != 0 {
		t.Fatal("a decision was stored")
	}
	c = decision()
	c.ActorID = "x"
	if _, err := w.service.Approve(ctx, c); fieldOf(err) != "actorId" {
		t.Errorf("a bad actor: %v", err)
	}
	c = decision()
	c.TenantID = "x"
	if _, err := w.service.Approve(ctx, c); fieldOf(err) != "tenantId" {
		t.Errorf("a bad tenant: %v", err)
	}
}

func TestA_OnlyAPendingRequestIsDecided(t *testing.T) {
	for name, edit := range map[string]func(*supportaccess.Access){
		"approved": func(a *supportaccess.Access) { a.Status = supportaccess.Approved },
		"rejected": func(a *supportaccess.Access) { a.Status = supportaccess.Rejected },
		"closed":   func(a *supportaccess.Access) { a.Status = supportaccess.Closed },
		"too old":  func(a *supportaccess.Access) { a.RequestedAt = now.Add(-80 * time.Hour) },
	} {
		w := newWorld(t)
		a := w.store.items[requestA]
		edit(&a)
		w.store.items[requestA] = a
		c := decision()
		c.Reason = "no"
		if _, err := w.service.Approve(ctx, decision()); !errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("approving %s: %v", name, err)
		}
		if _, err := w.service.Reject(ctx, c); !errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("rejecting %s: %v", name, err)
		}
		if len(w.store.decided) != 0 {
			t.Errorf("%s: a decision was stored", name)
		}
	}
}

func TestA_TwoDecisionsAtOnceHaveOneWinner(t *testing.T) {
	w := newWorld(t)
	w.store.lost = true // the other administrator decided between the read and the write
	if _, err := w.service.Approve(ctx, decision()); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Fatalf("err = %v", err)
	}
}

func TestA_TheListIsOfTheTenantAndShowsWhatRanOutAsExpired(t *testing.T) {
	w := newWorld(t)
	old := pending(t, now.Add(-100*time.Hour))
	old.ID = "77777777-7777-4777-8777-777777777777"
	w.store.items[old.ID] = old
	elsewhere := pending(t, now)
	elsewhere.ID, elsewhere.TenantID = "88888888-8888-4888-8888-888888888888", otherID
	w.store.items[elsewhere.ID] = elsewhere

	page, err := w.service.List(ctx, supportdecision.Query{TenantID: tenantID, Page: 1, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.store.approvedExpired) != 1 || w.store.approvedExpired[0] != "|"+tenantID {
		t.Fatalf("approved accesses expired for %v", w.store.approvedExpired)
	}
	if len(w.store.expiredFor) != 1 || w.store.expiredFor[0] != tenantID || len(w.store.listed) != 1 || w.store.listed[0] != tenantID {
		t.Fatalf("expired for %v, listed for %v", w.store.expiredFor, w.store.listed)
	}
	if page.Total != 2 || len(page.Data) != 2 || page.TotalPages != 1 {
		t.Fatalf("page = %+v", page)
	}
	for _, a := range page.Data {
		if a.TenantID != tenantID {
			t.Errorf("a request of another tenant: %+v", a)
		}
		if a.ID == old.ID && a.Status != supportaccess.Expired {
			t.Errorf("the old request shows %s", a.Status)
		}
	}
}

func TestA_TheListChecksItsFilters(t *testing.T) {
	for name, q := range map[string]supportdecision.Query{
		"tenant":     {TenantID: "x", Page: 1, Limit: 20},
		"status":     {TenantID: tenantID, Status: "DONE", Page: 1, Limit: 20},
		"limit":      {TenantID: tenantID, Page: 1, Limit: 101},
		"page":       {TenantID: tenantID, Page: 0, Limit: 20},
		"huge page":  {TenantID: tenantID, Page: 1 << 62, Limit: 100},
		"zero limit": {TenantID: tenantID, Page: 1, Limit: 0},
	} {
		w := newWorld(t)
		if _, err := w.service.List(ctx, q); fieldOf(err) == "" {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(w.store.listed) != 0 {
			t.Errorf("%s: the store was asked", name)
		}
	}
	w := newWorld(t)
	if _, err := w.service.List(ctx, supportdecision.Query{TenantID: tenantID, Status: "PENDING", Page: 3, Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if w.store.statuses[0] != "PENDING" || w.store.limit != 10 || w.store.skip != 20 {
		t.Fatalf("status=%v limit=%d skip=%d", w.store.statuses, w.store.limit, w.store.skip)
	}
}

func TestA_AFailureOfTheStoreIsNotAnAnswerOfTheRules(t *testing.T) {
	w := newWorld(t)
	w.store.err = errors.New("db down")
	for name, call := range map[string]func() error{
		"approve": func() error { _, err := w.service.Approve(ctx, decision()); return err },
		"reject": func() error {
			c := decision()
			c.Reason = "no"
			_, err := w.service.Reject(ctx, c)
			return err
		},
		"list": func() error {
			_, err := w.service.List(ctx, supportdecision.Query{TenantID: tenantID, Page: 1, Limit: 20})
			return err
		},
	} {
		if err := call(); err == nil || fieldOf(err) != "" || errors.Is(err, supportdecision.ErrNotFound) || errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestA_NothingRunsWithoutItsPieces(t *testing.T) {
	if _, err := (&supportdecision.Service{}).Approve(ctx, decision()); err == nil || fieldOf(err) != "" {
		t.Errorf("err = %v", err)
	}
	if _, err := (&supportdecision.Service{}).List(ctx, supportdecision.Query{TenantID: tenantID, Page: 1, Limit: 20}); err == nil || fieldOf(err) != "" {
		t.Errorf("err = %v", err)
	}
}

// The instants of a decision are kept to the microsecond, as the store keeps them, so the answer and a later read agree.
func TestA_TheInstantsOfADecisionAreKeptToTheMicrosecond(t *testing.T) {
	w := newWorld(t)
	w.service.Clock = func() time.Time { return now.Add(time.Hour + 123*time.Nanosecond) }
	got, err := w.service.Approve(ctx, decision())
	if err != nil {
		t.Fatal(err)
	}
	if got.DecidedAt.Nanosecond()%1000 != 0 || got.ExpiresAt.Nanosecond()%1000 != 0 {
		t.Fatalf("decided at %v, ends at %v", got.DecidedAt, got.ExpiresAt)
	}
}
