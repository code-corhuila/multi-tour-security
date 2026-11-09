package supportrequest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportrequest"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// Asking for a support access and listing the own requests (HU-SEC-007 part A, security spec 009: RN-SEC-009-01, -07, -09).

const (
	tenantID   = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	inactiveID = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	pendingID  = "11111111-2222-4333-8444-555555555555"
	failedID   = "22222222-3333-4444-8555-666666666666"
	platform   = "44444444-4444-4444-8444-444444444444"
	key        = "ask-0123456789"
)

var now = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

type fakeTenants struct {
	port.Tenants
	copies map[string]tenant.Copy
	err    error
}

func (f *fakeTenants) FindByID(_ context.Context, id string) (tenant.Copy, bool, error) {
	c, ok := f.copies[id]
	return c, ok, f.err
}

type fakeStore struct {
	created   []supportaccess.Access
	keys      map[string]supportaccess.Access
	list      []supportaccess.Access
	err       error
	listed    []string // the requester of each listing
	statuses  []string
	expired   []string // the requester of each expiry
	expireErr error
	listLimit int
	listSkip  int
}

func (f *fakeStore) Create(_ context.Context, a supportaccess.Access, key string) (supportaccess.Access, bool, error) {
	if f.err != nil {
		return supportaccess.Access{}, false, f.err
	}
	if prior, ok := f.keys[a.RequestedBy+"|"+key]; ok {
		return prior, false, nil
	}
	a.ID = "55555555-5555-4555-8555-555555555555"
	f.created = append(f.created, a)
	if f.keys == nil {
		f.keys = map[string]supportaccess.Access{}
	}
	f.keys[a.RequestedBy+"|"+key] = a
	return a, true, nil
}

func (f *fakeStore) ListByRequester(_ context.Context, requestedBy, status string, limit, offset int) ([]supportaccess.Access, int, error) {
	f.listed, f.statuses, f.listLimit, f.listSkip = append(f.listed, requestedBy), append(f.statuses, status), limit, offset
	return f.list, len(f.list), f.err
}

func (f *fakeStore) FindByKey(_ context.Context, requestedBy, key string) (supportaccess.Access, bool, error) {
	a, ok := f.keys[requestedBy+"|"+key]
	return a, ok, f.err
}

func (f *fakeStore) ExpirePending(_ context.Context, requestedBy string, _ time.Time) error {
	f.expired = append(f.expired, requestedBy)
	return f.expireErr
}

type world struct {
	service *supportrequest.Service
	tenants *fakeTenants
	store   *fakeStore
}

func newWorld() *world {
	w := &world{
		tenants: &fakeTenants{copies: map[string]tenant.Copy{
			tenantID:   {TenantID: tenantID, Status: tenant.Active},
			inactiveID: {TenantID: inactiveID, Status: tenant.Inactive},
			pendingID:  {TenantID: pendingID, Status: tenant.Pending},
			failedID:   {TenantID: failedID, Status: tenant.Failed},
		}},
		store: &fakeStore{},
	}
	w.service = &supportrequest.Service{Tenants: w.tenants, Store: w.store, Clock: func() time.Time { return now }}
	return w
}

func command() supportrequest.Command {
	return supportrequest.Command{ActorID: platform, TenantID: tenantID, Reason: "The cash closing does not show the transfers",
		Areas: []string{"CASH", "RESERVATIONS"}, Hours: 4, IdempotencyKey: key}
}

var ctx = context.Background()

func fieldOf(t *testing.T, err error) string {
	t.Helper()
	var fe *supportrequest.FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v, want a FieldError", err)
	}
	return fe.Field
}

func TestA_ARequestNeedsAReasonAnAreaAndAtMost24Hours(t *testing.T) {
	cases := map[string]struct {
		edit  func(*supportrequest.Command)
		field string
	}{
		"no reason":       {func(c *supportrequest.Command) { c.Reason = " " }, "reason"},
		"long reason":     {func(c *supportrequest.Command) { c.Reason = strings.Repeat("x", 501) }, "reason"},
		"no area":         {func(c *supportrequest.Command) { c.Areas = nil }, "areas"},
		"sensitive area":  {func(c *supportrequest.Command) { c.Areas = []string{"MEDICAL"} }, "areas"},
		"no hours":        {func(c *supportrequest.Command) { c.Hours = 0 }, "hours"},
		"too many hours":  {func(c *supportrequest.Command) { c.Hours = 25 }, "hours"},
		"tenant not uuid": {func(c *supportrequest.Command) { c.TenantID = "../x" }, "tenantId"},
		"short key":       {func(c *supportrequest.Command) { c.IdempotencyKey = "short" }, "idempotencyKey"},
		"long key":        {func(c *supportrequest.Command) { c.IdempotencyKey = strings.Repeat("k", 129) }, "idempotencyKey"},
	}
	for name, c := range cases {
		w := newWorld()
		cmd := command()
		c.edit(&cmd)
		if _, _, err := w.service.Ask(ctx, cmd); fieldOf(t, err) != c.field {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(w.store.created) != 0 {
			t.Errorf("%s: a refused request was stored", name)
		}
	}
}

func TestA_ATenantThatIsNotActiveOrInactiveIsRefused(t *testing.T) {
	for name, id := range map[string]string{"unknown": "66666666-6666-4666-8666-666666666666", "pending": pendingID, "failed": failedID} {
		w := newWorld()
		cmd := command()
		cmd.TenantID = id
		if _, _, err := w.service.Ask(ctx, cmd); !errors.Is(err, supportrequest.ErrTenantNotFound) {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(w.store.created) != 0 {
			t.Errorf("%s: a request was stored", name)
		}
	}
}

func TestA_AnInactiveTenantIsAcceptedBecauseItsAdministratorDecidesWithTheRestrictedAccess(t *testing.T) {
	w := newWorld()
	cmd := command()
	cmd.TenantID = inactiveID
	if _, created, err := w.service.Ask(ctx, cmd); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}

func TestA_AValidRequestIsPendingForTheCallerAndKeepsWhatWasAsked(t *testing.T) {
	w := newWorld()
	got, created, err := w.service.Ask(ctx, command())
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if got.Status != supportaccess.Pending || got.TenantID != tenantID || got.RequestedBy != platform || got.Hours != 4 || !got.RequestedAt.Equal(now) ||
		strings.Join(got.Scope(), ",") != "CASH,RESERVATIONS" {
		t.Fatalf("request = %+v", got)
	}
}

func TestA_TheSameKeyAnswersTheSameRequestAndStoresNoSecondOne(t *testing.T) {
	w := newWorld()
	first, _, err := w.service.Ask(ctx, command())
	if err != nil {
		t.Fatal(err)
	}
	again, created, err := w.service.Ask(ctx, command())
	if err != nil || created || again.ID != first.ID || len(w.store.created) != 1 {
		t.Fatalf("created=%v err=%v stored=%d", created, err, len(w.store.created))
	}
}

func TestA_AFailureOfTheStoreIsNotAnAnswer(t *testing.T) {
	w := newWorld()
	w.store.err = errors.New("db down")
	if _, _, err := w.service.Ask(ctx, command()); err == nil || fieldOf2(err) {
		t.Fatalf("err = %v", err)
	}
	w = newWorld()
	w.tenants.err = errors.New("db down")
	if _, _, err := w.service.Ask(ctx, command()); err == nil || fieldOf2(err) {
		t.Fatalf("err = %v", err)
	}
}

func fieldOf2(err error) bool {
	var fe *supportrequest.FieldError
	return errors.As(err, &fe)
}

func TestA_TheListIsOfTheCallerOnlyAndShowsWhatRanOutAsExpired(t *testing.T) {
	w := newWorld()
	old, _ := supportaccess.New(tenantID, platform, "why", []string{"CASH"}, 1, now.Add(-100*time.Hour))
	old.ID = "77777777-7777-4777-8777-777777777777"
	w.store.list = []supportaccess.Access{old}
	page, err := w.service.List(ctx, supportrequest.Query{ActorID: platform, Page: 1, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.store.listed) != 1 || w.store.listed[0] != platform || len(w.store.expired) != 1 || w.store.expired[0] != platform {
		t.Fatalf("listed=%v expired=%d", w.store.listed, w.store.expired)
	}
	if len(page.Data) != 1 || page.Data[0].Status != supportaccess.Expired || page.Total != 1 || page.TotalPages != 1 {
		t.Fatalf("page = %+v", page)
	}
}

func TestA_TheListChecksItsFilters(t *testing.T) {
	for name, q := range map[string]supportrequest.Query{
		"status":        {ActorID: platform, Status: "DONE", Page: 1, Limit: 20},
		"limit":         {ActorID: platform, Page: 1, Limit: 101},
		"zero limit":    {ActorID: platform, Page: 1, Limit: 0},
		"page":          {ActorID: platform, Page: 0, Limit: 20},
		"huge page":     {ActorID: platform, Page: 1 << 62, Limit: 100},
		"actor not uid": {ActorID: "x", Page: 1, Limit: 20},
	} {
		w := newWorld()
		if _, err := w.service.List(ctx, q); !fieldOf2(err) {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(w.store.listed) != 0 {
			t.Errorf("%s: the store was asked", name)
		}
	}
	w := newWorld()
	if _, err := w.service.List(ctx, supportrequest.Query{ActorID: platform, Status: "APPROVED", Page: 3, Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if w.store.statuses[0] != "APPROVED" || w.store.listLimit != 10 || w.store.listSkip != 20 {
		t.Fatalf("status=%v limit=%d skip=%d", w.store.statuses, w.store.listLimit, w.store.listSkip)
	}
}

func TestA_NothingRunsWithoutItsPieces(t *testing.T) {
	if _, _, err := (&supportrequest.Service{}).Ask(ctx, command()); err == nil || fieldOf2(err) {
		t.Errorf("err = %v", err)
	}
	if _, err := (&supportrequest.Service{}).List(ctx, supportrequest.Query{ActorID: platform, Page: 1, Limit: 20}); err == nil || fieldOf2(err) {
		t.Errorf("err = %v", err)
	}
}

// A repeat of the key answers the request that key made, without looking at the body or at the tenant again (Annex C).
func TestA_ARepeatOfTheKeyAnswersTheStoredRequestEvenIfTheBodyOrTheTenantChanged(t *testing.T) {
	w := newWorld()
	first, _, err := w.service.Ask(ctx, command())
	if err != nil {
		t.Fatal(err)
	}
	w.tenants.copies[tenantID] = tenant.Copy{TenantID: tenantID, Status: tenant.Failed}
	changed := command()
	changed.Reason, changed.Hours, changed.Areas = " ", 99, nil
	again, created, err := w.service.Ask(ctx, changed)
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("created=%v err=%v again=%+v", created, err, again)
	}
	// another author with the same key is not a repeat
	other := command()
	other.ActorID = "88888888-8888-4888-8888-888888888888"
	if _, created, err := w.service.Ask(ctx, other); err == nil && created {
		t.Fatal("a request of another author was taken for a repeat, or the tenant check was skipped")
	}
}

func TestA_AFailureToMarkTheExpiredRequestsIsAFailureOfTheList(t *testing.T) {
	w := newWorld()
	w.store.expireErr = errors.New("db down")
	if _, err := w.service.List(ctx, supportrequest.Query{ActorID: platform, Page: 1, Limit: 20}); err == nil || fieldOf2(err) {
		t.Fatalf("err = %v", err)
	}
	if len(w.store.listed) != 0 {
		t.Fatal("the list was read after the failure")
	}
}
