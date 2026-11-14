package supportemergency_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportemergency"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// Opening an emergency access (HU-SEC-007 part B, security spec 010: RN-SEC-010-01, -02, -08, -09).

const (
	tenantID   = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	inactiveID = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	pendingID  = "11111111-2222-4333-8444-555555555555"
	failedID   = "22222222-3333-4444-8555-666666666666"
	platform   = "44444444-4444-4444-8444-444444444444"
	key        = "emergency-0123"
)

var now = time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)

type fakeTenants struct {
	port.Tenants
	copies map[string]tenant.Copy
}

func (f *fakeTenants) FindByID(_ context.Context, id string) (tenant.Copy, bool, error) {
	c, ok := f.copies[id]
	return c, ok, nil
}

type fakeStore struct {
	opened      []supportaccess.Access
	correlation []string
	keys        map[string]supportaccess.Access
	lookups     int
	open        bool // an access of that pair is already open
	err         error
}

func (f *fakeStore) FindByKey(_ context.Context, requestedBy, key string) (supportaccess.Access, bool, error) {
	f.lookups++
	a, ok := f.keys[requestedBy+"|"+key]
	return a, ok, f.err
}

func (f *fakeStore) OpenEmergency(_ context.Context, a supportaccess.Access, key, correlationID string) (supportaccess.Access, bool, error) {
	if f.err != nil {
		return supportaccess.Access{}, false, f.err
	}
	if f.open {
		return supportaccess.Access{}, false, supportaccess.ErrOpenAccessExists
	}
	a.ID = "55555555-5555-4555-8555-555555555555"
	f.opened, f.correlation = append(f.opened, a), append(f.correlation, correlationID)
	if f.keys == nil {
		f.keys = map[string]supportaccess.Access{}
	}
	f.keys[a.RequestedBy+"|"+key] = a
	return a, true, nil
}

func newService() (*supportemergency.Service, *fakeStore) {
	store := &fakeStore{}
	tenants := &fakeTenants{copies: map[string]tenant.Copy{
		tenantID:   {TenantID: tenantID, Status: tenant.Active},
		inactiveID: {TenantID: inactiveID, Status: tenant.Inactive},
		pendingID:  {TenantID: pendingID, Status: tenant.Pending},
		failedID:   {TenantID: failedID, Status: tenant.Failed},
	}}
	return &supportemergency.Service{Tenants: tenants, Store: store, Clock: func() time.Time { return now }}, store
}

func command() supportemergency.Command {
	return supportemergency.Command{ActorID: platform, TenantID: tenantID, Reason: "Every cash of today shows a negative balance",
		Statement: "No Administrator can sign in", Areas: []string{"CASH"}, Hours: 4, IdempotencyKey: key, CorrelationID: "corr-1"}
}

var ctx = context.Background()

func fieldOf(t *testing.T, err error) string {
	t.Helper()
	var fe *supportemergency.FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v, want a FieldError", err)
	}
	return fe.Field
}

func TestA_AnEmergencyNeedsAJustificationAStatementAnAreaAndAtMost24Hours(t *testing.T) {
	for name, c := range map[string]struct {
		change func(*supportemergency.Command)
		field  string
	}{
		"no reason":         {func(c *supportemergency.Command) { c.Reason = "" }, "reason"},
		"no statement":      {func(c *supportemergency.Command) { c.Statement = "" }, "statement"},
		"no area":           {func(c *supportemergency.Command) { c.Areas = nil }, "areas"},
		"25 hours":          {func(c *supportemergency.Command) { c.Hours = 25 }, "hours"},
		"flag without why":  {func(c *supportemergency.Command) { c.Sensitive = true }, "sensitiveReason"},
		"why without flag":  {func(c *supportemergency.Command) { c.SensitiveReason = "a reason alone" }, "sensitive"},
		"actor not a uuid":  {func(c *supportemergency.Command) { c.ActorID = "x" }, "actorId"},
		"tenant not a uuid": {func(c *supportemergency.Command) { c.TenantID = "x" }, "tenantId"},
		"short key":         {func(c *supportemergency.Command) { c.IdempotencyKey = "short" }, "idempotencyKey"},
	} {
		s, store := newService()
		cmd := command()
		c.change(&cmd)
		_, _, err := s.Open(ctx, cmd)
		if got := fieldOf(t, err); got != c.field {
			t.Errorf("%s: field = %s, want %s", name, got, c.field)
		}
		if len(store.opened) != 0 {
			t.Errorf("%s: nothing is stored on a bad form", name)
		}
	}
	s, store := newService()
	made, created, err := s.Open(ctx, command())
	if err != nil || !created || len(store.opened) != 1 || made.Basis != supportaccess.Emergency || made.Status != supportaccess.Approved {
		t.Fatalf("a good form opens an emergency: %+v %v %v", made, created, err)
	}
	if store.correlation[0] != "corr-1" {
		t.Errorf("the correlation id goes to the store: %v", store.correlation)
	}
}

func TestA_ATenantThatIsNotActiveOrInactiveIsRefused(t *testing.T) {
	for name, id := range map[string]string{"unknown": "99999999-9999-4999-8999-999999999999", "pending": pendingID, "failed": failedID} {
		s, store := newService()
		cmd := command()
		cmd.TenantID = id
		if _, _, err := s.Open(ctx, cmd); !errors.Is(err, supportemergency.ErrTenantNotFound) || len(store.opened) != 0 {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	s, _ := newService()
	cmd := command()
	cmd.TenantID = inactiveID
	if _, created, err := s.Open(ctx, cmd); err != nil || !created {
		t.Errorf("an inactive tenant is the very case of an emergency: %v", err)
	}
}

func TestA_TheSameKeyAnswersTheSameEmergency(t *testing.T) {
	s, store := newService()
	first, created, err := s.Open(ctx, command())
	if err != nil || !created {
		t.Fatal(err)
	}
	cmd := command()
	cmd.Reason, cmd.TenantID = "Another reason", inactiveID // the body does not matter on a repeat (Annex C)
	again, created, err := s.Open(ctx, cmd)
	if err != nil || created || again.ID != first.ID || len(store.opened) != 1 {
		t.Errorf("a repeat answers the first: %+v created=%v err=%v stored=%d", again, created, err, len(store.opened))
	}
}

func TestA_AnOpenAccessOfThePairRefusesASecondOne(t *testing.T) {
	s, store := newService()
	store.open = true
	if _, _, err := s.Open(ctx, command()); !errors.Is(err, supportaccess.ErrOpenAccessExists) {
		t.Errorf("err = %v", err)
	}
}

func TestA_AUseCaseWithoutItsPiecesFailsLoudly(t *testing.T) {
	if _, _, err := (&supportemergency.Service{}).Open(ctx, command()); err == nil {
		t.Error("an unwired service must not open anything")
	}
}
