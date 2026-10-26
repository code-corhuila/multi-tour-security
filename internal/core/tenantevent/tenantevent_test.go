package tenantevent_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenantevent"
)

const (
	tenantID = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	eventID  = "6b9f2c1e-7a3d-4c58-9e10-2f4a8b7c6d5e"
)

var at = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

type fakeTenants struct {
	applied []tenant.Copy
	result  bool
	err     error
}

func (f *fakeTenants) Apply(_ context.Context, c tenant.Copy) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	f.applied = append(f.applied, c)
	return f.result, nil
}
func (f *fakeTenants) FindByIdentifier(context.Context, string) (tenant.Copy, bool, error) {
	return tenant.Copy{}, false, nil
}
func (f *fakeTenants) FindByID(context.Context, string) (tenant.Copy, bool, error) {
	return tenant.Copy{}, false, nil
}

func valid(kind, status string) tenantevent.Event {
	return tenantevent.Event{PathTenantID: tenantID, EventID: eventID, Type: kind, Version: 1, TenantID: tenantID, AggregateID: tenantID,
		Identifier: "travesia-natural", Status: status, OccurredAt: at}
}

var ctx = context.Background()

func TestC_EachEventOfATenantBecomesTheCopyItDescribes(t *testing.T) {
	for _, c := range []struct{ kind, status string }{
		{"TenantCreated", "PENDING"}, {"TenantCreated", "ACTIVE"}, {"TenantInactivated", "INACTIVE"}, {"TenantReactivated", "ACTIVE"},
	} {
		store := &fakeTenants{result: true}
		applied, err := (&tenantevent.Service{Tenants: store}).Receive(ctx, valid(c.kind, c.status))
		want := tenant.Copy{TenantID: tenantID, Identifier: "travesia-natural", Status: tenant.Status(c.status), OccurredAt: at}
		if err != nil || !applied || len(store.applied) != 1 || store.applied[0] != want {
			t.Errorf("%s/%s: %v %v %+v", c.kind, c.status, applied, err, store.applied)
		}
	}
}

func TestC_AnEventTheStoreIgnoresIsNotAppliedAndIsNotAnError(t *testing.T) {
	store := &fakeTenants{result: false}
	applied, err := (&tenantevent.Service{Tenants: store}).Receive(ctx, valid("TenantInactivated", "INACTIVE"))
	if err != nil || applied {
		t.Fatalf("an older or repeated event is a 200 with nothing applied: %v %v", applied, err)
	}
}

func TestC_AnEnvelopeThatContradictsItselfOrBreaksTheContractIsInvalidAndTouchesNothing(t *testing.T) {
	other := "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	edit := func(f func(e *tenantevent.Event)) tenantevent.Event {
		e := valid("TenantCreated", "ACTIVE")
		f(&e)
		return e
	}
	bad := map[string]tenantevent.Event{
		"path tenant differs":          edit(func(e *tenantevent.Event) { e.PathTenantID = other }),
		"body tenant differs":          edit(func(e *tenantevent.Event) { e.TenantID = other }),
		"aggregate differs":            edit(func(e *tenantevent.Event) { e.AggregateID = other }),
		"payload tenant differs":       edit(func(e *tenantevent.Event) { e.PayloadTenantID = other }),
		"event id is not a UUID":       edit(func(e *tenantevent.Event) { e.EventID = "not-a-uuid" }),
		"tenant id is not a UUID":      edit(func(e *tenantevent.Event) { e.PathTenantID, e.TenantID, e.AggregateID = "x", "x", "x" }),
		"upper-case UUID":              edit(func(e *tenantevent.Event) { e.EventID = strings.ToUpper(eventID) }),
		"unknown event type":           edit(func(e *tenantevent.Event) { e.Type = "TenantDeleted" }),
		"empty event type":             edit(func(e *tenantevent.Event) { e.Type = "" }),
		"version zero":                 edit(func(e *tenantevent.Event) { e.Version = 0 }),
		"unknown status":               edit(func(e *tenantevent.Event) { e.Status = "DELETED" }),
		"lower-case status":            edit(func(e *tenantevent.Event) { e.Status = "active" }),
		"empty status":                 edit(func(e *tenantevent.Event) { e.Status = "" }),
		"identifier of two characters": edit(func(e *tenantevent.Event) { e.Identifier = "ab" }),
		"identifier of 41":             edit(func(e *tenantevent.Event) { e.Identifier = strings.Repeat("a", 41) }),
		"identifier in capitals":       edit(func(e *tenantevent.Event) { e.Identifier = "Travesia" }),
		"identifier with two hyphens":  edit(func(e *tenantevent.Event) { e.Identifier = "a--b" }),
		"identifier with a slash":      edit(func(e *tenantevent.Event) { e.Identifier = "a/b" }),
		"no instant":                   edit(func(e *tenantevent.Event) { e.OccurredAt = time.Time{} }),
		"inactivated with ACTIVE":      valid("TenantInactivated", "ACTIVE"),
		"reactivated with INACTIVE":    valid("TenantReactivated", "INACTIVE"),
		"reactivated with PENDING":     valid("TenantReactivated", "PENDING"),
	}
	for name, e := range bad {
		store := &fakeTenants{result: true}
		if _, err := (&tenantevent.Service{Tenants: store}).Receive(ctx, e); !errors.Is(err, tenantevent.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if len(store.applied) != 0 {
			t.Errorf("%s reached the store", name)
		}
	}
	ok := edit(func(e *tenantevent.Event) { e.Identifier = strings.Repeat("a", 40); e.PayloadTenantID = tenantID })
	if _, err := (&tenantevent.Service{Tenants: &fakeTenants{}}).Receive(ctx, ok); err != nil {
		t.Errorf("40 characters and a payload that names the same tenant are fine: %v", err)
	}
}

func TestC_AnIdentifierThatAnotherTenantStillHoldsIsToBeRetriedAndNeverARefusal(t *testing.T) {
	store := &fakeTenants{err: port.ErrIdentifierTaken}
	_, err := (&tenantevent.Service{Tenants: store}).Receive(ctx, valid("TenantCreated", "ACTIVE"))
	if !errors.Is(err, tenantevent.ErrRetryLater) || errors.Is(err, tenantevent.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestC_AFailureOfTheStoreIsAnErrorThatIsNeitherInvalidNorRetryLater(t *testing.T) {
	boom := errors.New("connection reset")
	_, err := (&tenantevent.Service{Tenants: &fakeTenants{err: boom}}).Receive(ctx, valid("TenantCreated", "ACTIVE"))
	if !errors.Is(err, boom) || errors.Is(err, tenantevent.ErrInvalid) || errors.Is(err, tenantevent.ErrRetryLater) {
		t.Fatalf("got %v", err)
	}
	if _, err := (&tenantevent.Service{}).Receive(ctx, valid("TenantCreated", "ACTIVE")); err == nil {
		t.Fatal("a service without its store answered")
	}
}

func TestC_TheCommercialNameOfAnEventReachesTheCopyAndAnEventWithoutOneLeavesItEmpty(t *testing.T) {
	named := valid("TenantCreated", "ACTIVE")
	named.CommercialName = "Travesía Natural SAS"
	store := &fakeTenants{result: true}
	if _, err := (&tenantevent.Service{Tenants: store}).Receive(ctx, named); err != nil {
		t.Fatal(err)
	}
	if _, err := (&tenantevent.Service{Tenants: store}).Receive(ctx, valid("TenantInactivated", "INACTIVE")); err != nil {
		t.Fatal(err)
	}
	if store.applied[0].CommercialName != "Travesía Natural SAS" {
		t.Fatalf("the name of the event did not reach the copy: %+v", store.applied[0])
	}
	if store.applied[1].CommercialName != "" {
		t.Fatalf("an event without a name must carry none, so the store keeps the one it knows: %+v", store.applied[1])
	}
}

func TestC_ACommercialNameWithAControlCharacterIsAnInvalidEnvelopeAndTouchesNothing(t *testing.T) {
	for _, name := range []string{"Evil\r\nBcc: x@y.z", "Tab\there", "Nul\x00"} {
		e := valid("TenantCreated", "ACTIVE")
		e.CommercialName = name
		store := &fakeTenants{result: true}
		if _, err := (&tenantevent.Service{Tenants: store}).Receive(ctx, e); !errors.Is(err, tenantevent.ErrInvalid) || len(store.applied) != 0 {
			t.Fatalf("%q: err = %v, applied %v", name, err, store.applied)
		}
	}
}
