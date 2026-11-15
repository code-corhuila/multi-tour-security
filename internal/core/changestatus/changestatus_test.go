package changestatus_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/changestatus"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-005, RN-SEC-003-09 and -10: inactivating and reactivating an internal user, with the fake store.

const (
	tenantID  = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	accountID = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	actorID   = "7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 123456789, time.UTC)

type fakeStore struct {
	commands []port.StatusCommand
	reg      port.Registered
	err      error
}

func (f *fakeStore) ChangeStatus(_ context.Context, c port.StatusCommand) (port.Registered, error) {
	f.commands = append(f.commands, c)
	return f.reg, f.err
}

func service(store port.UserStatus) *changestatus.Service {
	return &changestatus.Service{Store: store, Clock: func() time.Time { return now }}
}

func request(reason string) changestatus.Request {
	return changestatus.Request{TenantID: tenantID, AccountID: accountID, ActorID: actorID, Reason: reason, CorrelationID: "corr-1"}
}

func TestA_InactivatingAsksTheStoreForTheTenantTheActorAndTheReasonAtTheInstantOfTheClock(t *testing.T) {
	store := &fakeStore{reg: port.Registered{Role: "MANAGER"}}
	got, err := service(store).Inactivate(context.Background(), request("  Left the company  "))
	if err != nil || got.Role != "MANAGER" {
		t.Fatalf("%+v %v", got, err)
	}
	want := port.StatusCommand{TenantID: tenantID, AccountID: accountID, To: account.Inactive, By: "tenant-administrator/" + actorID, ActorID: actorID,
		Reason: "Left the company", CorrelationID: "corr-1", Now: now}
	if len(store.commands) != 1 || store.commands[0] != want {
		t.Fatalf("the store was asked %+v", store.commands)
	}
}

func TestA_ReactivatingAsksForTheActiveStatusAndKeepsTheSameAccount(t *testing.T) {
	store := &fakeStore{}
	if _, err := service(store).Reactivate(context.Background(), request("Back from leave")); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 || store.commands[0].To != account.Active || store.commands[0].AccountID != accountID {
		t.Fatalf("the store was asked %+v", store.commands)
	}
}

func TestA_AReasonIsRequiredAndAtMost500CharactersAndTheStoreIsNotAskedOtherwise(t *testing.T) {
	for name, r := range map[string]changestatus.Request{
		"no reason":           request(""),
		"only spaces":         request(" \t\n "),
		"501 characters":      request(strings.Repeat("r", 501)),
		"501 multibyte runes": request(strings.Repeat("ñ", 501)),
	} {
		for action, do := range map[string]func(*changestatus.Service) error{
			"inactivate": func(s *changestatus.Service) error { _, err := s.Inactivate(context.Background(), r); return err },
			"reactivate": func(s *changestatus.Service) error { _, err := s.Reactivate(context.Background(), r); return err },
		} {
			store := &fakeStore{}
			err := do(service(store))
			var invalid *changestatus.FieldError
			if !errors.As(err, &invalid) || invalid.Field != "reason" || !errors.Is(err, changestatus.ErrInvalid) || len(store.commands) != 0 {
				t.Errorf("%s, %s: err=%v asked %d times", action, name, err, len(store.commands))
			}
		}
	}
	// 500 characters, counted as characters and not bytes, are fine
	if _, err := service(&fakeStore{}).Inactivate(context.Background(), request(strings.Repeat("ñ", 500))); err != nil {
		t.Fatalf("500 characters: %v", err)
	}
}

func TestA_AnIdThatIsNotAnIdIsRefusedNamingTheFieldBeforeTheStore(t *testing.T) {
	for field, mutate := range map[string]func(*changestatus.Request){
		"accountId": func(r *changestatus.Request) { r.AccountID = "not-a-uuid" },
		"tenantId":  func(r *changestatus.Request) { r.TenantID = "" },
		"actorId":   func(r *changestatus.Request) { r.ActorID = "someone" },
	} {
		r := request("Left")
		mutate(&r)
		store := &fakeStore{}
		_, err := service(store).Inactivate(context.Background(), r)
		var invalid *changestatus.FieldError
		if !errors.As(err, &invalid) || invalid.Field != field || len(store.commands) != 0 {
			t.Errorf("%s: err=%v asked %d times", field, err, len(store.commands))
		}
	}
}

func TestA_TheRefusalsOfTheStoreReachTheCallerAsTheyAre(t *testing.T) {
	for _, refusal := range []error{port.ErrUserNotFound, port.ErrStatusTransition} {
		_, err := service(&fakeStore{err: refusal}).Inactivate(context.Background(), request("Left"))
		if !errors.Is(err, refusal) {
			t.Errorf("%v became %v", refusal, err)
		}
	}
}

func TestA_AServiceWithAPieceMissingFailsAsAWiringErrorAndNotAsABadRequest(t *testing.T) {
	for name, s := range map[string]*changestatus.Service{
		"no store": {Clock: func() time.Time { return now }},
		"no clock": {Store: &fakeStore{}},
	} {
		if _, err := s.Inactivate(context.Background(), request("Left")); err == nil || errors.Is(err, changestatus.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the outbox takes a correlation id of 1 to 128 characters: anything else is our mistake, not the caller's, and the store is not asked
	for name, id := range map[string]string{"none": "", "129 characters": strings.Repeat("c", 129)} {
		r := request("Left")
		r.CorrelationID = id
		store := &fakeStore{}
		if _, err := service(store).Inactivate(context.Background(), r); err == nil || errors.Is(err, changestatus.ErrInvalid) || len(store.commands) != 0 {
			t.Errorf("%s: err=%v asked %d times", name, err, len(store.commands))
		}
	}
	if _, err := service(&fakeStore{}).Inactivate(context.Background(), func() changestatus.Request {
		r := request("Left")
		r.CorrelationID = strings.Repeat("c", 128)
		return r
	}()); err != nil {
		t.Fatalf("128 characters are fine: %v", err)
	}
}
