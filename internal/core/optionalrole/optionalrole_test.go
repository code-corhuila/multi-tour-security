package optionalrole_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/optionalrole"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-006, RN-SEC-005-02, -12 and -13: enabling and disabling the optional roles of a tenant, with the fake store.

const (
	tenantID = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	actorID  = "7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

var now = time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC)

type fakeStore struct {
	states   []port.OptionalRoleState
	listed   []string
	enabled  []port.OptionalRoleChange
	disabled []port.OptionalRoleChange
	state    port.OptionalRoleState
	err      error
}

func (f *fakeStore) List(_ context.Context, tenantID string) ([]port.OptionalRoleState, error) {
	f.listed = append(f.listed, tenantID)
	return f.states, f.err
}

func (f *fakeStore) Enable(_ context.Context, c port.OptionalRoleChange) (port.OptionalRoleState, error) {
	f.enabled = append(f.enabled, c)
	return f.state, f.err
}

func (f *fakeStore) Disable(_ context.Context, c port.OptionalRoleChange) (port.OptionalRoleState, error) {
	f.disabled = append(f.disabled, c)
	return f.state, f.err
}

func service(store port.OptionalRoles) *optionalrole.Service {
	return &optionalrole.Service{Store: store, Clock: func() time.Time { return now }}
}

func request(role string) optionalrole.Request {
	return optionalrole.Request{TenantID: tenantID, ActorID: actorID, Role: role, CorrelationID: "corr-1"}
}

func TestA_ATenantStartsWithNoOptionalRoleEnabledAndTheListIsTheOneOfItsTenant(t *testing.T) {
	store := &fakeStore{states: []port.OptionalRoleState{{Role: "MANAGER"}, {Role: "ACCOUNTANT"}, {Role: "ANALYST"}}}
	got, err := service(store).List(context.Background(), optionalrole.Query{TenantID: tenantID})
	if err != nil || len(got) != 3 || !slices.Equal(store.listed, []string{tenantID}) {
		t.Fatalf("%v %v asked %v", got, err, store.listed)
	}
	for _, st := range got {
		if st.Enabled {
			t.Errorf("%s is enabled in a tenant that never enabled it", st.Role)
		}
	}
}

func TestA_TheListRefusesATenantThatIsNotAnIdBeforeTheStore(t *testing.T) {
	store := &fakeStore{}
	_, err := service(store).List(context.Background(), optionalrole.Query{TenantID: "not-a-uuid"})
	var invalid *optionalrole.FieldError
	if !errors.As(err, &invalid) || invalid.Field != "tenantId" || len(store.listed) != 0 {
		t.Fatalf("%v", err)
	}
}

func TestA_EnablingAndDisablingAskTheStoreForTheTenantTheActorAndTheInstantOfTheClock(t *testing.T) {
	for _, role := range []string{"MANAGER", "ACCOUNTANT", "ANALYST"} {
		store := &fakeStore{state: port.OptionalRoleState{Role: role, Enabled: true}}
		want := port.OptionalRoleChange{TenantID: tenantID, Role: role, By: "tenant-administrator/" + actorID, ActorID: actorID,
			ActorRole: "TENANT_ADMINISTRATOR", CorrelationID: "corr-1", Now: now}
		got, err := service(store).Enable(context.Background(), request(role))
		if err != nil || got.Role != role || len(store.enabled) != 1 || store.enabled[0] != want || len(store.disabled) != 0 {
			t.Errorf("enabling %s: %+v %v asked %+v", role, got, err, store.enabled)
		}
		if _, err := service(store).Disable(context.Background(), request(role)); err != nil || len(store.disabled) != 1 || store.disabled[0] != want {
			t.Errorf("disabling %s: %v asked %+v", role, err, store.disabled)
		}
	}
}

func TestA_ARoleThatIsNotOneOfTheThreeIsRefusedNamingTheFieldAndNoRouteCanCreateARole(t *testing.T) {
	for _, role := range []string{"TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "FINAL_CUSTOMER", "PLATFORM_ADMINISTRATOR", "SUPERUSER", "", "manager", "MANAGER "} {
		for action, do := range map[string]func(*optionalrole.Service) error{
			"enable": func(s *optionalrole.Service) error {
				_, err := s.Enable(context.Background(), request(role))
				return err
			},
			"disable": func(s *optionalrole.Service) error {
				_, err := s.Disable(context.Background(), request(role))
				return err
			},
		} {
			store := &fakeStore{}
			err := do(service(store))
			var invalid *optionalrole.FieldError
			if !errors.As(err, &invalid) || invalid.Field != "role" || !errors.Is(err, optionalrole.ErrInvalid) || len(store.enabled)+len(store.disabled) != 0 {
				t.Errorf("%s %q: %v", action, role, err)
			}
			if err != nil && role != "" && strings.Contains(err.Error(), role) {
				t.Errorf("the error shows the value %q: %v", role, err)
			}
		}
	}
}

func TestA_ATenantOrAnActorThatIsNotAnIdIsRefusedBeforeTheStore(t *testing.T) {
	for field, mutate := range map[string]func(*optionalrole.Request){
		"tenantId": func(r *optionalrole.Request) { r.TenantID = "" },
		"actorId":  func(r *optionalrole.Request) { r.ActorID = "someone" },
	} {
		store := &fakeStore{}
		r := request("MANAGER")
		mutate(&r)
		_, err := service(store).Enable(context.Background(), r)
		var invalid *optionalrole.FieldError
		if !errors.As(err, &invalid) || invalid.Field != field || len(store.enabled) != 0 {
			t.Errorf("%s: %v", field, err)
		}
	}
}

func TestA_DisablingARoleWithActiveHoldersIsRefusedAndTheRefusalsOfTheStoreReachTheCallerAsTheyAre(t *testing.T) {
	boom := errors.New("boom")
	for name, want := range map[string]error{"a role in use": port.ErrRoleInUse, "a transition that cannot be made": port.ErrStatusTransition, "a failure of ours": boom} {
		store := &fakeStore{err: want}
		if _, err := service(store).Disable(context.Background(), request("MANAGER")); !errors.Is(err, want) {
			t.Errorf("disabling, %s: %v", name, err)
		}
		if _, err := service(store).Enable(context.Background(), request("MANAGER")); !errors.Is(err, want) {
			t.Errorf("enabling, %s: %v", name, err)
		}
	}
}

func TestA_AServiceWithAPieceMissingOrACorrelationIdTheOutboxRefusesIsOurMistakeAndNotABadRequest(t *testing.T) {
	for name, s := range map[string]*optionalrole.Service{
		"no store": {Clock: func() time.Time { return now }},
		"no clock": {Store: &fakeStore{}},
	} {
		if _, err := s.Enable(context.Background(), request("MANAGER")); err == nil || errors.Is(err, optionalrole.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		// the list reads and never uses the clock: only a missing store is a wiring error for it
		if _, err := s.List(context.Background(), optionalrole.Query{TenantID: tenantID}); (name == "no store") != (err != nil) || errors.Is(err, optionalrole.ErrInvalid) {
			t.Errorf("%s, listing: %v", name, err)
		}
	}
	for name, id := range map[string]string{"none": "", "129 characters": strings.Repeat("c", 129)} {
		store := &fakeStore{}
		r := request("MANAGER")
		r.CorrelationID = id
		if _, err := service(store).Enable(context.Background(), r); err == nil || errors.Is(err, optionalrole.ErrInvalid) || len(store.enabled) != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}
