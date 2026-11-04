package changepermission_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/changepermission"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-006, RN-SEC-005-03 to -07 and -10: who may be assigned or relieved of which permission, with the fake store.

const (
	tenantID  = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	accountID = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	actorID   = "7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

var (
	now  = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	four = []string{"VALIDATE_PAYMENT_PROOFS", "MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "CONSULT_SENSITIVE_DATA"}
)

type fakeStore struct {
	holder      port.PermissionHolder
	holderErr   error
	holderCalls int
	grants      []port.PermissionChange
	removals    []port.PermissionChange
	reg         port.Registered
	err         error
}

func (f *fakeStore) Holder(context.Context, string, string) (port.PermissionHolder, error) {
	f.holderCalls++
	return f.holder, f.holderErr
}

func (f *fakeStore) Grant(_ context.Context, c port.PermissionChange) (port.Registered, error) {
	f.grants = append(f.grants, c)
	return f.reg, f.err
}

func (f *fakeStore) Remove(_ context.Context, c port.PermissionChange) (port.Registered, error) {
	f.removals = append(f.removals, c)
	return f.reg, f.err
}

func service(store port.UserPermissions) *changepermission.Service {
	return &changepermission.Service{Store: store, Clock: func() time.Time { return now }}
}

func request(permission string) changepermission.Request {
	return changepermission.Request{TenantID: tenantID, AccountID: accountID, ActorID: actorID, Permission: permission, CorrelationID: "corr-1"}
}

func holding(role string, held ...string) *fakeStore {
	return &fakeStore{holder: port.PermissionHolder{Role: role, Held: held}, reg: port.Registered{Role: role}}
}

func TestA_ACollaboratorReceivesEachOfTheFourAndTheStoreGetsTheTenantTheActorAndTheInstant(t *testing.T) {
	for _, p := range four {
		store := holding("OPERATIONAL_COLLABORATOR")
		got, err := service(store).Grant(context.Background(), request(p))
		want := port.PermissionChange{TenantID: tenantID, AccountID: accountID, Permission: p, By: "tenant-administrator/" + actorID, ActorID: actorID,
			ActorRole: "TENANT_ADMINISTRATOR", CorrelationID: "corr-1", Now: now}
		if err != nil || got.Role != "OPERATIONAL_COLLABORATOR" || len(store.grants) != 1 || store.grants[0] != want {
			t.Errorf("%s: %+v %v asked %+v", p, got, err, store.grants)
		}
	}
}

func TestA_AnAdministratorAssignsSensitiveDataToThemselvesAndToAnotherAdministrator(t *testing.T) {
	store := holding("TENANT_ADMINISTRATOR")
	r := request("CONSULT_SENSITIVE_DATA")
	r.AccountID = actorID // their own account
	if _, err := service(store).Grant(context.Background(), r); err != nil || len(store.grants) != 1 {
		t.Fatalf("%v", err)
	}
}

func TestA_AProfilePermissionOfAnAdministratorIsNeitherAssignedNorRemoved(t *testing.T) {
	for _, p := range []string{"VALIDATE_PAYMENT_PROOFS", "MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION"} {
		store := holding("TENANT_ADMINISTRATOR")
		if _, err := service(store).Grant(context.Background(), request(p)); !errors.Is(err, changepermission.ErrProfilePermission) || len(store.grants) != 0 {
			t.Errorf("assigning %s: %v", p, err)
		}
		if _, err := service(store).Remove(context.Background(), request(p)); !errors.Is(err, changepermission.ErrProfilePermission) || len(store.removals) != 0 {
			t.Errorf("removing %s: %v", p, err)
		}
	}
}

func TestA_AnOptionalRoleACustomerAndThePlatformNeverReceiveAnySpecialPermission(t *testing.T) {
	for _, role := range []string{"MANAGER", "ACCOUNTANT", "ANALYST", "FINAL_CUSTOMER", "PLATFORM_ADMINISTRATOR", ""} {
		for _, p := range four {
			store := holding(role)
			if _, err := service(store).Grant(context.Background(), request(p)); !errors.Is(err, changepermission.ErrNotAssignable) || len(store.grants) != 0 {
				t.Errorf("%q, %s: %v asked %d times", role, p, err, len(store.grants))
			}
		}
	}
}

func TestA_ARemovalIsNotRefusedForARoleThatCannotHoldItSoAStrayRowCanBeCleaned(t *testing.T) {
	store := holding("MANAGER", "MANAGE_CASH")
	if _, err := service(store).Remove(context.Background(), request("MANAGE_CASH")); err != nil || len(store.removals) != 1 {
		t.Fatalf("%v", err)
	}
}

func TestA_AssigningCutsNoSessionAndRemovingIsTheOnlyWayThatDoes(t *testing.T) {
	store := holding("OPERATIONAL_COLLABORATOR")
	if _, err := service(store).Grant(context.Background(), request("MANAGE_CASH")); err != nil || len(store.removals) != 0 || len(store.grants) != 1 {
		t.Fatalf("assigning asked the store to remove: %v", err)
	}
	if _, err := service(store).Remove(context.Background(), request("MANAGE_CASH")); err != nil || len(store.removals) != 1 {
		t.Fatalf("%v", err)
	}
}

func TestA_APermissionOutsideTheFourAndAnIdThatIsNotAnIdAreRefusedNamingTheFieldAndTheStoreIsNeverCalled(t *testing.T) {
	for name, c := range map[string]struct {
		mutate func(*changepermission.Request)
		field  string
	}{
		"a permission outside the four": {func(r *changepermission.Request) { r.Permission = "SUPERUSER" }, "permission"},
		"no permission":                 {func(r *changepermission.Request) { r.Permission = "" }, "permission"},
		"a literal in lower case":       {func(r *changepermission.Request) { r.Permission = "manage_cash" }, "permission"},
		"a Spanish screen name":         {func(r *changepermission.Request) { r.Permission = "Gestionar caja" }, "permission"},
		"an account that is not an id":  {func(r *changepermission.Request) { r.AccountID = "not-a-uuid" }, "accountId"},
		"no tenant":                     {func(r *changepermission.Request) { r.TenantID = "" }, "tenantId"},
		"an actor that is not an id":    {func(r *changepermission.Request) { r.ActorID = "someone" }, "actorId"},
	} {
		for action, do := range map[string]func(*changepermission.Service, changepermission.Request) error{
			"grant": func(s *changepermission.Service, r changepermission.Request) error {
				_, err := s.Grant(context.Background(), r)
				return err
			},
			"remove": func(s *changepermission.Service, r changepermission.Request) error {
				_, err := s.Remove(context.Background(), r)
				return err
			},
		} {
			store := holding("OPERATIONAL_COLLABORATOR")
			r := request("MANAGE_CASH")
			c.mutate(&r)
			err := do(service(store), r)
			var invalid *changepermission.FieldError
			if !errors.As(err, &invalid) || invalid.Field != c.field || !errors.Is(err, changepermission.ErrInvalid) ||
				store.holderCalls != 0 || len(store.grants)+len(store.removals) != 0 {
				t.Errorf("%s, %s: %v", name, action, err)
			}
			if err != nil && strings.Contains(err.Error(), "SUPERUSER") {
				t.Errorf("%s: the error shows the value: %v", name, err)
			}
		}
	}
}

func TestA_TheRefusalsAndTheFailuresOfTheStoreReachTheCallerAsTheyAre(t *testing.T) {
	boom := errors.New("boom")
	missing := holding("OPERATIONAL_COLLABORATOR")
	missing.holderErr = port.ErrUserNotFound
	reading := holding("OPERATIONAL_COLLABORATOR")
	reading.holderErr = boom
	writing := holding("OPERATIONAL_COLLABORATOR")
	writing.err = boom
	for name, c := range map[string]struct {
		store *fakeStore
		want  error
	}{"a user that is not there": {missing, port.ErrUserNotFound}, "a failure reading": {reading, boom}, "a failure writing": {writing, boom}} {
		if _, err := service(c.store).Grant(context.Background(), request("MANAGE_CASH")); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := service(c.store).Remove(context.Background(), request("MANAGE_CASH")); !errors.Is(err, c.want) {
			t.Errorf("%s, removing: %v", name, err)
		}
	}
}

func TestA_AServiceWithAPieceMissingOrACorrelationIdTheOutboxRefusesIsOurMistakeAndNotABadRequest(t *testing.T) {
	for name, s := range map[string]*changepermission.Service{
		"no store": {Clock: func() time.Time { return now }},
		"no clock": {Store: holding("OPERATIONAL_COLLABORATOR")},
	} {
		if _, err := s.Grant(context.Background(), request("MANAGE_CASH")); err == nil || errors.Is(err, changepermission.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, id := range map[string]string{"none": "", "129 characters": strings.Repeat("c", 129)} {
		store := holding("OPERATIONAL_COLLABORATOR")
		r := request("MANAGE_CASH")
		r.CorrelationID = id
		if _, err := service(store).Grant(context.Background(), r); err == nil || errors.Is(err, changepermission.ErrInvalid) || len(store.grants) != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestA_TheRulesAreTheTableOfTheAccountAndNothingElse(t *testing.T) {
	for _, role := range account.InternalRoles() {
		for _, p := range four {
			store := holding(role)
			_, err := service(store).Grant(context.Background(), request(p))
			profile := role == account.RoleTenantAdministrator && p != "CONSULT_SENSITIVE_DATA"
			switch {
			case profile && !errors.Is(err, changepermission.ErrProfilePermission):
				t.Errorf("%s, %s: %v", role, p, err)
			case !profile && account.Assignable(role, p) != (err == nil):
				t.Errorf("%s, %s: Assignable says %v and the use case %v", role, p, account.Assignable(role, p), err)
			}
		}
	}
}
