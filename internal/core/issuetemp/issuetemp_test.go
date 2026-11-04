package issuetemp_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/issuetemp"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-005, RN-SEC-003-14 and -15: who may issue a new temporary credential to whom, with the fake store.

const (
	tenantA   = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	tenantB   = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	actorID   = "7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	targetID  = "11111111-2222-4333-8444-555555555555"
	temporary = "Temporal-2026!"
	tenantAdm = "TENANT_ADMINISTRATOR"
	platform  = "PLATFORM_ADMINISTRATOR"
)

var now = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

type fakeStore struct {
	target  port.CredentialTarget
	found   bool
	asked   time.Time
	issued  []port.IssueCommand
	reg     port.Registered
	findErr error
	err     error
}

func (f *fakeStore) Target(_ context.Context, _ string, at time.Time) (port.CredentialTarget, bool, error) {
	f.asked = at
	return f.target, f.found, f.findErr
}

func (f *fakeStore) Issue(_ context.Context, c port.IssueCommand) (port.Registered, error) {
	f.issued = append(f.issued, c)
	return f.reg, f.err
}

type fakeHasher struct{ hashed []string }

func (h *fakeHasher) Compare(string, string) bool { return false }
func (h *fakeHasher) Hash(p string) (string, error) {
	h.hashed = append(h.hashed, p)
	return "hash-of-" + p, nil
}

// collaborator is a user of tenant A with a temporary credential that expired before the first sign-in.
func collaborator() *fakeStore {
	return &fakeStore{found: true, reg: port.Registered{Role: "OPERATIONAL_COLLABORATOR"}, target: port.CredentialTarget{
		AccountID: targetID, TenantID: tenantA, Active: true, HasTemporary: true}}
}

func administrator(first bool, ableToSignIn int) *fakeStore {
	s := collaborator()
	s.target.Administrator, s.target.FirstAdministrator, s.target.AdministratorsAbleToSignIn = true, first, ableToSignIn
	return s
}

func request(role, tenant string) issuetemp.Request {
	return issuetemp.Request{ActorID: actorID, ActorRole: role, ActorTenantID: tenant, AccountID: targetID, Password: temporary, Confirmation: temporary, CorrelationID: "corr-1"}
}

func issue(store *fakeStore, r issuetemp.Request) (*fakeHasher, error) {
	hasher := &fakeHasher{}
	_, err := (&issuetemp.Service{Store: store, Hasher: hasher, Clock: func() time.Time { return now }}).Issue(context.Background(), r)
	return hasher, err
}

func TestA_ANewTemporaryCredentialInvalidatesTheEarlierOneAndIsIssuedAtTheInstantOfTheClockWithTheIssuerAsActor(t *testing.T) {
	store := collaborator()
	hasher, err := issue(store, request(tenantAdm, tenantA))
	if err != nil {
		t.Fatal(err)
	}
	want := port.IssueCommand{TenantID: tenantA, AccountID: targetID, Hash: "hash-of-" + temporary, By: "tenant-administrator/" + actorID, ActorID: actorID,
		ActorRole: tenantAdm, CorrelationID: "corr-1", Now: now}
	if len(store.issued) != 1 || store.issued[0] != want || len(hasher.hashed) != 1 || !store.asked.Equal(now) {
		t.Fatalf("issued %+v hashed %v asked %v", store.issued, hasher.hashed, store.asked)
	}
}

func TestA_ATenantAdministratorIssuesToACollaboratorAndToAnAdministratorThatIsNotTheFirst(t *testing.T) {
	for name, store := range map[string]*fakeStore{"a collaborator": collaborator(), "an administrator they registered": administrator(false, 1)} {
		if _, err := issue(store, request(tenantAdm, tenantA)); err != nil || len(store.issued) != 1 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestA_ATenantAdministratorCannotIssueToTheFirstAdministratorWhateverTheState(t *testing.T) {
	for _, able := range []int{0, 3} {
		store := administrator(true, able)
		_, err := issue(store, request(tenantAdm, tenantA))
		if !errors.Is(err, issuetemp.ErrNotAuthorized) || len(store.issued) != 0 {
			t.Errorf("able=%d: %v issued %d", able, err, len(store.issued))
		}
	}
}

func TestA_ThePlatformAdministratorIssuesToTheFirstAdministratorOfAnyTenant(t *testing.T) {
	for _, able := range []int{0, 2} {
		store := administrator(true, able)
		store.target.TenantID = tenantB
		if _, err := issue(store, request(platform, "")); err != nil || len(store.issued) != 1 || store.issued[0].TenantID != tenantB ||
			store.issued[0].By != "platform-administrator/"+actorID || store.issued[0].ActorRole != platform {
			t.Errorf("able=%d: %v %+v", able, err, store.issued)
		}
	}
}

func TestA_WithNoAdministratorAbleToSignInThePlatformIssuesToAnyActiveAdministrator(t *testing.T) {
	store := administrator(false, 0)
	if _, err := issue(store, request(platform, "")); err != nil || len(store.issued) != 1 {
		t.Fatalf("%v", err)
	}
}

func TestA_WithAnAdministratorAbleToSignInThePlatformIssuesOnlyToTheFirst(t *testing.T) {
	store := administrator(false, 1)
	if _, err := issue(store, request(platform, "")); !errors.Is(err, issuetemp.ErrNotAuthorized) || len(store.issued) != 0 {
		t.Fatalf("%v issued %d", err, len(store.issued))
	}
}

func TestA_ThePlatformNeverIssuesToAUserWhoIsNotAnAdministratorNorToAnInactiveOne(t *testing.T) {
	inactive := administrator(false, 0)
	inactive.target.Active = false
	for name, store := range map[string]*fakeStore{"a collaborator": collaborator(), "an inactive administrator": inactive} {
		if _, err := issue(store, request(platform, "")); !errors.Is(err, issuetemp.ErrNotAuthorized) || len(store.issued) != 0 {
			t.Errorf("%s: %v issued %d", name, err, len(store.issued))
		}
	}
}

func TestA_AnAccountThatChoseItsOwnPasswordIsRefusedBeforeHashing(t *testing.T) {
	store := collaborator()
	store.target.HasTemporary = false
	hasher, err := issue(store, request(tenantAdm, tenantA))
	if !errors.Is(err, port.ErrNotTemporary) || len(store.issued) != 0 || len(hasher.hashed) != 0 {
		t.Fatalf("%v issued %d hashed %d", err, len(store.issued), len(hasher.hashed))
	}
}

func TestA_AUserOfAnotherTenantOrNoUserAtAllIsNotFoundForATenantAdministrator(t *testing.T) {
	other := collaborator()
	other.target.TenantID = tenantB
	for name, store := range map[string]*fakeStore{"a user of another tenant": other, "no user": {}} {
		hasher, err := issue(store, request(tenantAdm, tenantA))
		if !errors.Is(err, port.ErrUserNotFound) || len(store.issued) != 0 || len(hasher.hashed) != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestA_ThePasswordAndItsConfirmationFollowThePolicyAndNothingIsHashedOrIssuedOtherwise(t *testing.T) {
	for field, mutate := range map[string]func(*issuetemp.Request){
		"passwordConfirmation": func(r *issuetemp.Request) { r.Confirmation = temporary + "x" },
		"password":             func(r *issuetemp.Request) { r.Password, r.Confirmation = "weak", "weak" },
	} {
		store := collaborator()
		r := request(tenantAdm, tenantA)
		mutate(&r)
		hasher, err := issue(store, r)
		var invalid *issuetemp.FieldError
		if !errors.As(err, &invalid) || invalid.Field != field || !errors.Is(err, issuetemp.ErrInvalid) || len(store.issued) != 0 || len(hasher.hashed) != 0 {
			t.Errorf("%s: %v", field, err)
		}
		if strings.Contains(err.Error(), "weak") {
			t.Errorf("%s: the error shows the password: %v", field, err)
		}
	}
}

func TestA_AnIdThatIsNotAnIdIsRefusedNamingTheFieldBeforeTheStore(t *testing.T) {
	for field, mutate := range map[string]func(*issuetemp.Request){
		"accountId": func(r *issuetemp.Request) { r.AccountID = "not-a-uuid" },
		"actorId":   func(r *issuetemp.Request) { r.ActorID = "someone" },
	} {
		store := collaborator()
		r := request(tenantAdm, tenantA)
		mutate(&r)
		_, err := issue(store, r)
		var invalid *issuetemp.FieldError
		if !errors.As(err, &invalid) || invalid.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
}

func TestA_ARoleThatCannotIssueOrAPieceMissingIsOurMistakeAndNotABadRequest(t *testing.T) {
	for name, r := range map[string]issuetemp.Request{
		"a collaborator":                    request("OPERATIONAL_COLLABORATOR", tenantA),
		"a tenant administrator, no tenant": request(tenantAdm, ""),
		"no correlation id":                 func() issuetemp.Request { r := request(tenantAdm, tenantA); r.CorrelationID = ""; return r }(),
		"a correlation id of 129": func() issuetemp.Request {
			r := request(tenantAdm, tenantA)
			r.CorrelationID = strings.Repeat("c", 129)
			return r
		}(),
	} {
		store := collaborator()
		if _, err := issue(store, r); err == nil || errors.Is(err, issuetemp.ErrInvalid) || len(store.issued) != 0 {
			t.Errorf("%s: %v issued %d", name, err, len(store.issued))
		}
	}
	if _, err := (&issuetemp.Service{}).Issue(context.Background(), request(tenantAdm, tenantA)); err == nil || errors.Is(err, issuetemp.ErrInvalid) {
		t.Fatalf("a service with no pieces: %v", err)
	}
}

func TestA_TheFailuresOfTheStoreReachTheCallerAsTheyAre(t *testing.T) {
	boom := errors.New("boom")
	find := collaborator()
	find.findErr = boom
	write := collaborator()
	write.err = boom
	for name, store := range map[string]*fakeStore{"reading the target": find, "issuing": write} {
		if _, err := issue(store, request(tenantAdm, tenantA)); !errors.Is(err, boom) {
			t.Errorf("%s: %v", name, err)
		}
	}
	late := collaborator()
	late.err = port.ErrNotTemporary
	if _, err := issue(late, request(tenantAdm, tenantA)); !errors.Is(err, port.ErrNotTemporary) {
		t.Fatalf("an account that chose its password between the read and the write: %v", err)
	}
}
