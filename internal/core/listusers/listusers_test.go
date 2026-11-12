package listusers_test

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/listusers"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-005, RN-SEC-003-07: the list of the internal users of a tenant, with the fake store.

const tenantID = "7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"

type fakeDirectory struct {
	tenant string
	filter port.UserFilter
	limit  int
	offset int
	calls  int
	users  []port.Registered
	total  int
	err    error
}

func (f *fakeDirectory) List(_ context.Context, tenantID string, filter port.UserFilter, limit, offset int) ([]port.Registered, int, error) {
	f.calls++
	f.tenant, f.filter, f.limit, f.offset = tenantID, filter, limit, offset
	return f.users, f.total, f.err
}

func ask(t *testing.T, dir *fakeDirectory, q listusers.Query) (listusers.Page, error) {
	t.Helper()
	return (&listusers.Service{Directory: dir}).List(context.Background(), q)
}

func TestA_TheListAlwaysAsksForTheFiveInternalRolesOfTheTenantAndNothingElse(t *testing.T) {
	dir := &fakeDirectory{}
	if _, err := ask(t, dir, listusers.Query{TenantID: tenantID, Page: 1, Limit: 20}); err != nil {
		t.Fatal(err)
	}
	want := []string{"ACCOUNTANT", "ANALYST", "MANAGER", "OPERATIONAL_COLLABORATOR", "TENANT_ADMINISTRATOR"}
	got := slices.Clone(dir.filter.Roles)
	slices.Sort(got)
	if dir.tenant != tenantID || !slices.Equal(got, want) || dir.filter.Status != "" {
		t.Fatalf("the store was asked %q %+v: a customer or a platform role must never be listed", dir.tenant, dir.filter)
	}
}

func TestA_AFilterByRoleNarrowsToThatRoleAndAStatusIsPassedOn(t *testing.T) {
	dir := &fakeDirectory{}
	if _, err := ask(t, dir, listusers.Query{TenantID: tenantID, Role: "MANAGER", Status: "INACTIVE", Page: 1, Limit: 20}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dir.filter.Roles, []string{"MANAGER"}) || dir.filter.Status != "INACTIVE" {
		t.Fatalf("the filter is %+v", dir.filter)
	}
}

func TestA_ARoleThatIsNotInternalOrAStatusThatDoesNotExistIsRefusedNamingTheFieldAndTheStoreIsNotAsked(t *testing.T) {
	for _, c := range []struct {
		name  string
		q     listusers.Query
		field string
	}{
		{"a customer role", listusers.Query{TenantID: tenantID, Role: "FINAL_CUSTOMER", Page: 1, Limit: 20}, "role"},
		{"the platform role", listusers.Query{TenantID: tenantID, Role: "PLATFORM_ADMINISTRATOR", Page: 1, Limit: 20}, "role"},
		{"a role in lower case", listusers.Query{TenantID: tenantID, Role: "manager", Page: 1, Limit: 20}, "role"},
		{"an unknown status", listusers.Query{TenantID: tenantID, Status: "DELETED", Page: 1, Limit: 20}, "status"},
		{"page zero", listusers.Query{TenantID: tenantID, Page: 0, Limit: 20}, "page"},
		{"a page whose offset would overflow", listusers.Query{TenantID: tenantID, Page: math.MaxInt, Limit: 100}, "page"},
		{"a page whose offset would wrap to a negative", listusers.Query{TenantID: tenantID, Page: math.MaxInt, Limit: 2}, "page"},
		{"limit zero", listusers.Query{TenantID: tenantID, Page: 1, Limit: 0}, "limit"},
		{"limit over 100", listusers.Query{TenantID: tenantID, Page: 1, Limit: 101}, "limit"},
		{"no tenant", listusers.Query{Page: 1, Limit: 20}, "tenantId"},
		{"a tenant that is not an id", listusers.Query{TenantID: "not-a-uuid", Page: 1, Limit: 20}, "tenantId"},
	} {
		dir := &fakeDirectory{}
		_, err := ask(t, dir, c.q)
		var invalid *listusers.FieldError
		if !errors.As(err, &invalid) || invalid.Field != c.field || !errors.Is(err, listusers.ErrInvalid) || dir.calls != 0 {
			t.Errorf("%s: err=%v field=%q store asked %d times", c.name, err, c.field, dir.calls)
		}
	}
}

func TestA_ThePageIsWorkedOutFromTheTotalAndAnEmptyListIsNotNil(t *testing.T) {
	for _, c := range []struct {
		page, limit, total, offset, pages int
	}{
		{1, 20, 0, 0, 0},
		{1, 20, 20, 0, 1},
		{1, 20, 21, 0, 2},
		{3, 10, 25, 20, 3},
		{5, 10, 25, 40, 3},
	} {
		dir := &fakeDirectory{total: c.total}
		got, err := ask(t, dir, listusers.Query{TenantID: tenantID, Page: c.page, Limit: c.limit})
		if err != nil || dir.offset != c.offset || dir.limit != c.limit || got.Total != c.total || got.TotalPages != c.pages || got.Page != c.page || got.Limit != c.limit || got.Data == nil {
			t.Errorf("%+v: err=%v offset=%d got=%+v", c, err, dir.offset, got)
		}
	}
}

func TestA_ThePassedRolesAreACopyThatTheStoreCannotUseToChangeTheListOfInternalRoles(t *testing.T) {
	first := &fakeDirectory{}
	_, _ = ask(t, first, listusers.Query{TenantID: tenantID, Page: 1, Limit: 20})
	slices.Sort(first.filter.Roles)
	second := &fakeDirectory{}
	_, _ = ask(t, second, listusers.Query{TenantID: tenantID, Page: 1, Limit: 20})
	if second.filter.Roles[0] != "TENANT_ADMINISTRATOR" {
		t.Fatalf("a store that sorted the roles changed the next request: %v", second.filter.Roles)
	}
}

func TestA_TheUsersComeAsTheStoreGaveThemAndAFailureIsNotHidden(t *testing.T) {
	dir := &fakeDirectory{users: []port.Registered{{Role: "MANAGER"}, {Role: "ANALYST"}}, total: 2}
	got, err := ask(t, dir, listusers.Query{TenantID: tenantID, Page: 1, Limit: 20})
	if err != nil || len(got.Data) != 2 || got.Data[0].Role != "MANAGER" {
		t.Fatalf("%+v %v", got, err)
	}
	boom := errors.New("boom")
	if _, err := ask(t, &fakeDirectory{err: boom}, listusers.Query{TenantID: tenantID, Page: 1, Limit: 20}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := (&listusers.Service{}).List(context.Background(), listusers.Query{TenantID: tenantID, Page: 1, Limit: 20}); err == nil || errors.Is(err, listusers.ErrInvalid) {
		t.Fatalf("a service with no store must fail as a wiring error, got %v", err)
	}
}
