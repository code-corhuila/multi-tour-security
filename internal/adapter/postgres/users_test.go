package postgres_test

import (
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HU-SEC-005, RN-SEC-003-07: the list of the internal users of a tenant, against the real engine.

var internalRoles = []string{"TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "MANAGER", "ACCOUNTANT", "ANALYST"}

func directory(t *testing.T) (*postgres.UserDirectory, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewUserDirectory(pool), pool
}

func user(t *testing.T, pool *pgxpool.Pool, tenantID, email string, o pgtest.Options, roles ...string) string {
	t.Helper()
	id, err := pgtest.AccountWith(ctx, pool, tenantID, email, pgtest.ValidHash, o, roles...)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// createdAt puts the account in an exact place of the order of the list.
func createdAt(t *testing.T, pool *pgxpool.Pool, id string, at time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `UPDATE security.identity SET created_at = $2 WHERE identity_id = $1::uuid`, id, at); err != nil {
		t.Fatal(err)
	}
}

func emails(users []port.Registered) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.Account.EmailNormalized)
	}
	return out
}

func TestI_ListShowsOnlyTheInternalUsersOfTheTenantAndNeverACustomerOrAnotherTenantOrTheHash(t *testing.T) {
	dir, pool := directory(t)
	user(t, pool, tenant, "admin@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	user(t, pool, tenant, "colab@example.com", pgtest.Options{TemporaryUntil: time.Now().Add(72 * time.Hour)}, "OPERATIONAL_COLLABORATOR")
	user(t, pool, tenant, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	user(t, pool, tenant, "pending@example.com", pgtest.Options{Pending: true}, "FINAL_CUSTOMER")
	user(t, pool, otherTenant, "other@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	user(t, pool, "", "root@example.com", pgtest.Options{}, "PLATFORM_ADMINISTRATOR")

	got, total, err := dir.List(ctx, tenant, port.UserFilter{Roles: internalRoles}, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("total=%d users=%v, want only the admin and the collaborator of the tenant", total, emails(got))
	}
	for _, u := range got {
		if u.Account.PasswordHash != "" {
			t.Fatalf("the list carries a hash: %+v", u)
		}
		if u.Account.TenantID != tenant {
			t.Fatalf("a user of another tenant is listed: %+v", u)
		}
	}
	byEmail := map[string]port.Registered{got[0].Account.EmailNormalized: got[0], got[1].Account.EmailNormalized: got[1]}
	if c := byEmail["colab@example.com"]; c.Role != "OPERATIONAL_COLLABORATOR" || c.Account.TemporaryUntil.IsZero() || c.Account.Status != account.Active {
		t.Fatalf("the collaborator shows %+v: its role and the end of its temporary credential are what the screen needs", c)
	}
}

func TestI_ListIsNewestFirstWithAStablePageAndTheRightTotal(t *testing.T) {
	dir, pool := directory(t)
	base := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for i, email := range []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com"} {
		id := user(t, pool, tenant, email, pgtest.Options{}, "ANALYST")
		// c and d are made in the same instant: the order of the page must still be stable
		at := base.Add(time.Duration(i) * time.Hour)
		if email == "d@example.com" {
			at = base.Add(2 * time.Hour)
		}
		createdAt(t, pool, id, at)
	}
	seen := map[string]bool{}
	var order []string
	for page := 0; page < 3; page++ {
		got, total, err := dir.List(ctx, tenant, port.UserFilter{Roles: internalRoles}, 2, page*2)
		if err != nil {
			t.Fatal(err)
		}
		if total != 5 {
			t.Fatalf("page %d: total = %d", page, total)
		}
		for _, e := range emails(got) {
			if seen[e] {
				t.Fatalf("%s is on two pages: %v", e, order)
			}
			seen[e] = true
			order = append(order, e)
		}
	}
	if len(order) != 5 || order[0] != "e@example.com" || order[4] != "a@example.com" {
		t.Fatalf("order = %v, want the newest first and the oldest last", order)
	}
	again, _, _ := dir.List(ctx, tenant, port.UserFilter{Roles: internalRoles}, 5, 0)
	for i, e := range emails(again) {
		if e != order[i] {
			t.Fatalf("a second read gives another order: %v vs %v", emails(again), order)
		}
	}
}

func TestI_APageBeyondTheEndIsEmptyAndStillKnowsTheTotal(t *testing.T) {
	dir, pool := directory(t)
	user(t, pool, tenant, "a@example.com", pgtest.Options{}, "MANAGER")
	user(t, pool, tenant, "b@example.com", pgtest.Options{}, "MANAGER")
	got, total, err := dir.List(ctx, tenant, port.UserFilter{Roles: internalRoles}, 20, 100)
	if err != nil || len(got) != 0 || total != 2 {
		t.Fatalf("users=%d total=%d err=%v", len(got), total, err)
	}
	none, total, err := dir.List(ctx, otherTenant, port.UserFilter{Roles: internalRoles}, 20, 0)
	if err != nil || len(none) != 0 || total != 0 {
		t.Fatalf("a tenant with nobody: users=%d total=%d err=%v", len(none), total, err)
	}
}

func TestI_TheFiltersNarrowByRoleAndByStatus(t *testing.T) {
	dir, pool := directory(t)
	user(t, pool, tenant, "admin@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	user(t, pool, tenant, "m1@example.com", pgtest.Options{}, "MANAGER")
	user(t, pool, tenant, "m2@example.com", pgtest.Options{Inactive: true}, "MANAGER")
	user(t, pool, tenant, "acc@example.com", pgtest.Options{Inactive: true}, "ACCOUNTANT")

	cases := []struct {
		name   string
		filter port.UserFilter
		want   int
	}{
		{"everyone", port.UserFilter{Roles: internalRoles}, 4},
		{"managers", port.UserFilter{Roles: []string{"MANAGER"}}, 2},
		{"inactive", port.UserFilter{Roles: internalRoles, Status: "INACTIVE"}, 2},
		{"active managers", port.UserFilter{Roles: []string{"MANAGER"}, Status: "ACTIVE"}, 1},
		{"inactive analysts", port.UserFilter{Roles: []string{"ANALYST"}, Status: "INACTIVE"}, 0},
		{"pending internal users do not exist", port.UserFilter{Roles: internalRoles, Status: "PENDING"}, 0},
	}
	for _, c := range cases {
		got, total, err := dir.List(ctx, tenant, c.filter, 20, 0)
		if err != nil || len(got) != c.want || total != c.want {
			t.Errorf("%s: users=%d total=%d err=%v, want %d", c.name, len(got), total, err, c.want)
		}
	}
}
