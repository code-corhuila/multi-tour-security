package postgres_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

const customerScope = "customer:" + tenant

func newAccount(email string) port.NewAccount {
	return port.NewAccount{TenantID: tenant, EmailNormalized: email, PasswordHash: pgtest.ValidHash, FullName: "Ana Perez",
		Phone: "+57 300 123 4567", Role: "FINAL_CUSTOMER", CreatedBy: "customer"}
}

func rows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.`+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func registrySetup(t *testing.T) (*postgres.Registry, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewRegistry(pool), pool
}

func TestI_TheCustomerCanBeReadBackActiveAndUnverified(t *testing.T) {
	registry, pool := registrySetup(t)
	got, err := registry.Create(ctx, newAccount("ana@example.com"), customerScope, "key-0001-abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got.Account.ID == "" || got.Account.TenantID != tenant || got.Account.Status != account.Active || got.EmailVerified ||
		got.Role != "FINAL_CUSTOMER" || got.FullName != "Ana Perez" || got.Phone != "+57 300 123 4567" || !got.Account.TemporaryUntil.IsZero() {
		t.Fatalf("not the account that was asked for: %+v", got)
	}
	var verified bool
	if err := pool.QueryRow(ctx, `SELECT email_verified FROM security.identity WHERE identity_id = $1::uuid`, got.Account.ID).Scan(&verified); err != nil || verified {
		t.Fatalf("the e-mail starts unverified: %v %v", verified, err)
	}
	roles, err := postgres.NewAccounts(pool).RolesOf(ctx, got.Account.ID)
	if err != nil || len(roles) != 1 || roles[0] != "FINAL_CUSTOMER" {
		t.Fatalf("roles %v %v", roles, err)
	}
}

func TestI_KeyAndAccountAreWrittenInOneTransaction(t *testing.T) {
	registry, pool := registrySetup(t)
	bad := newAccount("ana@example.com")
	bad.Role = "NOT_A_ROLE" // refused by the table after the identity and the membership were written
	if _, err := registry.Create(ctx, bad, customerScope, "key-0001-abcd"); err == nil {
		t.Fatal("an invalid role must be refused")
	}
	for _, table := range []string{"identity", "membership", "membership_role", "idempotency_key"} {
		if n := rows(t, pool, table); n != 0 {
			t.Errorf("%s kept %d rows of a refused account", table, n)
		}
	}
}

func TestI_TheUniqueKeyRefusesTheSameEmailEvenWhenInactive(t *testing.T) {
	registry, pool := registrySetup(t)
	if _, err := pgtest.AccountWith(ctx, pool, tenant, "off@example.com", pgtest.ValidHash, pgtest.Options{Inactive: true}, "ANALYST"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Create(ctx, newAccount("off@example.com"), customerScope, "key-0001-abcd"); !errors.Is(err, port.ErrEmailTaken) {
		t.Fatalf("want ErrEmailTaken, got %v", err)
	}
	if n := rows(t, pool, "idempotency_key"); n != 0 {
		t.Errorf("a refused account left %d keys", n)
	}
	// a different key does not help
	if _, err := registry.Create(ctx, newAccount("off@example.com"), customerScope, "key-0002-abcd"); !errors.Is(err, port.ErrEmailTaken) {
		t.Fatalf("want ErrEmailTaken, got %v", err)
	}
}

func TestI_SameEmailInTwoTenantsMakesTwoAccountsWithTheirOwnHash(t *testing.T) {
	registry, pool := registrySetup(t)
	other := "$2a$12$ZYXWVUTSRQPONMLKJIHGFEdcbaabcdefghijklmnopqrstuvwxyz0"
	b := newAccount("ana@example.com")
	b.TenantID, b.PasswordHash = otherTenant, other
	first, err := registry.Create(ctx, newAccount("ana@example.com"), customerScope, "key-0001-abcd")
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.Create(ctx, b, "customer:"+otherTenant, "key-0001-abcd") // the same key is another intent in another tenant
	if err != nil {
		t.Fatal(err)
	}
	if first.Account.ID == second.Account.ID || first.Account.PasswordHash == second.Account.PasswordHash || rows(t, pool, "identity") != 2 {
		t.Fatalf("two tenants must make two accounts: %+v %+v", first.Account, second.Account)
	}
}

func TestI_TwoRequestsWithTheSameKeyMakeOneAccountAndTheLoserGetsKeyTaken(t *testing.T) {
	registry, pool := registrySetup(t)
	const workers = 8
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = registry.Create(ctx, newAccount("ana@example.com"), customerScope, "key-0001-abcd")
		}()
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, port.ErrKeyTaken):
			t.Errorf("a loser must get ErrKeyTaken and never ErrEmailTaken, got %v", err)
		}
	}
	if wins != 1 || rows(t, pool, "identity") != 1 || rows(t, pool, "idempotency_key") != 1 {
		t.Fatalf("wins=%d identities=%d keys=%d", wins, rows(t, pool, "identity"), rows(t, pool, "idempotency_key"))
	}
}

func TestI_FindKeyReturnsTheAccountThatKeyMade(t *testing.T) {
	registry, _ := registrySetup(t)
	if _, found, err := registry.FindKey(ctx, customerScope, "key-0001-abcd"); err != nil || found {
		t.Fatalf("unknown key: %v %v", found, err)
	}
	made, err := registry.Create(ctx, newAccount("ana@example.com"), customerScope, "key-0001-abcd")
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := registry.FindKey(ctx, customerScope, "key-0001-abcd")
	if err != nil || !found || got.Account.ID != made.Account.ID || got.Role != "FINAL_CUSTOMER" || got.FullName != "Ana Perez" ||
		got.Phone != "+57 300 123 4567" || got.Account.PasswordHash != made.Account.PasswordHash {
		t.Fatalf("%+v %v %v", got, found, err)
	}
	if _, found, _ := registry.FindKey(ctx, "user:"+tenant, "key-0001-abcd"); found {
		t.Error("the same key in another scope is another intent")
	}
}

func TestI_NoSecretIsStoredInClear(t *testing.T) {
	registry, pool := registrySetup(t)
	n := newAccount("ana@example.com")
	if _, err := registry.Create(ctx, n, customerScope, "key-0001-abcd"); err != nil {
		t.Fatal(err)
	}
	var row string
	if err := pool.QueryRow(ctx, `SELECT i::text FROM security.identity i`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(row, n.PasswordHash) {
		t.Fatalf("the hash is what is stored: %s", row)
	}
	// a clear password is refused by the shape of the column
	n.EmailNormalized, n.PasswordHash = "bo@example.com", "Secret-Passw0rd!"
	if _, err := registry.Create(ctx, n, customerScope, "key-0002-abcd"); err == nil || errors.Is(err, port.ErrEmailTaken) {
		t.Fatalf("a clear password must be refused by the table, got %v", err)
	}
}

func TestI_ATemporaryCredentialStoresItsExpiry(t *testing.T) {
	registry, pool := registrySetup(t)
	n := newAccount("user@example.com")
	n.Role, n.CreatedBy = "MANAGER", "tenant-administrator/abc"
	n.TemporaryUntil = time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	got, err := registry.Create(ctx, n, "user:"+tenant, "key-0001-abcd")
	if err != nil || !got.Account.TemporaryUntil.Equal(n.TemporaryUntil) {
		t.Fatalf("%+v %v", got.Account, err)
	}
	read, found, err := postgres.NewAccounts(pool).FindByID(ctx, got.Account.ID)
	if err != nil || !found || !read.TemporaryUntil.Equal(n.TemporaryUntil) {
		t.Fatalf("the expiry was not stored: %+v %v %v", read, found, err)
	}
}
