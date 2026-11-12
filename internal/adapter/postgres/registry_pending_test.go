package postgres_test

import (
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// The tests below cover the creation of a customer account that waits for its e-mail (spec 004-hu-sec-003, RN-SEC-004-01, -02).

func pendingAccount(email string, l port.NewLink) port.NewAccount {
	n := newAccount(email)
	n.Pending, n.Link = true, &l
	return n
}

func TestI_ACustomerAccountIsCreatedPendingWithItsFirstLink(t *testing.T) {
	registry, pool := registrySetup(t)
	l := linkN(1, base)
	got, err := registry.Create(ctx, pendingAccount("ana@example.com", l), customerScope, "key-0001-abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got.Account.Status != account.Pending || got.EmailVerified {
		t.Fatalf("the account must read back pending and unverified: %+v", got)
	}
	var status, hash string
	var created, expires time.Time
	if err := pool.QueryRow(ctx, `SELECT i.identity_status, v.token_hash, v.created_at, v.expires_at FROM security.identity i
		JOIN security.email_verification v USING (identity_id)`).Scan(&status, &hash, &created, &expires); err != nil {
		t.Fatalf("exactly one account and one link: %v", err)
	}
	if status != "PENDING" || hash != l.TokenHash || !expires.Equal(l.ExpiresAt) || !created.Equal(l.CreatedAt) {
		t.Fatalf("stored %s %s created %v expires %v, want the instants of the link", status, hash, created, expires)
	}
}

func TestI_AnAccountAndItsFirstLinkAreWrittenTogether(t *testing.T) {
	registry, pool := registrySetup(t)
	l := linkN(1, base)
	if _, err := registry.Create(ctx, pendingAccount("ana@example.com", l), customerScope, "key-0001-abcd"); err != nil {
		t.Fatal(err)
	}
	// the same hash for another account: the link is refused, and the account, its role and its key must go with it
	if _, err := registry.Create(ctx, pendingAccount("bob@example.com", l), customerScope, "key-0002-abcd"); err == nil {
		t.Fatal("a link whose hash already exists was accepted")
	}
	if rows(t, pool, "identity") != 1 || rows(t, pool, "membership") != 1 || rows(t, pool, "idempotency_key") != 1 || rows(t, pool, "email_verification") != 1 {
		t.Fatalf("identity=%d membership=%d keys=%d links=%d: a refused link must undo the whole creation",
			rows(t, pool, "identity"), rows(t, pool, "membership"), rows(t, pool, "idempotency_key"), rows(t, pool, "email_verification"))
	}
}

func TestI_APendingAccountWithoutALinkIsRefused(t *testing.T) {
	registry, pool := registrySetup(t)
	n := newAccount("ana@example.com")
	n.Pending = true
	if _, err := registry.Create(ctx, n, customerScope, "key-0001-abcd"); err == nil {
		t.Fatal("a pending account with no link could never be verified")
	}
	if rows(t, pool, "identity") != 0 {
		t.Fatal("nothing may be written")
	}
}

func TestI_AnAccountThatIsNotPendingGetsNoLink(t *testing.T) {
	registry, pool := registrySetup(t)
	n := newAccount("luis@example.com")
	l := linkN(1, base)
	n.Link = &l // a link without the pending flag is not written either
	got, err := registry.Create(ctx, n, customerScope, "key-0001-abcd")
	if err != nil || got.Account.Status != account.Active || rows(t, pool, "email_verification") != 0 {
		t.Fatalf("status=%v links=%d err=%v", got.Account.Status, rows(t, pool, "email_verification"), err)
	}
}
