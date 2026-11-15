package postgres_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HU-SEC-005, RN-SEC-003-14 and -15: a new temporary credential, against the real engine.

const newHash = "$2a$12$ZYXWVUTSRQPONMLKJIHGFeabcdefghijklmnopqrstuvwxyz01234"

var issuedAt = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

func credentialStore(t *testing.T) (*postgres.TemporaryCredentials, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Open(t)
	return postgres.NewTemporaryCredentials(pool), pool
}

func issueCmd(id string) port.IssueCommand {
	return port.IssueCommand{TenantID: tenant, AccountID: id, Hash: newHash, By: "tenant-administrator/" + actorID, ActorID: actorID,
		ActorRole: "TENANT_ADMINISTRATOR", CorrelationID: "corr-issue", Now: issuedAt}
}

// madeBy sets who created the membership of an account, which is how the first Administrator is told from the others.
func madeBy(t *testing.T, pool *pgxpool.Pool, id, creator string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `UPDATE security.membership SET created_by = $2 WHERE identity_id = $1::uuid`, id, creator); err != nil {
		t.Fatal(err)
	}
}

func TestI_IssuingReplacesTheHashStartsThe72HoursKeepsWhoAndWhenAndWritesTheEventTogether(t *testing.T) {
	store, pool := credentialStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(-24 * time.Hour)}, "MANAGER")
	if _, err := pool.Exec(ctx, `UPDATE security.identity SET failed_count = 5, first_failed_at = $2, blocked_until = $3 WHERE identity_id = $1::uuid`,
		id, issuedAt.Add(-time.Hour), issuedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := store.Issue(ctx, issueCmd(id))
	if err != nil {
		t.Fatal(err)
	}
	if got.Account.ID != id || got.Role != "MANAGER" || got.Account.PasswordHash != "" || !got.Account.TemporaryUntil.Equal(issuedAt.Add(72*time.Hour)) {
		t.Fatalf("the answer is %+v", got)
	}
	var hash, by string
	var until, at time.Time
	var failed int
	var blocked *time.Time
	if err := pool.QueryRow(ctx, `SELECT password_hash, temporary_until, temporary_issued_at, temporary_issued_by, failed_count, blocked_until
		FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&hash, &until, &at, &by, &failed, &blocked); err != nil {
		t.Fatal(err)
	}
	if hash != newHash || !until.Equal(issuedAt.Add(72*time.Hour)) || !at.Equal(issuedAt) || by != "tenant-administrator/"+actorID || failed != 0 || blocked != nil {
		t.Fatalf("stored hash=%s until=%v at=%v by=%s failed=%d blocked=%v", hash, until, at, by, failed, blocked)
	}
	var actor, correlation, payload string
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) OVER (), actor_id::text, correlation_id, payload::text FROM security.outbox_event
		WHERE aggregate_id = $1::uuid AND event_type = 'AccountTemporaryCredentialIssued'`, id).Scan(&n, &actor, &correlation, &payload); err != nil ||
		n != 1 || actor != actorID || correlation != "corr-issue" {
		t.Fatalf("event: n=%d actor=%s correlation=%s %v", n, actor, correlation, err)
	}
	for _, want := range []string{id, tenant, actorID, "TENANT_ADMINISTRATOR"} {
		if !strings.Contains(payload, want) {
			t.Errorf("the event does not say %s: %s", want, payload)
		}
	}
	for _, secret := range []string{newHash, "password", "hash", "Hash"} {
		if strings.Contains(payload, secret) {
			t.Errorf("the event carries %q: %s", secret, payload)
		}
	}
}

func TestI_ACredentialStillInForceIsReplacedToo(t *testing.T) {
	store, pool := credentialStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(time.Hour)}, "MANAGER")
	if _, err := store.Issue(ctx, issueCmd(id)); err != nil {
		t.Fatal(err)
	}
}

func TestI_AnAccountWithItsOwnPasswordOrNotActiveOrNotInternalIsRefusedAndNothingIsWritten(t *testing.T) {
	store, pool := credentialStore(t)
	own := user(t, pool, tenant, "own@example.com", pgtest.Options{}, "MANAGER")
	gone := user(t, pool, tenant, "gone@example.com", pgtest.Options{Inactive: true, TemporaryUntil: issuedAt.Add(time.Hour)}, "MANAGER")
	customer := user(t, pool, tenant, "customer@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(time.Hour)}, "FINAL_CUSTOMER")
	for name, id := range map[string]string{"an account with its own password": own, "an inactive account": gone, "a customer": customer} {
		if _, err := store.Issue(ctx, issueCmd(id)); !errors.Is(err, port.ErrNotTemporary) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var changed int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.identity WHERE password_hash = $1 OR temporary_issued_at IS NOT NULL`, newHash).Scan(&changed); err != nil || changed != 0 {
		t.Fatalf("a refusal wrote %d rows (%v)", changed, err)
	}
	var events int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountTemporaryCredentialIssued'`).Scan(&events); err != nil || events != 0 {
		t.Fatalf("a refusal wrote %d events (%v)", events, err)
	}
}

func TestI_IfTheEventCannotBeWrittenTheCredentialIsNotReplaced(t *testing.T) {
	store, pool := credentialStore(t)
	id := user(t, pool, tenant, "luis@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(-time.Hour)}, "MANAGER")
	bad := issueCmd(id)
	bad.CorrelationID = "" // the outbox refuses an event with no correlation id
	if _, err := store.Issue(ctx, bad); err == nil {
		t.Fatal("an event that the outbox refuses must fail the issue")
	}
	var hash string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&hash); err != nil || hash != pgtest.ValidHash {
		t.Fatalf("the hash is %s (%v): the change and its event must be written together", hash, err)
	}
}

func TestI_TheTargetTellsTheFactsThatDecideWhoMayIssue(t *testing.T) {
	store, pool := credentialStore(t)
	first := user(t, pool, tenant, "first@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(-time.Hour)}, "TENANT_ADMINISTRATOR")
	madeBy(t, pool, first, "service/workflow-onboard-tenant")
	other := user(t, pool, tenant, "other@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(time.Hour)}, "TENANT_ADMINISTRATOR")
	madeBy(t, pool, other, "tenant-administrator/"+actorID)
	collaborator := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")

	got, found, err := store.Target(ctx, first, issuedAt)
	if err != nil || !found || got.TenantID != tenant || !got.Active || !got.HasTemporary || !got.Administrator || !got.FirstAdministrator {
		t.Fatalf("the first administrator: %+v %v %v", got, found, err)
	}
	got, _, _ = store.Target(ctx, other, issuedAt)
	if !got.Administrator || got.FirstAdministrator {
		t.Fatalf("an administrator that another administrator registered is not the first: %+v", got)
	}
	got, _, _ = store.Target(ctx, collaborator, issuedAt)
	if got.Administrator || got.FirstAdministrator || got.HasTemporary {
		t.Fatalf("a collaborator with their own password: %+v", got)
	}
	for name, id := range map[string]string{
		"a customer":           user(t, pool, tenant, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER"),
		"the platform account": user(t, pool, "", "root@example.com", pgtest.Options{}, "PLATFORM_ADMINISTRATOR"),
		"no account":           missing,
	} {
		if _, found, err := store.Target(ctx, id, issuedAt); err != nil || found {
			t.Errorf("%s: found=%v %v", name, found, err)
		}
	}
}

func TestI_AdministratorsAbleToSignInAreCountedByTheirOwnTenantAtTheInstantAsked(t *testing.T) {
	store, pool := credentialStore(t)
	target := user(t, pool, tenant, "target@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(-time.Hour)}, "TENANT_ADMINISTRATOR")
	count := func() int {
		t.Helper()
		got, _, err := store.Target(ctx, target, issuedAt)
		if err != nil {
			t.Fatal(err)
		}
		return got.AdministratorsAbleToSignIn
	}
	if n := count(); n != 0 {
		t.Fatalf("the target itself has an expired credential and cannot sign in: %d", n)
	}
	user(t, pool, tenant, "own@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	user(t, pool, tenant, "inforce@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(time.Hour)}, "TENANT_ADMINISTRATOR")
	if n := count(); n != 2 {
		t.Fatalf("an administrator with their own password and one with a credential in force can sign in: %d", n)
	}
	user(t, pool, tenant, "expired@example.com", pgtest.Options{TemporaryUntil: issuedAt.Add(-time.Minute)}, "TENANT_ADMINISTRATOR")
	user(t, pool, tenant, "gone@example.com", pgtest.Options{Inactive: true}, "TENANT_ADMINISTRATOR")
	user(t, pool, tenant, "manager@example.com", pgtest.Options{}, "MANAGER")
	user(t, pool, otherTenant, "elsewhere@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	blocked := user(t, pool, tenant, "blocked@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	if _, err := pool.Exec(ctx, `UPDATE security.identity SET blocked_until = $2 WHERE identity_id = $1::uuid`, blocked, issuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 2 {
		t.Fatalf("an expired, an inactive, a blocked, a non administrator and another tenant's do not count: %d", n)
	}
}
