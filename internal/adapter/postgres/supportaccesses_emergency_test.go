package postgres_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

// HU-SEC-007 part B, security spec 010: opening an emergency access against the real engine (RN-SEC-010-02, -07, -08, -09; plan D-04, D-07).

func emergencyAt(t *testing.T, root, tenantID string, at time.Time, sensitive bool) supportaccess.Access {
	t.Helper()
	reason := ""
	if sensitive {
		reason = "The incident is about a passenger's medical record"
	}
	a, err := supportaccess.NewEmergency(tenantID, root, "Every cash of today shows a negative balance", "No Administrator can sign in", []string{"CASH"}, 4, sensitive, reason, at)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestI_AnEmergencyOpeningWritesItsFactWithItAndTheFirstTokenWritesNoSecond(t *testing.T) {
	store, pool, root := supportSetup(t)
	made, created, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, true), "emerg-0001-abcd", "corr-emergency-1")
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if len(made.ID) != 36 || made.Basis != supportaccess.Emergency || made.Status != supportaccess.Approved || made.DecidedBy != "" || !made.Sensitive ||
		made.SensitiveReason == "" || made.Statement != "No Administrator can sign in" || !made.OpenedAt.Equal(base) || !made.ExpiresAt.Equal(base.Add(4*time.Hour)) ||
		!slices.Equal(made.AreaNames(), []string{"CASH"}) {
		t.Fatalf("emergency = %+v", made)
	}
	got := facts(t, pool, "PlatformExceptionalAccessOpened")
	if len(got) != 1 {
		t.Fatalf("%d facts", len(got))
	}
	payload, _ := got[0]["payload"].(map[string]any)
	if got[0]["aggregateId"] != made.ID || got[0]["actorId"] != root || got[0]["tenantId"] != tenant || got[0]["correlationId"] != "corr-emergency-1" ||
		payload["basis"] != "EMERGENCY" || payload["authorizationId"] != made.ID || payload["includesSensitiveData"] != true || payload["statement"] != "No Administrator can sign in" ||
		payload["sensitiveReason"] == "" || payload["expiresAt"] != "2026-10-10T14:00:00.000000Z" {
		t.Fatalf("fact = %v", got[0])
	}
	// the token is taken later: the access is already open, so no second fact is written
	if _, ok, err := store.Open(ctx, root, made.ID, base.Add(time.Minute), "corr-token"); err != nil || !ok {
		t.Fatalf("token: ok=%v err=%v", ok, err)
	}
	if n := len(facts(t, pool, "PlatformExceptionalAccessOpened")); n != 1 {
		t.Errorf("%d opening facts after the token", n)
	}
}

func TestI_AnEmergencyWithoutSensitiveDataSaysSoInItsFact(t *testing.T) {
	store, pool, root := supportSetup(t)
	if _, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "emerg-0002-abcd", "corr-2"); err != nil {
		t.Fatal(err)
	}
	payload, _ := facts(t, pool, "PlatformExceptionalAccessOpened")[0]["payload"].(map[string]any)
	if payload["includesSensitiveData"] != false {
		t.Errorf("payload = %v", payload)
	}
	if _, has := payload["sensitiveReason"]; has {
		t.Errorf("no justification for data that is not asked: %v", payload)
	}
}

func TestI_TheSameKeyReturnsTheFirstEmergencyAndStoresNoSecondOne(t *testing.T) {
	store, pool, root := supportSetup(t)
	first, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "emerg-0003-abcd", "corr-3")
	if err != nil {
		t.Fatal(err)
	}
	again, created, err := store.OpenEmergency(ctx, emergencyAt(t, root, otherTenant, base.Add(time.Minute), false), "emerg-0003-abcd", "corr-3b")
	if err != nil || created || again.ID != first.ID || again.TenantID != tenant {
		t.Fatalf("created=%v err=%v again=%+v", created, err, again)
	}
	if n, f := rows(t, pool, "support_access"), len(facts(t, pool, "PlatformExceptionalAccessOpened")); n != 1 || f != 1 {
		t.Fatalf("%d rows, %d facts", n, f)
	}
}

func TestI_ASecondOpenAccessToTheSameTenantIsRefusedAnotherTenantIsNotAndTheEndFreesIt(t *testing.T) {
	store, pool, root := supportSetup(t)
	if _, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "emerg-0004-abcd", "corr-4"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base.Add(time.Hour), false), "emerg-0004-wxyz", "corr-4b"); !errors.Is(err, supportaccess.ErrOpenAccessExists) {
		t.Fatalf("a second open access: %v", err)
	}
	if n := rows(t, pool, "support_access"); n != 1 {
		t.Fatalf("%d rows after the refusal", n)
	}
	if _, created, err := store.OpenEmergency(ctx, emergencyAt(t, root, otherTenant, base.Add(time.Hour), false), "emerg-0004-tenant", "corr-4c"); err != nil || !created {
		t.Fatalf("another tenant: created=%v err=%v", created, err)
	}
	// the hours of the first are over: opening again expires it first, with its closing fact, and is allowed
	if _, created, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base.Add(5*time.Hour), false), "emerg-0004-later", "corr-4d"); err != nil || !created {
		t.Fatalf("after the end: created=%v err=%v", created, err)
	}
	closed := facts(t, pool, "PlatformExceptionalAccessClosed")
	if len(closed) != 1 {
		t.Fatalf("%d closing facts", len(closed))
	}
	if payload, _ := closed[0]["payload"].(map[string]any); payload["endedBy"] != "EXPIRED" {
		t.Errorf("closing fact = %v", closed[0])
	}
}

func TestI_TwoEmergenciesOfTheSamePairAtOnceOpenOnlyOne(t *testing.T) {
	store, pool, root := supportSetup(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, key := range []string{"emerg-0005-aaaa", "emerg-0005-bbbb"} {
		go func() {
			<-start
			_, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base.Add(time.Duration(i)*time.Minute), false), key, "corr-5")
			results <- err
		}()
	}
	close(start)
	a, b := <-results, <-results
	refused := 0
	for _, err := range []error{a, b} {
		if errors.Is(err, supportaccess.ErrOpenAccessExists) {
			refused++
		} else if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	}
	if refused != 1 || rows(t, pool, "support_access") != 1 {
		t.Fatalf("refused %d, rows %d (%v, %v)", refused, rows(t, pool, "support_access"), a, b)
	}
}

func TestI_AnAuthorizedRequestIsReadBackWithTheAuthorizationBasisAndNoStatement(t *testing.T) {
	store, _, root := supportSetup(t)
	made, _, err := store.Create(ctx, asked(t, root, base), "ask-0006-abcd")
	if err != nil {
		t.Fatal(err)
	}
	if made.Basis != supportaccess.TenantAuthorization || made.Statement != "" || made.Sensitive || made.SensitiveReason != "" {
		t.Fatalf("request = %+v", made)
	}
}

// The lock is of the pair (tenant, author) and the key is unique per author, so the same key at once for two tenants meets only the unique key:
// both must get the one access that won, never an error (review of spec 010, finding H1).
func TestI_TheSameKeyAtOnceForTwoTenantsOpensOneAndBothGetIt(t *testing.T) {
	store, pool, root := supportSetup(t)
	start := make(chan struct{})
	type result struct {
		id  string
		err error
	}
	results := make(chan result, 2)
	for _, tenantID := range []string{tenant, otherTenant} {
		go func() {
			<-start
			got, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenantID, base, false), "emerg-0007-same", "corr-7")
			results <- result{got.ID, err}
		}()
	}
	close(start)
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || len(a.id) != 36 || a.id != b.id || rows(t, pool, "support_access") != 1 || len(facts(t, pool, "PlatformExceptionalAccessOpened")) != 1 {
		t.Fatalf("%+v %+v rows %d facts %d", a, b, rows(t, pool, "support_access"), len(facts(t, pool, "PlatformExceptionalAccessOpened")))
	}
}
