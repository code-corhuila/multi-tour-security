package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/jackc/pgx/v5/pgconn"
)

// The tests below cover RN-SEC-001-11: the service knows the status of each tenant from the events of identity-audit,
// delivered once or more, in any order.

func copyAt(status coretenant.Status, minutes int) coretenant.Copy {
	return coretenant.Copy{TenantID: tenant, Identifier: "travesia-natural", Status: status, OccurredAt: base.Add(time.Duration(minutes) * time.Minute)}
}

func apply(t *testing.T, tenants *postgres.Tenants, c coretenant.Copy) bool {
	t.Helper()
	applied, err := tenants.Apply(ctx, c)
	if err != nil {
		t.Fatalf("Apply(%+v): %v", c, err)
	}
	return applied
}

func find(t *testing.T, tenants *postgres.Tenants, identifier string) coretenant.Copy {
	t.Helper()
	got, found, err := tenants.FindByIdentifier(ctx, identifier)
	if err != nil || !found {
		t.Fatalf("FindByIdentifier(%q): %+v %v %v", identifier, got, found, err)
	}
	return got
}

func pgCode(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return "not a PostgreSQL error: " + errString(err)
}

func TestI_TheFirstEventCreatesTheCopyAndAnUnknownIdentifierIsNotFound(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	if !apply(t, tenants, copyAt(coretenant.Pending, 0)) {
		t.Fatal("the first event must be applied")
	}
	got := find(t, tenants, "travesia-natural")
	if got.TenantID != tenant || got.Status != coretenant.Pending || !got.OccurredAt.Equal(base) {
		t.Fatalf("the copy is not what the event said: %+v", got)
	}
	if _, found, err := tenants.FindByIdentifier(ctx, "unknown"); found || err != nil {
		t.Errorf("an unknown identifier is found=false with no error: %v %v", found, err)
	}
}

func TestI_ANewerEventReplacesTheStateAndARepeatedOrSimultaneousOneChangesNothing(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	apply(t, tenants, copyAt(coretenant.Pending, 0))
	if !apply(t, tenants, copyAt(coretenant.Active, 1)) {
		t.Fatal("a newer event is applied")
	}
	if apply(t, tenants, copyAt(coretenant.Active, 1)) {
		t.Fatal("the same event twice is applied once")
	}
	other := copyAt(coretenant.Inactive, 1)
	other.Identifier = "another-name"
	if apply(t, tenants, other) {
		t.Fatal("only a strictly newer event applies: the same instant with another state or identifier is ignored")
	}
	if got := find(t, tenants, "travesia-natural"); got.Status != coretenant.Active || !got.OccurredAt.Equal(base.Add(time.Minute)) {
		t.Fatalf("the copy after repeats: %+v", got)
	}
}

func TestI_EventsInTheOrder2Then0Then1EndInTheStateOf2(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	if !apply(t, tenants, copyAt(coretenant.Inactive, 2)) {
		t.Fatal("an event for a tenant not yet known creates it, even when older ones are still to come")
	}
	if apply(t, tenants, copyAt(coretenant.Pending, 0)) || apply(t, tenants, copyAt(coretenant.Active, 1)) {
		t.Fatal("older events arriving late are ignored")
	}
	if got := find(t, tenants, "travesia-natural"); got.Status != coretenant.Inactive || !got.OccurredAt.Equal(base.Add(2*time.Minute)) {
		t.Fatalf("delivery is not ordered and the newest state wins, got %+v", got)
	}
}

func TestI_ADeactivationAndItsReactivationEndActive(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	for minute, status := range []coretenant.Status{coretenant.Active, coretenant.Inactive, coretenant.Active} {
		apply(t, tenants, copyAt(status, minute))
	}
	got := find(t, tenants, "travesia-natural")
	if !got.IsActive() || !got.OccurredAt.Equal(base.Add(2*time.Minute)) {
		t.Fatalf("the round trip must end active at the time of the last event: %+v", got)
	}
}

func TestI_TheCopyFollowsTheIdentifierOfTheNewestEvent(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	apply(t, tenants, copyAt(coretenant.Active, 0))
	renamed := copyAt(coretenant.Active, 1)
	renamed.Identifier = "travesia"
	apply(t, tenants, renamed)
	if _, found, err := tenants.FindByIdentifier(ctx, "travesia-natural"); found || err != nil {
		t.Errorf("the old identifier still answers: %v %v", found, err)
	}
	if got := find(t, tenants, "travesia"); got.TenantID != tenant {
		t.Errorf("the new identifier does not answer: %+v", got)
	}
}

func TestI_TwentyEventsStartedTogetherEndInTheNewestStateWithOneAppliedAtTheTop(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	start := make(chan struct{})
	var wg sync.WaitGroup
	var topApplied atomic.Int32
	for minute := 0; minute < 20; minute++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status := coretenant.Active
			if minute%2 == 1 {
				status = coretenant.Inactive // the newest, minute 19, is the odd one: last writer wins would end at random
			}
			<-start
			applied, err := tenants.Apply(ctx, copyAt(status, minute))
			if err != nil {
				t.Error(err)
			}
			if applied && minute == 19 {
				topApplied.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := find(t, tenants, "travesia-natural"); got.Status != coretenant.Inactive || !got.OccurredAt.Equal(base.Add(19*time.Minute)) {
		t.Fatalf("the newest event must win whatever the order, got %+v", got)
	}
	if topApplied.Load() != 1 {
		t.Fatalf("the newest event is applied exactly once, got %d", topApplied.Load())
	}
}

func TestI_TheInstantIsKeptInMicrosecondsSoTwoEventsAFewNanosecondsApartAreTheSameEvent(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	first := copyAt(coretenant.Pending, 0)
	first.OccurredAt = base.Add(1 * time.Nanosecond)
	second := copyAt(coretenant.Active, 0)
	second.OccurredAt = base.Add(2 * time.Nanosecond)
	if !apply(t, tenants, first) || apply(t, tenants, second) {
		t.Fatal("events less than a microsecond apart are the same instant: the second is ignored")
	}
	next := copyAt(coretenant.Active, 0)
	next.OccurredAt = base.Add(time.Microsecond)
	if !apply(t, tenants, next) {
		t.Fatal("an event a microsecond newer applies")
	}
	zone := copyAt(coretenant.Inactive, 0)
	zone.OccurredAt = base.Add(time.Hour).In(time.FixedZone("UTC-5", -5*3600))
	apply(t, tenants, zone)
	if got := find(t, tenants, "travesia-natural"); got.Status != coretenant.Inactive || !got.OccurredAt.Equal(base.Add(time.Hour)) {
		t.Fatalf("an instant in another zone is the same instant, got %+v", got)
	}
}

func TestI_TheTableRefusesAStatusAndAnIdentifierOutOfRangeOnInsertAndOnUpdate(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	if _, err := tenants.Apply(ctx, copyAt("DELETED", 0)); pgCode(err) != "23514" {
		t.Errorf("a status outside the four breaks the CHECK on insert (23514), got %s", pgCode(err))
	}
	for identifier, wantRefused := range map[string]bool{"ab": true, "abc": false, strings.Repeat("a", 40): false, strings.Repeat("a", 41): true} {
		tenants := postgres.NewTenants(pgtest.Open(t))
		c := copyAt(coretenant.Active, 0)
		c.Identifier = identifier
		_, err := tenants.Apply(ctx, c)
		if wantRefused != (err != nil) || (wantRefused && pgCode(err) != "23514") {
			t.Errorf("identifier of %d characters: refused=%v, error %v", len(identifier), wantRefused, err)
		}
	}
	apply(t, tenants, copyAt(coretenant.Active, 10))
	if _, err := tenants.Apply(ctx, copyAt("DELETED", 11)); pgCode(err) != "23514" {
		t.Errorf("a newer event with a bad status breaks the CHECK on update (23514), got %s", pgCode(err))
	}
	if got := find(t, tenants, "travesia-natural"); got.Status != coretenant.Active || !got.OccurredAt.Equal(base.Add(10*time.Minute)) {
		t.Errorf("the refused event changed the copy: %+v", got)
	}
}

func TestI_AnIdentifierTakenByAnotherTenantIsRefusedOnInsertAndOnUpdateAndIgnoredWhenOlder(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	apply(t, tenants, copyAt(coretenant.Active, 10))
	other := copyAt(coretenant.Active, 1)
	other.TenantID = otherTenant
	if _, err := tenants.Apply(ctx, other); pgCode(err) != "23505" {
		t.Errorf("a new tenant with a taken identifier breaks the unique (23505), got %s", pgCode(err))
	}
	own := copyAt(coretenant.Active, 0)
	own.TenantID, own.Identifier = otherTenant, "second-tenant"
	apply(t, tenants, own)
	takes := copyAt(coretenant.Active, 20)
	takes.TenantID = otherTenant
	if _, err := tenants.Apply(ctx, takes); pgCode(err) != "23505" {
		t.Errorf("a newer event that takes another tenant's identifier breaks the unique (23505), got %s", pgCode(err))
	}
	older := copyAt(coretenant.Active, -5)
	older.TenantID = otherTenant
	if applied, err := tenants.Apply(ctx, older); err != nil || applied {
		t.Errorf("an older event is ignored before the identifier matters: applied=%v err=%v", applied, err)
	}
	if got := find(t, tenants, "travesia-natural"); got.TenantID != tenant || got.Status != coretenant.Active || !got.OccurredAt.Equal(base.Add(10*time.Minute)) {
		t.Errorf("the refused events changed the copy: %+v", got)
	}
	if got := find(t, tenants, "second-tenant"); got.TenantID != otherTenant || !got.OccurredAt.Equal(base) {
		t.Errorf("the refused events changed the other copy: %+v", got)
	}
}

func TestI_AnEventWithoutAnInstantOrWithAnInvalidTenantIdIsAnErrorAndAWorkingContextIsNeeded(t *testing.T) {
	tenants := postgres.NewTenants(pgtest.Open(t))
	noTime := copyAt(coretenant.Active, 0)
	noTime.OccurredAt = time.Time{}
	if _, err := tenants.Apply(ctx, noTime); err == nil {
		t.Error("an event without an instant was applied")
	}
	for _, id := range []string{"", "not-a-uuid"} {
		bad := copyAt(coretenant.Active, 0)
		bad.TenantID = id
		if _, err := tenants.Apply(ctx, bad); err == nil {
			t.Errorf("an event of the tenant %q was applied", id)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := tenants.Apply(cancelled, copyAt(coretenant.Active, 0)); err == nil {
		t.Error("Apply ignored a cancelled context")
	}
	if _, _, err := tenants.FindByIdentifier(cancelled, "travesia-natural"); err == nil {
		t.Error("FindByIdentifier ignored a cancelled context")
	}
	if _, found, err := tenants.FindByIdentifier(ctx, "travesia-natural"); found || err != nil {
		t.Errorf("none of the refused events left a copy: %v %v", found, err)
	}
}
