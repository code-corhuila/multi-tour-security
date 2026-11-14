package postgres_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HU-SEC-007 part C, security spec 011: the notices of the opening of an emergency access (RN-SEC-011-01, -02, -03, -04, -06; AC-SEC11.1, .3, .4, .5, .6, .8).

const noticeFact = "EmergencyAccessNoticeRequested"

func noticeSetup(t *testing.T, commercialName string) (*pgxpool.Pool, string, map[string]string) {
	t.Helper()
	_, pool, root := supportSetup(t)
	if commercialName != "" {
		if _, err := pool.Exec(context.Background(), `INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at, commercial_name)
			VALUES ($1::uuid, 'travesia', 'ACTIVE', now(), $2)`, tenant, commercialName); err != nil {
			t.Fatal(err)
		}
	}
	accounts := map[string]string{}
	mk := func(name string, tenantID string, o pgtest.Options, roles ...string) {
		id, err := pgtest.AccountWith(context.Background(), pool, tenantID, name+"@example.com", pgtest.ValidHash, o, roles...)
		if err != nil {
			t.Fatal(err)
		}
		accounts[name] = id
	}
	mk("ana-admin", tenant, pgtest.Options{}, "TENANT_ADMINISTRATOR")
	mk("beto-admin", tenant, pgtest.Options{}, "TENANT_ADMINISTRATOR")
	mk("inactive-admin", tenant, pgtest.Options{Inactive: true}, "TENANT_ADMINISTRATOR")
	mk("membership-off-admin", tenant, pgtest.Options{MembershipInactive: true}, "TENANT_ADMINISTRATOR")
	mk("role-off-admin", tenant, pgtest.Options{}, "TENANT_ADMINISTRATOR")
	if _, err := pool.Exec(context.Background(), `UPDATE security.membership_role SET role_status = 'INACTIVE'
		WHERE membership_id = (SELECT membership_id FROM security.membership WHERE identity_id = $1::uuid)`, accounts["role-off-admin"]); err != nil {
		t.Fatal(err)
	}
	mk("pending-admin", tenant, pgtest.Options{Pending: true}, "TENANT_ADMINISTRATOR")
	mk("other-tenant-admin", otherTenant, pgtest.Options{}, "TENANT_ADMINISTRATOR")
	mk("collaborator", tenant, pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	accounts["root"] = root
	return pool, root, accounts
}

func notices(t *testing.T, pool *pgxpool.Pool) []map[string]any {
	t.Helper()
	return facts(t, pool, noticeFact)
}

func recipients(list []map[string]any) []string {
	var out []string
	for _, n := range list {
		payload, _ := n["payload"].(map[string]any)
		out = append(out, payload["recipientEmail"].(string))
	}
	slices.Sort(out)
	return out
}

func TestI_TheOpeningWritesItsFactAndItsNoticesTogetherToTheActiveAdministratorsOfThatTenantOnly(t *testing.T) {
	pool, root, _ := noticeSetup(t, "Travesia Natural SAS")
	store := postgres.NewSupportAccesses(pool)
	made, created, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "notice-0001-abcd", "corr-notice-1")
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	got := notices(t, pool)
	if want := []string{"ana-admin@example.com", "beto-admin@example.com"}; !slices.Equal(recipients(got), want) {
		t.Fatalf("recipients = %v, want %v", recipients(got), want)
	}
	if n := len(facts(t, pool, "PlatformExceptionalAccessOpened")); n != 1 {
		t.Fatalf("%d opening facts", n)
	}
	for _, n := range got {
		payload, _ := n["payload"].(map[string]any)
		scope, _ := payload["scope"].([]any)
		if n["aggregateId"] != made.ID || n["actorId"] != root || n["tenantId"] != tenant || n["correlationId"] != "corr-notice-1" ||
			payload["kind"] != "OPENED" || payload["tenantName"] != "Travesia Natural SAS" || payload["platformAdministrator"] != "root@multitour.example" ||
			payload["reason"] != "Every cash of today shows a negative balance" || len(scope) != 1 || scope[0] != "CASH" || payload["includesSensitiveData"] != false ||
			payload["startedAt"] != "2026-10-10T10:00:00.000000Z" || payload["authorizationId"] != made.ID {
			t.Fatalf("notice = %v", n)
		}
		if _, has := payload["endedAt"]; has {
			t.Errorf("an opening has no end: %v", payload)
		}
	}
}

func TestI_TheNoticeOfAnEmergencyShowsMultitourForATenantWithoutACommercialName(t *testing.T) {
	pool, root, _ := noticeSetup(t, "")
	if _, _, err := postgres.NewSupportAccesses(pool).OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "notice-0002-abcd", "corr-notice-2"); err != nil {
		t.Fatal(err)
	}
	list := notices(t, pool)
	if len(list) != 2 {
		t.Fatalf("%d notices, want one per active Administrator", len(list))
	}
	for _, n := range list {
		if payload, _ := n["payload"].(map[string]any); payload["tenantName"] != "Multitour" {
			t.Errorf("name = %v", payload["tenantName"])
		}
	}
}

func TestI_ANoticeCarriesNoStatementAndNoSensitiveJustificationButSaysWhetherSensitiveDataAreReached(t *testing.T) {
	pool, root, _ := noticeSetup(t, "Travesia Natural SAS")
	if _, _, err := postgres.NewSupportAccesses(pool).OpenEmergency(ctx, emergencyAt(t, root, tenant, base, true), "notice-0003-abcd", "corr-notice-3"); err != nil {
		t.Fatal(err)
	}
	list := notices(t, pool)
	if len(list) != 2 {
		t.Fatalf("%d notices", len(list))
	}
	for _, n := range list {
		raw, _ := json.Marshal(n["payload"])
		text := string(raw)
		if strings.Contains(text, "No Administrator can sign in") || strings.Contains(text, "medical record") || strings.Contains(strings.ToLower(text), "statement") ||
			strings.Contains(strings.ToLower(text), "sensitivereason") || strings.Contains(strings.ToLower(text), "password") {
			t.Errorf("the notice carries what it must not: %s", text)
		}
		if payload, _ := n["payload"].(map[string]any); payload["includesSensitiveData"] != true {
			t.Errorf("the notice must say that sensitive data are reached: %v", payload)
		}
	}
}

func TestI_ATenantWithoutAdministratorsOpensWithNoNotice(t *testing.T) {
	store, pool, root := supportSetup(t)
	made, created, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "notice-0004-abcd", "corr-notice-4")
	if err != nil || !created || made.Status != supportaccess.Approved {
		t.Fatalf("created=%v err=%v access=%+v", created, err, made)
	}
	if n := len(notices(t, pool)); n != 0 {
		t.Errorf("%d notices for nobody", n)
	}
	if n := len(facts(t, pool, "PlatformExceptionalAccessOpened")); n != 1 {
		t.Errorf("%d opening facts", n)
	}
}

func TestI_ARepeatedOpeningAndAnAuthorizedAccessRequestNoNoticeAtTheOpening(t *testing.T) {
	pool, root, _ := noticeSetup(t, "Travesia Natural SAS")
	store := postgres.NewSupportAccesses(pool)
	if _, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "notice-0005-abcd", "corr-notice-5"); err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base.Add(time.Minute), false), "notice-0005-abcd", "corr-notice-5b"); err != nil || created {
		t.Fatalf("repeat: created=%v err=%v", created, err)
	}
	if n := len(notices(t, pool)); n != 2 {
		t.Errorf("%d notices after a repeated opening, want the two of the first", n)
	}
	// an access authorized by a Tenant Administrator (part A) never requests one when its first token opens it
	authorized := approvedAccess(t, store, pool, root, "ask-0006-abcd")
	if _, ok, err := store.Open(ctx, root, authorized.ID, base.Add(2*time.Hour), "corr-token"); err != nil || !ok {
		t.Fatalf("token: ok=%v err=%v", ok, err)
	}
	if n := len(notices(t, pool)); n != 2 {
		t.Errorf("%d notices: an authorized access asked for one", n)
	}
}
