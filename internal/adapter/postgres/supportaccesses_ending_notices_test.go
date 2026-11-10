package postgres_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

// HU-SEC-007 part C, security spec 011: the notices of the ending of an emergency access, early or by the end of its hours
// (RN-SEC-011-01, -02, -03, -04; AC-SEC11.2, .3, .4, .5, .8).

func ofKind(list []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, n := range list {
		if payload, _ := n["payload"].(map[string]any); payload["kind"] == kind {
			out = append(out, n)
		}
	}
	return out
}

func TestI_TheEarlyClosingOfAnEmergencyWritesItsFactAndItsEndNoticesTogetherAndASecondClosingNone(t *testing.T) {
	pool, root, _ := noticeSetup(t, "Travesia Natural SAS")
	store := postgres.NewSupportAccesses(pool)
	made, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, true), "ending-0001-abcd", "corr-ending-1")
	if err != nil {
		t.Fatal(err)
	}
	closing := supportaccess.Access{ID: made.ID, RequestedBy: root, ClosedAt: base.Add(30 * time.Minute), ClosedReason: "The incident is solved"}
	if ok, err := store.Close(ctx, closing, "corr-ending-2"); err != nil || !ok {
		t.Fatalf("close: ok=%v err=%v", ok, err)
	}
	ended := ofKind(notices(t, pool), "CLOSED")
	if want := []string{"ana-admin@example.com", "beto-admin@example.com"}; !slices.Equal(recipients(ended), want) {
		t.Fatalf("recipients = %v, want %v", recipients(ended), want)
	}
	if n := len(facts(t, pool, "PlatformExceptionalAccessClosed")); n != 1 {
		t.Fatalf("%d closing facts", n)
	}
	for _, n := range ended {
		payload, _ := n["payload"].(map[string]any)
		scope, _ := payload["scope"].([]any)
		raw, _ := json.Marshal(payload)
		if n["aggregateId"] != made.ID || n["actorId"] != root || n["tenantId"] != tenant || n["correlationId"] != "corr-ending-2" ||
			payload["tenantName"] != "Travesia Natural SAS" || payload["platformAdministrator"] != "root@multitour.example" ||
			payload["reason"] != "Every cash of today shows a negative balance" || len(scope) != 1 || scope[0] != "CASH" || payload["includesSensitiveData"] != true ||
			payload["startedAt"] != "2026-10-10T10:00:00.000000Z" || payload["endedAt"] != "2026-10-10T10:30:00.000000Z" || payload["authorizationId"] != made.ID {
			t.Fatalf("notice = %v", n)
		}
		if text := strings.ToLower(string(raw)); strings.Contains(text, "statement") || strings.Contains(text, "sensitivereason") || strings.Contains(text, "medical record") ||
			strings.Contains(string(raw), "The incident is solved") {
			t.Errorf("the notice carries what it must not: %s", raw)
		}
	}
	// a second closing finds nothing to close and requests nothing
	if ok, err := store.Close(ctx, closing, "corr-ending-3"); err != nil || ok {
		t.Fatalf("second close: ok=%v err=%v", ok, err)
	}
	if n := len(ofKind(notices(t, pool), "CLOSED")); n != 2 {
		t.Errorf("%d end notices after a second closing, want 2", n)
	}
}

func TestI_TheEndOfTheHoursOfAnEmergencyWritesTheEndNoticesAtTheEndInstantOnce(t *testing.T) {
	pool, root, _ := noticeSetup(t, "Travesia Natural SAS")
	store := postgres.NewSupportAccesses(pool)
	if _, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "ending-0002-abcd", "corr-ending-4"); err != nil {
		t.Fatal(err)
	}
	if err := store.ExpireApproved(ctx, root, "", base.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ended := ofKind(notices(t, pool), "CLOSED")
	if len(ended) != 2 {
		t.Fatalf("%d end notices, want one per active Administrator", len(ended))
	}
	for _, n := range ended {
		payload, _ := n["payload"].(map[string]any)
		if payload["endedAt"] != "2026-10-10T14:00:00.000000Z" || payload["startedAt"] != "2026-10-10T10:00:00.000000Z" || n["correlationId"] != "support-access-expiry" {
			t.Errorf("notice = %v", n)
		}
	}
	if err := store.ExpireApproved(ctx, root, "", base.Add(6*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := len(ofKind(notices(t, pool), "CLOSED")); n != 2 {
		t.Errorf("%d end notices after asking again, want 2", n)
	}
}

func TestI_AnAuthorizedAccessAndATenantWithoutAdministratorsRequestNoEndNotice(t *testing.T) {
	store, pool, root := supportSetup(t)
	// a tenant with no Administrator: the emergency opens, closes and tells nobody
	made, _, err := store.OpenEmergency(ctx, emergencyAt(t, root, tenant, base, false), "ending-0003-abcd", "corr-ending-5")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Close(ctx, supportaccess.Access{ID: made.ID, RequestedBy: root, ClosedAt: base.Add(time.Hour), ClosedReason: "Done"}, "corr-ending-6"); err != nil || !ok {
		t.Fatalf("close: ok=%v err=%v", ok, err)
	}
	if n := len(notices(t, pool)); n != 0 {
		t.Errorf("%d notices for nobody", n)
	}
	// an access that a Tenant Administrator authorized: its closing and its expiry ask for no notice
	pool2, root2, _ := noticeSetup(t, "Travesia Natural SAS")
	store2 := postgres.NewSupportAccesses(pool2)
	authorized := approvedAccess(t, store2, pool2, root2, "ask-0007-abcd")
	if _, ok, err := store2.Open(ctx, root2, authorized.ID, base.Add(2*time.Hour), "corr-token"); err != nil || !ok {
		t.Fatalf("token: ok=%v err=%v", ok, err)
	}
	if ok, err := store2.Close(ctx, supportaccess.Access{ID: authorized.ID, RequestedBy: root2, ClosedAt: base.Add(3 * time.Hour), ClosedReason: "Done"}, "corr-ending-7"); err != nil || !ok {
		t.Fatalf("close: ok=%v err=%v", ok, err)
	}
	if n := len(notices(t, pool2)); n != 0 {
		t.Errorf("%d notices for an authorized access", n)
	}
}
