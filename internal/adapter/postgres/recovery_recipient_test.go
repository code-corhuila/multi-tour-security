package postgres_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-004 AC5 for job 4 (security spec 008): the facts of a reset say whom to write to and in whose name.

func (w recoveryWorld) payload(t *testing.T, eventType string) map[string]any {
	t.Helper()
	var raw string
	if err := w.pool.QueryRow(ctx, `SELECT payload::text FROM security.outbox_event WHERE event_type = $1 ORDER BY occurred_at DESC LIMIT 1`, eventType).Scan(&raw); err != nil {
		t.Fatalf("%s: %v", eventType, err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (w recoveryWorld) setCommercialName(t *testing.T, name string) {
	t.Helper()
	if _, err := w.pool.Exec(ctx, `INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at, commercial_name)
		VALUES ($1::uuid, 'travesia', 'ACTIVE', now(), $2) ON CONFLICT (tenant_id) DO UPDATE SET commercial_name = EXCLUDED.commercial_name`, tenant, name); err != nil {
		t.Fatal(err)
	}
}

func TestI_TheResetFactCarriesTheEmailAndTheTenantName(t *testing.T) {
	w := recoverySetup(t)
	w.setCommercialName(t, "Travesía Natural")
	w.issue(t, w.boss, tenant, 1, base)
	at := base.Add(5 * time.Minute)
	if !w.reset(t, w.boss, w.live(t, w.boss, at).ID, false, true, at) {
		t.Fatal("the reset did not run")
	}
	got := w.payload(t, "PasswordReset")
	if got["email"] != "boss@example.com" || got["tenantName"] != "Travesía Natural" || got["accountId"] != w.boss {
		t.Fatalf("payload = %v", got)
	}
}

func TestI_ATenantWithoutACommercialNameShowsMultitour(t *testing.T) {
	w := recoverySetup(t)
	// the copy exists and has no commercial name, which is not the same as having no copy
	if _, err := w.pool.Exec(ctx, `INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at) VALUES ($1::uuid, 'travesia', 'ACTIVE', now())`, tenant); err != nil {
		t.Fatal(err)
	}
	w.issue(t, w.boss, tenant, 1, base)
	at := base.Add(5 * time.Minute)
	w.reset(t, w.boss, w.live(t, w.boss, at).ID, false, true, at)
	if got := w.payload(t, "PasswordReset"); got["tenantName"] != "Multitour" {
		t.Fatalf("payload = %v", got)
	}
}

func TestI_ThePlatformResetShowsMultitour(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.root, "", 1, base)
	at := base.Add(5 * time.Minute)
	if !w.reset(t, w.root, w.live(t, w.root, at).ID, false, true, at) {
		t.Fatal("the reset did not run")
	}
	got := w.payload(t, "PasswordReset")
	if got["email"] != "root@multitour.example" || got["tenantName"] != "Multitour" {
		t.Fatalf("payload = %v", got)
	}
}

func TestI_TheFailedResetFactCarriesTheEmailTheNameAndTheRoles(t *testing.T) {
	w := recoverySetup(t)
	w.setCommercialName(t, "Travesía Natural")
	w.issue(t, w.boss, tenant, 1, base)
	w.fail(t, w.boss, w.live(t, w.boss, base).ID, port.ReasonWrongCode, true, base)
	got := w.payload(t, "PasswordResetFailed")
	if got["email"] != "boss@example.com" || got["tenantName"] != "Travesía Natural" || got["reason"] != port.ReasonWrongCode {
		t.Fatalf("payload = %v", got)
	}
	if roles, _ := got["roles"].([]any); len(roles) != 1 || roles[0] != "TENANT_ADMINISTRATOR" {
		t.Fatalf("roles = %v", got["roles"])
	}
}

func TestI_TheResetFactsCarryNoCredential(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.boss, tenant, 1, base)
	code := w.live(t, w.boss, base)
	w.fail(t, w.boss, code.ID, port.ReasonWrongCode, true, base)
	at := base.Add(5 * time.Minute)
	w.reset(t, w.boss, code.ID, false, true, at)
	for _, kind := range []string{"PasswordReset", "PasswordResetFailed"} {
		var raw string
		if err := w.pool.QueryRow(ctx, `SELECT payload::text FROM security.outbox_event WHERE event_type = $1 LIMIT 1`, kind).Scan(&raw); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		for _, secret := range []string{recoveredHash, code.ID, strings.Repeat("0", 20)} {
			if strings.Contains(raw, secret) {
				t.Errorf("%s carries %q", kind, secret)
			}
		}
		for _, field := range []string{"password", "code", "hash", "link", "token"} {
			if strings.Contains(strings.ToLower(raw), `"`+field+`"`) {
				t.Errorf("%s has a field named %s: %s", kind, field, raw)
			}
		}
	}
}

// The roles of the failed fact are those of the active membership, as RolesHeld reads them.
func TestI_TheFailedResetFactListsNoRoleOfAMembershipThatIsNotActive(t *testing.T) {
	w := recoverySetup(t)
	w.issue(t, w.boss, tenant, 1, base)
	if _, err := w.pool.Exec(ctx, `UPDATE security.membership SET membership_status = 'INACTIVE' WHERE identity_id = $1::uuid`, w.boss); err != nil {
		t.Fatal(err)
	}
	w.fail(t, w.boss, w.live(t, w.boss, base).ID, port.ReasonWrongCode, true, base)
	if roles, _ := w.payload(t, "PasswordResetFailed")["roles"].([]any); len(roles) != 0 {
		t.Fatalf("roles = %v", roles)
	}
}
