package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// End to end, with the real adapters and PostgreSQL: RN-SEC-001-06 and -07.

const refreshURL = "/api/v1/security/public/sessions/refresh"

func (s *stack) refresh(value string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"refreshToken": value})
	req := httptest.NewRequest(http.MethodPost, refreshURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-1")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

// signedIn signs the account in and returns its renewal value.
func (s *stack) signedIn(t *testing.T, email string) answer {
	t.Helper()
	a, _ := s.claims(t, s.signIn(tenantURL, email, password))
	return a
}

func TestC_ARenewalGivesANewValidPairAndTheOldValueNeverWorksAgain(t *testing.T) {
	s := newStack(t)
	id := s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	first := s.signedIn(t, "ana@example.com")
	next, claims := s.claims(t, s.refresh(first.RefreshToken))
	if claims["sub"] != id || claims["tenantId"] != tenantA || next.RefreshToken == "" || next.RefreshToken == first.RefreshToken {
		t.Fatalf("claims %v, pair %+v", claims, next)
	}
	again := s.refresh(first.RefreshToken)
	want := `{"error":"UNAUTHORIZED","message":"authentication failed","traceId":"e2e-1"}` + "\n"
	if again.Code != http.StatusUnauthorized || again.Body.String() != want {
		t.Fatalf("the value used twice is refused: %d %s", again.Code, again.Body)
	}
	if rec := s.refresh(next.RefreshToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the reuse revoked the whole session, so the value that was alive no longer renews: %d", rec.Code)
	}
}

func TestC_ARenewalCarriesTheRolesOfNowAndTheSessionDoesNotSlide(t *testing.T) {
	s := newStack(t)
	id := s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR", "MANAGER")
	first := s.signedIn(t, "ana@example.com")
	if _, err := s.pool.Exec(ctx, `DELETE FROM security.membership_role WHERE role = 'TENANT_ADMINISTRATOR'
		AND membership_id = (SELECT membership_id FROM security.membership WHERE identity_id = $1::uuid)`, id); err != nil {
		t.Fatal(err)
	}
	_, claims := s.claims(t, s.refresh(first.RefreshToken))
	if roles, _ := claims["roles"].([]any); len(roles) != 1 || roles[0] != "MANAGER" {
		t.Fatalf("a role removed since the session began must not come back: %v", claims["roles"])
	}
	var distinct int
	if err := s.pool.QueryRow(ctx, `SELECT count(DISTINCT expires_at) FROM security.refresh_token`).Scan(&distinct); err != nil || distinct != 1 {
		t.Fatalf("every value ends with the session: %d distinct ends, %v", distinct, err)
	}
}

func TestC_ASessionOfAnAccountThatWasStoppedCannotBeRenewed(t *testing.T) {
	s := newStack(t)
	inactive := s.account(t, tenantA, "off@example.com", pgtest.Options{}, "ANALYST")
	revoked := s.account(t, tenantA, "rev@example.com", pgtest.Options{}, "ANALYST")
	offValue := s.signedIn(t, "off@example.com").RefreshToken
	revValue := s.signedIn(t, "rev@example.com").RefreshToken
	if _, err := s.pool.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, inactive); err != nil {
		t.Fatal(err)
	}
	if err := postgres.NewSessions(s.pool).RevokeAll(ctx, revoked, time.Now().Add(time.Second), "corr-1"); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"inactive account": offValue, "signed out everywhere": revValue} {
		if rec := s.refresh(value); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func TestC_ASessionOfATenantThatIsNotActiveCannotBeRenewedAndItsAdministratorSignsInRestricted(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	value := s.signedIn(t, "ana@example.com").RefreshToken
	tenants := postgres.NewTenants(s.pool)
	if _, err := tenants.Apply(ctx, coretenant.Copy{TenantID: tenantA, Identifier: "travesia-natural", Status: coretenant.Inactive, OccurredAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if rec := s.refresh(value); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an inactive tenant ends the renewal: %d", rec.Code)
	}
	// the person signs in again, as the Administrator of an inactive tenant, with a restricted access
	if _, claims := s.claims(t, s.signIn(tenantURL, "ana@example.com", password)); claims["access"] != "restricted" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestC_ThePlatformAdministratorRenewsWithoutATenant(t *testing.T) {
	s := newStack(t)
	s.account(t, "", "root@example.com", pgtest.Options{}, "PLATFORM_ADMINISTRATOR")
	first, _ := s.claims(t, s.signIn(rootURL, "root@example.com", password))
	_, claims := s.claims(t, s.refresh(first.RefreshToken))
	if _, has := claims["tenantId"]; has {
		t.Fatalf("the platform token has no tenantId: %v", claims)
	}
}

func TestC_ARenewalIsRefusedForAnUnknownValueAndLogsShowNoValue(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	first := s.signedIn(t, "ana@example.com")
	unknown := strings.Repeat("u", 43)
	if rec := s.refresh(unknown); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unknown value: %d", rec.Code)
	}
	next, _ := s.claims(t, s.refresh(first.RefreshToken))
	for _, secret := range []string{first.RefreshToken, next.RefreshToken, unknown, next.AccessToken} {
		if strings.Contains(s.logs.String(), secret) {
			t.Errorf("the log shows %q", secret)
		}
	}
	var clear int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.refresh_token WHERE token_hash IN ($1, $2)`, first.RefreshToken, next.RefreshToken).Scan(&clear); err != nil || clear != 0 {
		t.Fatalf("a value is stored in clear: %d %v", clear, err)
	}
}
