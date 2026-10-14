package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// End to end against PostgreSQL, through HTTP: the temporary credential and the first password (RN-SEC-001-04, -07, -12).

const (
	passwordURL = "/api/v1/security/sessions/password"
	chosen      = "Tr4vesia-Natural"
)

func (s *stack) changePassword(token, newPassword string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"newPassword": newPassword})
	req := httptest.NewRequest(http.MethodPut, passwordURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Correlation-Id", "e2e-pw")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func (s *stack) temporary(t *testing.T, email string) (id, token string) {
	t.Helper()
	id = s.account(t, tenantA, email, pgtest.Options{TemporaryUntil: time.Now().Add(72 * time.Hour)}, "TENANT_ADMINISTRATOR")
	a, claims := s.claims(t, s.signIn(tenantURL, email, password))
	if claims["access"] != "password-change" {
		t.Fatalf("claims = %v", claims)
	}
	return id, a.AccessToken
}

func TestC_TheFirstPasswordReplacesTheTemporaryOneAndOpensTheNormalSignIn(t *testing.T) {
	s := newStack(t)
	id, token := s.temporary(t, "new@example.com")
	if rec := s.changePassword(token, chosen); rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "new@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the temporary password no longer signs in: %d", rec.Code)
	}
	a, claims := s.claims(t, s.signIn(tenantURL, "new@example.com", chosen))
	if _, restricted := claims["access"]; restricted || claims["sub"] != id || a.RefreshToken == "" {
		t.Fatalf("the person now signs in normally, with the roles of the account: %v %+v", claims, a)
	}
	if roles, _ := claims["roles"].([]any); len(roles) != 1 || roles[0] != "TENANT_ADMINISTRATOR" {
		t.Fatalf("roles = %v", claims["roles"])
	}
	var temporaryLeft int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.identity WHERE identity_id = $1::uuid AND temporary_until IS NOT NULL`, id).Scan(&temporaryLeft); err != nil || temporaryLeft != 0 {
		t.Fatalf("the temporary state is cleared: %d %v", temporaryLeft, err)
	}
	var events int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountSessionsRevoked' AND aggregate_id = $1::uuid`, id).Scan(&events); err != nil || events != 1 {
		t.Fatalf("the change leaves the event of the revocation: %d %v", events, err)
	}
}

func TestC_TheTokenOfATemporaryCredentialWorksOnceAndNothingElseAcceptsIt(t *testing.T) {
	s := newStack(t)
	_, token := s.temporary(t, "new@example.com")
	if rec := s.changePassword(token, chosen); rec.Code != http.StatusNoContent {
		t.Fatalf("first use: %d", rec.Code)
	}
	if rec := s.changePassword(token, "An0ther-Good-Pass"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the credential was already changed, so the same token is refused: %d", rec.Code)
	}
	if rec := s.signIn(tenantURL, "new@example.com", "An0ther-Good-Pass"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the second change did not happen: %d", rec.Code)
	}
}

func TestC_AWeakPasswordIsA400AndTheCredentialStaysTemporary(t *testing.T) {
	s := newStack(t)
	id, token := s.temporary(t, "new@example.com")
	for _, weak := range []string{"sh0rt!A", "alllowercase1!", "Password1!", password} {
		rec := s.changePassword(token, weak)
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), weak) {
			t.Errorf("%q: %d %s", weak, rec.Code, rec.Body)
		}
	}
	var temporaryLeft int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.identity WHERE identity_id = $1::uuid AND temporary_until IS NOT NULL`, id).Scan(&temporaryLeft); err != nil || temporaryLeft != 1 {
		t.Fatalf("a refused password changes nothing: %d %v", temporaryLeft, err)
	}
	if rec := s.changePassword(token, chosen); rec.Code != http.StatusNoContent {
		t.Fatalf("a good password after the weak ones works: %d", rec.Code)
	}
}

func TestC_AnOrdinaryTokenCannotChangeThePasswordThroughThisRoute(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	a, _ := s.claims(t, s.signIn(tenantURL, "ana@example.com", password))
	if rec := s.changePassword(a.AccessToken, chosen); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an ordinary session does not choose a first password: %d", rec.Code)
	}
}

func TestC_ATemporaryCredentialThatExpiredBeforeTheChangeLeavesTheAccount(t *testing.T) {
	s := newStack(t)
	id, token := s.temporary(t, "new@example.com")
	if _, err := s.pool.Exec(ctx, `UPDATE security.identity SET temporary_until = now() - interval '1 second' WHERE identity_id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	if rec := s.changePassword(token, chosen); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an expired credential cannot be changed: %d", rec.Code)
	}
	var accounts int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.identity WHERE identity_id = $1::uuid`, id).Scan(&accounts); err != nil || accounts != 1 {
		t.Fatalf("the account stays registered: %d %v", accounts, err)
	}
}

func TestC_LogsAndTablesHoldNoPassword(t *testing.T) {
	s := newStack(t)
	_, token := s.temporary(t, "new@example.com")
	s.changePassword(token, "short")
	s.changePassword(token, chosen)
	for _, secret := range []string{chosen, "short", password} {
		if strings.Contains(s.logs.String(), secret) {
			t.Errorf("the log shows %q", secret)
		}
	}
	var clear int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.identity WHERE password_hash IN ($1, $2)`, chosen, password).Scan(&clear); err != nil || clear != 0 {
		t.Fatalf("a password is stored in clear: %d %v", clear, err)
	}
	if s.logs.Len() == 0 {
		t.Fatal("nothing was logged: the check proves nothing")
	}
}
