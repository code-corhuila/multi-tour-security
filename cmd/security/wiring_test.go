package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	bcryptadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/bcrypt"
	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/core/session"
	coretenant "github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests start from the composition root, with the real adapters and a real PostgreSQL, and go through HTTP: they
// are the end-to-end proof of what the sign-in promises (RN-SEC-001-01 to -05, -08, -09, -10, -12).

const (
	tenantA   = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	tenantB   = "9c7d1a2b-3c4d-4e6f-8f2b-8c1e5d4a4f6b"
	password  = "correct horse"
	tenantURL = "/api/v1/security/public/tenants/travesia-natural/sessions"
	otherURL  = "/api/v1/security/public/tenants/otra-agencia/sessions"
	rootURL   = "/api/v1/security/public/platform/sessions"
)

var (
	ctx      = context.Background()
	hashOnce sync.Once
	hashed   string
)

func realHash(t *testing.T) string {
	t.Helper()
	hashOnce.Do(func() {
		var err error
		if hashed, err = bcryptadapter.Hash(password); err != nil {
			t.Fatal(err)
		}
	})
	return hashed
}

type stack struct {
	handler http.Handler
	pool    *pgxpool.Pool
	logs    *bytes.Buffer
	public  *rsa.PublicKey
}

func newStack(t *testing.T) *stack {
	t.Helper()
	pool := pgtest.Open(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	handler, err := buildHandler(pool, config{privateKey: key, publicKey: &key.PublicKey}, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	tenants := postgres.NewTenants(pool)
	for id, identifier := range map[string]string{tenantA: "travesia-natural", tenantB: "otra-agencia"} {
		if _, err := tenants.Apply(ctx, coretenant.Copy{TenantID: id, Identifier: identifier, Status: coretenant.Active, OccurredAt: time.Now().Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	return &stack{handler: handler, pool: pool, logs: logs, public: &key.PublicKey}
}

func (s *stack) account(t *testing.T, tenantID, email string, o pgtest.Options, roles ...string) string {
	t.Helper()
	id, err := pgtest.AccountWith(ctx, s.pool, tenantID, email, realHash(t), o, roles...)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (s *stack) signIn(url, email, pass string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"email": email, "password": pass})
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-1")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

type answer struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
}

func (s *stack) claims(t *testing.T, rec *httptest.ResponseRecorder) (answer, jwt.MapClaims) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var a answer
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(a.AccessToken, claims, func(*jwt.Token) (any, error) { return s.public, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("multi-tour-security"), jwt.WithAudience("multi-tour"), jwt.WithExpirationRequired()); err != nil {
		t.Fatalf("a service holding only the public key refuses the token: %v", err)
	}
	return a, claims
}

func TestC_TheTokenIsValidForAServiceWithThePublicKeyAndCarriesTheTenantOfTheLink(t *testing.T) {
	s := newStack(t)
	id := s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR", "MANAGER")
	a, c := s.claims(t, s.signIn(tenantURL, " Ana@Example.com ", password))
	if c["sub"] != id || c["tenantId"] != tenantA || c["iss"] != "multi-tour-security" {
		t.Fatalf("claims = %v", c)
	}
	if roles, _ := c["roles"].([]any); len(roles) != 2 || roles[0] != "MANAGER" || roles[1] != "TENANT_ADMINISTRATOR" {
		t.Fatalf("roles = %v", c["roles"])
	}
	if _, has := c["access"]; has || a.ExpiresIn != 900 || a.RefreshToken == "" {
		t.Fatalf("an ordinary token has no access mark, lasts 900 seconds and comes with a renewal value: %v %+v", c, a)
	}
	iat, _ := c.GetIssuedAt()
	exp, _ := c.GetExpirationTime()
	nbf, _ := c.GetNotBefore()
	if exp.Sub(iat.Time) != 15*time.Minute || nbf.Time.Before(iat.Time) {
		t.Fatalf("iat %v nbf %v exp %v", iat, nbf, exp)
	}
}

func TestC_TheRenewalValueIsStoredOnlyAsAHashAndTheSessionLastsSevenDays(t *testing.T) {
	s := newStack(t)
	id := s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	a, _ := s.claims(t, s.signIn(tenantURL, "ana@example.com", password))
	var hash string
	var created, expires time.Time
	err := s.pool.QueryRow(ctx, `SELECT r.token_hash, s.created_at, s.expires_at FROM security.session s
		JOIN security.refresh_token r USING (session_id) WHERE s.identity_id = $1::uuid`, id).Scan(&hash, &created, &expires)
	if err != nil || hash != session.Hash(a.RefreshToken) || expires.Sub(created) != session.Life {
		t.Fatalf("hash %q, session %v to %v: %v", hash, created, expires, err)
	}
	var found int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.refresh_token WHERE token_hash = $1`, a.RefreshToken).Scan(&found); err != nil || found != 0 {
		t.Fatalf("the renewal value is stored in clear: %d %v", found, err)
	}
}

func TestC_EveryRefusalIsTheSame401WhateverTheCause(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	s.account(t, tenantB, "bob@example.com", pgtest.Options{}, "ANALYST")
	s.account(t, tenantA, "off@example.com", pgtest.Options{Inactive: true}, "ANALYST")
	s.account(t, tenantA, "old@example.com", pgtest.Options{TemporaryUntil: time.Now().Add(-time.Hour)}, "ANALYST")
	refusals := map[string]*httptest.ResponseRecorder{
		"wrong password":       s.signIn(tenantURL, "ana@example.com", "wrong"),
		"unknown e-mail":       s.signIn(tenantURL, "nobody@example.com", password),
		"account of a link":    s.signIn(tenantURL, "bob@example.com", password),
		"unknown tenant":       s.signIn("/api/v1/security/public/tenants/nowhere/sessions", "ana@example.com", password),
		"inactive account":     s.signIn(tenantURL, "off@example.com", password),
		"expired temporary":    s.signIn(tenantURL, "old@example.com", password),
		"platform with tenant": s.signIn(rootURL, "ana@example.com", password),
	}
	var want string
	for name, rec := range refusals {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, rec.Code)
		}
		if want == "" {
			want = rec.Body.String()
		} else if rec.Body.String() != want {
			t.Errorf("%s answered %s, others %s", name, rec.Body, want)
		}
	}
}

func TestC_FiveWrongPasswordsBlockTheAccountAndTheRightOneIsThenRefusedLikeAnyOther(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	for i := 0; i < 5; i++ {
		s.signIn(tenantURL, "ana@example.com", "wrong")
	}
	blocked := s.signIn(tenantURL, "ana@example.com", password)
	unknown := s.signIn(tenantURL, "nobody@example.com", password)
	if blocked.Code != http.StatusUnauthorized || blocked.Body.String() != unknown.Body.String() {
		t.Fatalf("a blocked account is refused like an unknown one: %d %s", blocked.Code, blocked.Body)
	}
	var events int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE event_type = 'AccountBlocked'`).Scan(&events); err != nil || events != 1 {
		t.Fatalf("the block leaves one event: %d %v", events, err)
	}
}

func TestC_ThePlatformAdministratorSignsInWithoutATenant(t *testing.T) {
	s := newStack(t)
	id := s.account(t, "", "root@example.com", pgtest.Options{}, "PLATFORM_ADMINISTRATOR")
	_, c := s.claims(t, s.signIn(rootURL, "root@example.com", password))
	if _, has := c["tenantId"]; has || c["sub"] != id {
		t.Fatalf("the platform token has no tenantId: %v", c)
	}
	if rec := s.signIn(tenantURL, "root@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the platform account does not sign in through a tenant: %d", rec.Code)
	}
}

func TestC_AnInactiveTenantLetsInOnlyItsAdministratorWithARestrictedAccess(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "boss@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := postgres.NewTenants(s.pool).Apply(ctx, coretenant.Copy{TenantID: tenantA, Identifier: "travesia-natural", Status: coretenant.Inactive, OccurredAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	a, c := s.claims(t, s.signIn(tenantURL, "boss@example.com", password))
	if c["access"] != "restricted" || a.RefreshToken != "" {
		t.Fatalf("restricted and not renewable: %v %+v", c, a)
	}
	if rec := s.signIn(tenantURL, "ana@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another user of an inactive tenant is refused: %d", rec.Code)
	}
}

func TestC_FirstSignInWithATemporaryCredentialOnlyGivesTheTokenToChooseAPassword(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "new@example.com", pgtest.Options{TemporaryUntil: time.Now().Add(72 * time.Hour)}, "TENANT_ADMINISTRATOR")
	a, c := s.claims(t, s.signIn(tenantURL, "new@example.com", password))
	if roles, _ := c["roles"].([]any); len(roles) != 0 || c["access"] != "password-change" || a.RefreshToken != "" || a.ExpiresIn != 600 {
		t.Fatalf("%v %+v", c, a)
	}
	var sessions int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.session`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("a temporary credential opens no session: %d %v", sessions, err)
	}
}

func TestC_LogsShowNoCredentialNoEmailAndNoToken(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	ok := s.signIn(tenantURL, "ana@example.com", password)
	s.signIn(tenantURL, "ana@example.com", "wrong-password-text")
	s.signIn(tenantURL, "nobody@example.com", "other-password-text")
	var a answer
	_ = json.Unmarshal(ok.Body.Bytes(), &a)
	for _, secret := range []string{password, "wrong-password-text", "other-password-text", "ana@example.com", "nobody@example.com", a.AccessToken, a.RefreshToken} {
		if strings.Contains(s.logs.String(), secret) {
			t.Errorf("the log shows %q", secret)
		}
	}
	if s.logs.Len() == 0 {
		t.Fatal("nothing was logged: the check proves nothing")
	}
}

func TestC_TheVerifierOfEveryServiceAcceptsWhatTheSignInIssues(t *testing.T) {
	s := newStack(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "ANALYST")
	a, _ := s.claims(t, s.signIn(tenantURL, "ana@example.com", password))
	if _, err := httpadapter.NewVerifier(s.public).Verify(a.AccessToken); err != nil {
		t.Fatalf("the verifier of this very service refused it: %v", err)
	}
}
