package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/golang-jwt/jwt/v5"
)

// The token of a worker or a saga (RN-SEC-001-13, ADR-004 D5): the name is the subject, the role is SERVICE and there is
// no tenant. `security issue-service-token <name> [duration]` prints it and nothing else, so that a script can keep it.

var issuedAt = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

func issue(t *testing.T, keys keyFiles, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := execute(context.Background(), append([]string{"issue-service-token"}, args...),
		envOf(map[string]string{"JWT_PRIVATE_KEY_FILE": keys.private}), strings.NewReader(""), &out, os.ReadFile, func() time.Time { return issuedAt })
	return out.String(), err
}

func parse(t *testing.T, raw string, keys keyFiles) jwt.MapClaims {
	t.Helper()
	public, err := readPublicKey(os.ReadFile, keys.public)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return public, nil }, jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithTimeFunc(func() time.Time { return issuedAt.Add(10 * time.Second) }), jwt.WithIssuer("multi-tour-security"), jwt.WithAudience("multi-tour"),
		jwt.WithExpirationRequired()); err != nil {
		t.Fatalf("a service holding only the public key refuses the token: %v", err)
	}
	return claims
}

func TestC_TheCommandPrintsOnlyTheTokenOfAServiceForTheTimeAsked(t *testing.T) {
	keys := writeKeys(t, 2048)
	out, err := issue(t, keys, "worker-event-relay", "12h")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") || strings.Contains(out, " ") {
		t.Fatalf("one line with the token and nothing else: %q", out)
	}
	claims := parse(t, strings.TrimSpace(out), keys)
	iat, _ := claims.GetIssuedAt()
	exp, _ := claims.GetExpirationTime()
	nbf, _ := claims.GetNotBefore()
	roles, _ := claims["roles"].([]any)
	if claims["sub"] != "worker-event-relay" || len(roles) != 1 || roles[0] != "SERVICE" || exp.Sub(iat.Time) != 12*time.Hour || !nbf.Equal(iat.Time) {
		t.Fatalf("claims = %v", claims)
	}
	for _, absent := range []string{"tenantId", "access"} {
		if _, has := claims[absent]; has {
			t.Errorf("a service token has no %s: %v", absent, claims)
		}
	}
	if perms, ok := claims["permissions"].([]any); !ok || len(perms) != 0 {
		t.Errorf("permissions are an empty list: %v", claims["permissions"])
	}
}

func TestC_WithoutADurationTheTokenLastsADayAndTheLimitsAreOneMinuteAndThirtyDays(t *testing.T) {
	keys := writeKeys(t, 2048)
	life := func(args ...string) (time.Duration, error) {
		out, err := issue(t, keys, args...)
		if err != nil {
			return 0, err
		}
		claims := parse(t, strings.TrimSpace(out), keys)
		iat, _ := claims.GetIssuedAt()
		exp, _ := claims.GetExpirationTime()
		return exp.Sub(iat.Time), nil
	}
	for args, want := range map[string]time.Duration{"": 24 * time.Hour, "1m": time.Minute, "720h": 30 * 24 * time.Hour} {
		a := []string{"saga-onboard-tenant"}
		if args != "" {
			a = append(a, args)
		}
		if got, err := life(a...); err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", args, got, err, want)
		}
	}
	for _, bad := range []string{"59s", "720h1s", "0", "-1h", "0s", "abc", "30d", "1h30"} {
		if out, err := issue(t, keys, "saga-onboard-tenant", bad); err == nil || out != "" {
			t.Errorf("%q: printed %q, err %v", bad, out, err)
		}
	}
}

func TestC_ANameThatTheServicesWouldRefuseAsASubjectIsRefusedHere(t *testing.T) {
	keys := writeKeys(t, 2048)
	for name, arg := range map[string]string{"blank": "  ", "padded": " worker", "101 characters": strings.Repeat("w", 101), "control": "wor\x07ker"} {
		if out, err := issue(t, keys, arg); err == nil || out != "" {
			t.Errorf("%s: printed %q, err %v", name, out, err)
		}
	}
}

func TestC_AnUnusableCallOrKeyIsRefusedWithoutPrintingAnythingOfTheKey(t *testing.T) {
	keys := writeKeys(t, 2048)
	short := writeKeys(t, 1024)
	for name, c := range map[string]struct {
		args []string
		keys keyFiles
		env  map[string]string
		want string
	}{
		"no name":            {nil, keys, nil, "usage"},
		"too many arguments": {[]string{"w", "1h", "extra"}, keys, nil, "usage"},
		"no key variable":    {[]string{"w"}, keys, map[string]string{"JWT_PRIVATE_KEY_FILE": ""}, "JWT_PRIVATE_KEY_FILE"},
		"key that is absent": {[]string{"w"}, keys, map[string]string{"JWT_PRIVATE_KEY_FILE": keys.private + ".missing"}, "JWT_PRIVATE_KEY_FILE"},
		"key that is short":  {[]string{"w"}, short, nil, "2048"},
		"public key given":   {[]string{"w"}, keys, map[string]string{"JWT_PRIVATE_KEY_FILE": keys.public}, "JWT_PRIVATE_KEY_FILE"},
	} {
		env := map[string]string{"JWT_PRIVATE_KEY_FILE": c.keys.private}
		for k, v := range c.env {
			env[k] = v
		}
		var out bytes.Buffer
		err := execute(context.Background(), append([]string{"issue-service-token"}, c.args...), envOf(env), strings.NewReader(""), &out, os.ReadFile,
			func() time.Time { return issuedAt })
		if err == nil || !strings.Contains(err.Error(), c.want) || out.Len() != 0 || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: %v printed %q", name, err, out.String())
		}
	}
}

// RN-SEC-001-13 and the Done-when of SEC-11: a service that holds only the public key lets a worker in on its internal
// routes with this token, and keeps a person out.
func TestC_TheTokenOfTheCommandOpensTheInternalRoutesAndTheTokenOfAPersonDoesNot(t *testing.T) {
	pool := pgtest.Open(t)
	keys := writeKeys(t, 2048)
	private, err := readPrivateKey(os.ReadFile, keys.private)
	if err != nil {
		t.Fatal(err)
	}
	public, err := readPublicKey(os.ReadFile, keys.public)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := buildHandler(pool, config{privateKey: private, publicKey: public}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	call := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	// the clock of the command is the real one here, because the service reads the token with its own
	var out bytes.Buffer
	if err := execute(context.Background(), []string{"issue-service-token", "worker-event-relay", "1h"},
		envOf(map[string]string{"JWT_PRIVATE_KEY_FILE": keys.private}), strings.NewReader(""), &out, os.ReadFile, time.Now); err != nil {
		t.Fatal(err)
	}
	if code := call(strings.TrimSpace(out.String())); code != http.StatusOK {
		t.Fatalf("a worker with its token: %d", code)
	}
	if code := call(personToken(t, private)); code != http.StatusForbidden {
		t.Fatalf("a person with a token of the same key: %d", code)
	}
}

func personToken(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "multi-tour-security", "aud": "multi-tour", "sub": "acc-1", "tenantId": "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f",
		"roles": []string{"TENANT_ADMINISTRATOR"}, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
