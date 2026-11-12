package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

func TestC_ADurationInAnyFormGoUnderstandsIsJudgedByItsValue(t *testing.T) {
	keys := writeKeys(t, 2048)
	for _, ok := range []string{"60s", "1h30m", "1.5h", "+1h", "90m", "43200m"} {
		if out, err := issue(t, keys, "saga-onboard-tenant", ok); err != nil || strings.Count(out, "\n") != 1 {
			t.Errorf("%q: %v %q", ok, err, out)
		}
	}
	for _, bad := range []string{"500ms", "1us", "1ns", "59s", "9999999h", "43201m", "1e3h", "", " 1h", "1h "} {
		if out, err := issue(t, keys, "saga-onboard-tenant", bad); err == nil || out != "" {
			t.Errorf("%q: printed %q, err %v", bad, out, err)
		}
	}
}

func TestC_NoErrorOfTheCommandShowsTheKeyOrWhereItIs(t *testing.T) {
	keys := writeKeys(t, 2048)
	short := writeKeys(t, 1024)
	for name, c := range map[string]struct {
		file string
		want string
	}{
		"absent":     {keys.private + ".missing", "cannot be read"},
		"public key": {keys.public, "PKCS#8"},
		"short key":  {short.private, "2048"},
	} {
		var out bytes.Buffer
		err := execute(context.Background(), []string{"issue-service-token", "worker"}, envOf(map[string]string{"JWT_PRIVATE_KEY_FILE": c.file}),
			strings.NewReader(""), &out, os.ReadFile, time.Now)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), c.file) || out.Len() != 0 {
			t.Errorf("%s: %v printed %q", name, err, out.String())
		}
	}
}

// The lifetime and the clock of the command reach the service: a token issued for a minute two minutes ago is expired
// there, and one that was never meant for a service is not let in by its signature alone.
func TestC_ATokenIssuedAMinuteForTwoMinutesAgoIsExpiredAtTheService(t *testing.T) {
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
	handler, _, err := build(pool, testConfig(private, public), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := execute(context.Background(), []string{"issue-service-token", "worker-event-relay", "1m"}, envOf(map[string]string{"JWT_PRIVATE_KEY_FILE": keys.private}),
		strings.NewReader(""), &out, os.ReadFile, func() time.Time { return time.Now().Add(-2 * time.Minute) }); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, outboxURL, nil)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(out.String()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an expired token of a service: %d", rec.Code)
	}
}
