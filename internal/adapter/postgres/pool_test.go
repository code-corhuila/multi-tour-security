package postgres_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
)

// the limits of the plan (piece plan D-09, Annex C): a pool of 10, 5 seconds to connect, 5 seconds per statement
var limits = postgres.Limits{MaxConns: 10, ConnectTimeout: 5 * time.Second, StatementTimeout: 5 * time.Second}

func TestI_ThePoolIsOpenedWithTheLimitsOfThePlan(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is not set in the CI")
		}
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool, err := postgres.Open(ctx, url, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if got := pool.Config().MaxConns; got != 10 {
		t.Errorf("MaxConns = %d, want 10", got)
	}
	var timeout string
	if err := pool.QueryRow(ctx, `SHOW statement_timeout`).Scan(&timeout); err != nil || timeout != "5s" {
		t.Errorf("statement_timeout = %q, %v: a statement must not run for more than 5 seconds", timeout, err)
	}
}

func TestI_AStatementThatRunsLongerThanTheLimitIsCutOff(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	short := postgres.Limits{MaxConns: 2, ConnectTimeout: 5 * time.Second, StatementTimeout: 200 * time.Millisecond}
	pool, err := postgres.Open(ctx, url, short)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(2)`); err == nil {
		t.Fatal("a statement of two seconds ran under a limit of 200 ms")
	}
}

func TestI_AnUnreachableDatabaseFailsAtStartUpWithinTheConnectionLimitAndNeverShowsThePassword(t *testing.T) {
	started := time.Now()
	_, err := postgres.Open(ctx, "postgres://security_app:s3cret-pw@127.0.0.1:1/multitour?sslmode=disable", limits)
	if err == nil {
		t.Fatal("a pool was opened on a port nobody listens on")
	}
	if strings.Contains(err.Error(), "s3cret-pw") {
		t.Fatalf("the error shows the password: %v", err)
	}
	if time.Since(started) > 10*time.Second {
		t.Fatalf("giving up took %v", time.Since(started))
	}
}

func TestI_AUrlThatCannotBeParsedFailsWithoutEchoingIt(t *testing.T) {
	_, err := postgres.Open(ctx, "postgres://security_app:s3cret-pw@%zz/multitour", limits)
	if err == nil || strings.Contains(err.Error(), "s3cret-pw") {
		t.Fatalf("a bad URL must fail, and say nothing of the password: %v", err)
	}
}
