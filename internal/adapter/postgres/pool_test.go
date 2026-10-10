package postgres_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/jackc/pgx/v5/pgconn"
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
	if got := pool.Stat().MaxConns(); got != 10 {
		t.Errorf("the pool allows %d connections, want 10", got)
	}
	var timeout string
	if err := pool.QueryRow(ctx, `SHOW statement_timeout`).Scan(&timeout); err != nil || timeout != "5s" {
		t.Errorf("statement_timeout = %q, %v: a statement must not run for more than 5 seconds", timeout, err)
	}
}

func TestI_AStatementThatRunsLongerThanTheLimitIsCutOff(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is not set in the CI")
		}
		t.Skip("TEST_DATABASE_URL is not set")
	}
	short := postgres.Limits{MaxConns: 2, ConnectTimeout: 5 * time.Second, StatementTimeout: 200 * time.Millisecond}
	pool, err := postgres.Open(ctx, url, short)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	started := time.Now()
	_, err = pool.Exec(ctx, `SELECT pg_sleep(2)`)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "57014" || time.Since(started) > time.Second {
		t.Fatalf("a statement of two seconds must be cancelled by the limit (57014) within a second: %v after %v", err, time.Since(started))
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
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("the operator must be told the kind of failure, without the connection string: %v", err)
	}
	if time.Since(started) > 10*time.Second {
		t.Fatalf("giving up took %v", time.Since(started))
	}
}

func TestI_AUrlThatCannotBeParsedFailsWithoutEchoingIt(t *testing.T) {
	_, err := postgres.Open(ctx, "postgres://security_app:s3cret-pw@%zz/multitour", limits)
	if err == nil || err.Error() != "DATABASE_URL cannot be parsed" {
		t.Fatalf("a bad URL must fail with a fixed text that says nothing of the password: %v", err)
	}
}
