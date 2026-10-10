// Package pgtest gives the tests of the PostgreSQL adapter a database of their own, built from the DDL of db/ so the
// tests run against the real constraints (plan D-09). It is imported by tests only.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ValidHash has the shape of a bcrypt hash (cost 12), which is all the CHECK of the table asks for.
const ValidHash = "$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

// Open creates a throwaway database from TEST_DATABASE_URL, applies the DDL and returns a pool on it. The test is
// skipped when the variable is not set; the CI sets it.
func Open(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is not set in the CI: the tests would pass without testing anything")
		}
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "t_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		t.Fatal(err)
	}
	// registered right after the creation, so that no later failure leaves the database behind; it runs before admin.Close
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		_, _ = admin.Exec(ctx, `DROP DATABASE `+name+` WITH (FORCE)`)
	})
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	if pool, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	for _, file := range ddlFiles(t) {
		sql, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	return pool
}

// ddlFiles lists the SQL of db/01_ddl in the order of the migrations: by folder, then by file name.
func ddlFiles(t *testing.T) []string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "db", "01_ddl")
	files, err := filepath.Glob(filepath.Join(root, "*", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no DDL found under %s: %v", root, err)
	}
	sort.Strings(files)
	return files
}
