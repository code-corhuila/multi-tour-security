package pgtest

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Options are the states of an account that a test needs besides the default (active, ordinary password).
type Options struct {
	Inactive           bool
	Pending            bool
	TemporaryUntil     time.Time
	MembershipInactive bool
}

// AccountWith creates an account with its membership and roles and returns its id. Until HU-SEC-002 and HU-SEC-005
// exist the tests make accounts with SQL, and there is no route or seed that does (plan D-10). tenantID is empty for
// the platform. It returns the error instead of failing so that a test can check a constraint.
func AccountWith(ctx context.Context, pool *pgxpool.Pool, tenantID, email, hash string, o Options, roles ...string) (string, error) {
	status := "ACTIVE"
	if o.Inactive {
		status = "INACTIVE"
	}
	if o.Pending {
		status = "PENDING"
	}
	var until *time.Time
	if !o.TemporaryUntil.IsZero() {
		until = &o.TemporaryUntil
	}
	var id string
	err := pool.QueryRow(ctx, `INSERT INTO security.identity (tenant_id, email_normalized, password_hash, identity_status, temporary_until)
		VALUES (NULLIF($1, '')::uuid, $2, $3, $4, $5) RETURNING identity_id::text`, tenantID, email, hash, status, until).Scan(&id)
	if err != nil {
		return "", err
	}
	membershipStatus := "ACTIVE"
	if o.MembershipInactive {
		membershipStatus = "INACTIVE"
	}
	var membership string
	if err := pool.QueryRow(ctx, `INSERT INTO security.membership (identity_id, created_by, membership_status) VALUES ($1::uuid, 'test', $2)
		RETURNING membership_id::text`, id, membershipStatus).Scan(&membership); err != nil {
		return "", err
	}
	for _, role := range roles {
		if _, err := pool.Exec(ctx, `INSERT INTO security.membership_role (membership_id, role) VALUES ($1::uuid, $2)`,
			membership, role); err != nil {
			return "", err
		}
	}
	return id, nil
}

// Account is AccountWith with the default state.
func Account(ctx context.Context, pool *pgxpool.Pool, tenantID, email, hash string, roles ...string) (string, error) {
	return AccountWith(ctx, pool, tenantID, email, hash, Options{}, roles...)
}

// MustAccount is Account for the tests that only need the account to exist.
func MustAccount(t *testing.T, pool *pgxpool.Pool, tenantID, email string, roles ...string) string {
	t.Helper()
	id, err := Account(context.Background(), pool, tenantID, email, ValidHash, roles...)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
