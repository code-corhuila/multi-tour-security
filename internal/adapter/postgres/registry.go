package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ port.AccountRegistry = (*Registry)(nil)

// Registry creates the accounts of HU-SEC-002 and remembers which idempotency key made which account.
type Registry struct {
	pool *pgxpool.Pool
}

func NewRegistry(pool *pgxpool.Pool) *Registry { return &Registry{pool: pool} }

// rowQuerier is what the pool and a transaction share, so that one read serves both.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// FindKey returns the account that the key made in the scope, if any.
func (r *Registry) FindKey(ctx context.Context, scope, key string) (port.Registered, bool, error) {
	id, found, err := keyOwner(ctx, r.pool, scope, key)
	if err != nil || !found {
		return port.Registered{}, false, err
	}
	reg, err := load(ctx, r.pool, id)
	return reg, err == nil, err
}

func keyOwner(ctx context.Context, q rowQuerier, scope, key string) (string, bool, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT identity_id::text FROM security.idempotency_key WHERE scope = $1 AND idempotency_key = $2`,
		scope, key).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return id, err == nil, err
}

// Create writes the identity, its membership, its role and the key in one transaction. The advisory lock on the key
// makes two requests with the same key take turns: the second finds the key and gets ErrKeyTaken, and never reaches the
// unique e-mail, which would tell it wrongly that the e-mail belongs to someone else.
func (r *Registry) Create(ctx context.Context, n port.NewAccount, scope, key string) (port.Registered, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return port.Registered{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op once committed

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, scope, key); err != nil {
		return port.Registered{}, err
	}
	if _, taken, err := keyOwner(ctx, tx, scope, key); err != nil || taken {
		if err == nil {
			err = port.ErrKeyTaken
		}
		return port.Registered{}, err
	}
	id, err := insertAccount(ctx, tx, n, scope, key)
	if err != nil {
		return port.Registered{}, err
	}
	reg, err := load(ctx, tx, id)
	if err != nil {
		return port.Registered{}, err
	}
	return reg, tx.Commit(ctx)
}

func insertAccount(ctx context.Context, tx pgx.Tx, n port.NewAccount, scope, key string) (string, error) {
	var until *time.Time
	if !n.TemporaryUntil.IsZero() {
		until = &n.TemporaryUntil
	}
	var id, membership string
	err := tx.QueryRow(ctx, `INSERT INTO security.identity (tenant_id, email_normalized, password_hash, temporary_until, full_name, phone)
		VALUES ($1::uuid, $2, $3, $4, $5, NULLIF($6, '')) RETURNING identity_id::text`,
		n.TenantID, n.EmailNormalized, n.PasswordHash, until, n.FullName, n.Phone).Scan(&id)
	if err != nil {
		return "", uniqueViolation(err, "uq_identity_tenant_email", port.ErrEmailTaken)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO security.membership (identity_id, created_by) VALUES ($1::uuid, $2) RETURNING membership_id::text`,
		id, n.CreatedBy).Scan(&membership); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security.membership_role (membership_id, role) VALUES ($1::uuid, $2)`, membership, n.Role); err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO security.idempotency_key (scope, idempotency_key, identity_id) VALUES ($1, $2, $3::uuid)`, scope, key, id)
	// backstop of the lock: the primary key of the key table still decides if the lock was bypassed
	return id, uniqueViolation(err, "pk_idempotency_key", port.ErrKeyTaken)
}

// uniqueViolation turns the refusal of one named constraint into the port's error; the driver's error stays reachable.
func uniqueViolation(err error, constraint string, as error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == constraint {
		return fmt.Errorf("%w: %w", as, err)
	}
	return err
}

// load reads an account with the data the answer of a creation shows.
func load(ctx context.Context, q rowQuerier, id string) (port.Registered, error) {
	a, err := scanAccount(q.QueryRow(ctx, `SELECT `+accountColumns+` FROM security.identity WHERE identity_id = $1::uuid`, id))
	if err != nil {
		return port.Registered{}, err
	}
	reg := port.Registered{Account: a}
	err = q.QueryRow(ctx, `SELECT COALESCE(i.full_name, ''), COALESCE(i.phone, ''), i.email_verified, COALESCE(min(mr.role), '')
		FROM security.identity i
		LEFT JOIN security.membership m ON m.identity_id = i.identity_id
		LEFT JOIN security.membership_role mr ON mr.membership_id = m.membership_id
		WHERE i.identity_id = $1::uuid GROUP BY i.identity_id`, id).Scan(&reg.FullName, &reg.Phone, &reg.EmailVerified, &reg.Role)
	return reg, err
}
