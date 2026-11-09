package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
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
//
// The errors returned wrap the driver's, whose PgError.Detail quotes the row that failed (an e-mail): the caller must
// not log it.
func (r *Registry) Create(ctx context.Context, n port.NewAccount, scope, key string) (port.Registered, error) {
	if n.TenantID == "" {
		return port.Registered{}, errors.New("an account created by this registry belongs to a tenant")
	}
	if n.Pending && n.Link == nil {
		return port.Registered{}, errors.New("a pending account needs its first link, or it could never be verified")
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
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
	if err := requireEnabledRole(ctx, tx, n); err != nil {
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
	if err := tx.Commit(ctx); err != nil {
		return port.Registered{}, err // nothing was committed: the caller must not see the hash of an account that is not there
	}
	return reg, nil
}

// AddRole gives the internal role to the account of an active, verified Final Customer of the tenant, in one transaction with the key. The
// account row is locked, so the check "still a customer with no internal role" and the insert cannot be split by another request. No
// account, no fact and no password is written (HU-SEC-008, RN-SEC-007-01 and -09).
func (r *Registry) AddRole(ctx context.Context, a port.AddedRole, scope, key string) (port.Registered, error) {
	if a.TenantID == "" || a.AccountID == "" || !account.IsInternalRole(a.Role) {
		return port.Registered{}, errors.New("a role is added to an account of a tenant, and it is an internal one")
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return port.Registered{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, scope, key); err != nil {
		return port.Registered{}, err
	}
	if _, taken, err := keyOwner(ctx, tx, scope, key); err != nil || taken {
		if err == nil {
			err = port.ErrKeyTaken
		}
		return port.Registered{}, err
	}
	if err := requireEnabledRole(ctx, tx, port.NewAccount{TenantID: a.TenantID, Role: a.Role}); err != nil {
		return port.Registered{}, err
	}
	var membership string
	err = tx.QueryRow(ctx, `
		SELECT m.membership_id::text FROM security.identity i JOIN security.membership m USING (identity_id)
		WHERE i.identity_id = $1::uuid AND i.tenant_id = $2::uuid AND i.identity_status = 'ACTIVE' AND m.membership_status = 'ACTIVE'
		  AND EXISTS (SELECT 1 FROM security.membership_role c WHERE c.membership_id = m.membership_id AND c.role = 'FINAL_CUSTOMER')
		  AND NOT EXISTS (SELECT 1 FROM security.membership_role o WHERE o.membership_id = m.membership_id AND o.role <> 'FINAL_CUSTOMER')
		FOR UPDATE OF i`, a.AccountID, a.TenantID).Scan(&membership)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.Registered{}, port.ErrEmailTaken
	}
	if err != nil {
		return port.Registered{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security.membership_role (membership_id, role) VALUES ($1::uuid, $2)`, membership, a.Role); err != nil {
		return port.Registered{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security.idempotency_key (scope, idempotency_key, identity_id) VALUES ($1, $2, $3::uuid)`, scope, key, a.AccountID); err != nil {
		return port.Registered{}, uniqueViolation(err, "pk_idempotency_key", port.ErrKeyTaken)
	}
	reg, err := load(ctx, tx, a.AccountID)
	if err != nil {
		return port.Registered{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return port.Registered{}, err
	}
	return reg, nil
}

// requireEnabledRole refuses an optional role that the tenant has not enabled (HU-SEC-006, plan D-10). It reads the setting row in share
// mode, inside the transaction that inserts the account: the disabling of the role locks that row for update and counts the active
// holders after it, so a registration and a disabling at once are serialized and none leaves an active holder in a disabled role. A role
// that is not optional reads nothing; a repeat of a key never gets here, as it is answered before.
func requireEnabledRole(ctx context.Context, tx pgx.Tx, n port.NewAccount) error {
	if !account.IsOptionalRole(n.Role) {
		return nil
	}
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT enabled FROM security.tenant_optional_role WHERE tenant_id = $1::uuid AND role = $2 FOR SHARE`, n.TenantID, n.Role).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		return port.ErrRoleNotEnabled
	}
	return err
}

func insertAccount(ctx context.Context, tx pgx.Tx, n port.NewAccount, scope, key string) (string, error) {
	var until *time.Time
	if !n.TemporaryUntil.IsZero() {
		until = &n.TemporaryUntil
	}
	var id, membership string
	status := "ACTIVE"
	if n.Pending {
		status = "PENDING"
	}
	err := tx.QueryRow(ctx, `INSERT INTO security.identity (tenant_id, email_normalized, password_hash, temporary_until, full_name, phone, identity_status)
		VALUES ($1::uuid, $2, $3, $4, $5, NULLIF($6, ''), $7) RETURNING identity_id::text`,
		n.TenantID, n.EmailNormalized, n.PasswordHash, until, n.FullName, n.Phone, status).Scan(&id)
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
	if err != nil {
		return id, uniqueViolation(err, "pk_idempotency_key", port.ErrKeyTaken)
	}
	if n.Pending {
		// the first link is written with the account: an account that waits for it is never left without one
		// created with the instant of the link (the clock of the use case), not the one of the database, so that the limit of
		// three an hour counts it on the same clock as the links that Issue writes
		var createdAt *time.Time
		if !n.Link.CreatedAt.IsZero() {
			createdAt = &n.Link.CreatedAt
		}
		_, err = tx.Exec(ctx, `INSERT INTO security.email_verification (identity_id, token_hash, created_at, expires_at)
			VALUES ($1::uuid, $2, COALESCE($3::timestamptz, now()), $4::timestamptz)`, id, n.Link.TokenHash, createdAt, n.Link.ExpiresAt)
	}
	return id, err
}

// uniqueViolation turns the refusal of one named constraint into the port's error; the driver's error stays reachable.
func uniqueViolation(err error, constraint string, as error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == constraint {
		return fmt.Errorf("%w: %w", as, err)
	}
	return err
}

// load reads an account with the data the answer of a creation shows. An account made here has exactly one role, so
// min(role) is that role; it only picks one deterministically if another story gives an account more.
func load(ctx context.Context, q rowQuerier, id string) (port.Registered, error) {
	var reg port.Registered
	a, err := scanAccount(q.QueryRow(ctx, `SELECT `+accountColumns+`, COALESCE(full_name, ''), COALESCE(phone, ''), email_verified, COALESCE(r.role, ''), r.roles, created_at, `+assignedPermissions+`
		FROM security.identity
		LEFT JOIN LATERAL (SELECT min(mr.role) AS role, COALESCE(array_agg(mr.role ORDER BY mr.role), '{}') AS roles FROM security.membership m
			JOIN security.membership_role mr USING (membership_id) WHERE m.identity_id = identity.identity_id) r ON true
		WHERE identity_id = $1::uuid`, id), &reg.FullName, &reg.Phone, &reg.EmailVerified, &reg.Role, &reg.Roles, &reg.CreatedAt, &reg.Permissions)
	reg.Account = a
	if err != nil {
		return port.Registered{}, err
	}
	return reg, nil
}
