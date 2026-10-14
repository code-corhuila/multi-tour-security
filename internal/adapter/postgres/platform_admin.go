package postgres

import (
	"context"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ port.PlatformAdmins = (*PlatformAdmins)(nil)

// PlatformAdmins makes the account of the Platform Administrator in security.identity.
type PlatformAdmins struct {
	pool *pgxpool.Pool
}

func NewPlatformAdmins(pool *pgxpool.Pool) *PlatformAdmins { return &PlatformAdmins{pool: pool} }

// platformAdminLock is the key of the advisory lock that serializes the creation of the first Platform Administrator.
const platformAdminLock = 7404001

func (r *PlatformAdmins) CreateFirst(ctx context.Context, email, hash string, temporaryUntil time.Time) (bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// two runs at once would both see "no platform account" under READ COMMITTED: the lock makes the second wait for
	// the first and see its account
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, platformAdminLock); err != nil {
		return false, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM security.identity WHERE tenant_id IS NULL)`).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	var id string
	if err := tx.QueryRow(ctx, `INSERT INTO security.identity (tenant_id, email_normalized, password_hash, temporary_until)
		VALUES (NULL, $1, $2, $3) RETURNING identity_id::text`, email, hash, temporaryUntil).Scan(&id); err != nil {
		return false, err
	}
	var membership string
	if err := tx.QueryRow(ctx, `INSERT INTO security.membership (identity_id, created_by) VALUES ($1::uuid, 'bootstrap')
		RETURNING membership_id::text`, id).Scan(&membership); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security.membership_role (membership_id, role) VALUES ($1::uuid, 'PLATFORM_ADMINISTRATOR')`, membership); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
