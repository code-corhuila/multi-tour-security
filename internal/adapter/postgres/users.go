package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// UserDirectory reads the users of a tenant for its Administrator.
type UserDirectory struct{ pool *pgxpool.Pool }

// NewUserDirectory expects a non-nil pool; the composition root owns it.
func NewUserDirectory(pool *pgxpool.Pool) *UserDirectory { return &UserDirectory{pool: pool} }

// the filters are optional: an empty status matches any, and the roles are an array so that one query serves them all
const userFilters = `WHERE tenant_id = $1::uuid AND ($3 = '' OR identity_status = $3)`

// the role shown is the smallest by name of the ones the filter lets in; an account with none of them is not listed. Today a user
// has one internal role (RN-SEC-003-02), so there is nothing to choose; with two the account would still appear once
const userRole = `JOIN LATERAL (SELECT min(mr.role) AS role FROM security.membership m
		JOIN security.membership_role mr USING (membership_id)
		WHERE m.identity_id = identity.identity_id AND mr.role = ANY($2)) r ON r.role IS NOT NULL`

// List is one query: the page and, in each row, the total of the filter. The hash is not selected, so it cannot leak. The
// order is the index of the listing, with the identifier as the tie-break, so a page never repeats or skips a user.
func (d *UserDirectory) List(ctx context.Context, tenantID string, f port.UserFilter, limit, offset int) ([]port.Registered, int, error) {
	rows, err := d.pool.Query(ctx, `SELECT identity_id::text, COALESCE(tenant_id::text, ''), email_normalized, identity_status, temporary_until,
			COALESCE(full_name, ''), COALESCE(phone, ''), email_verified, r.role, created_at, count(*) OVER (),
			status_changed_at, COALESCE(status_changed_by, ''), COALESCE(status_reason, '')
		FROM security.identity `+userRole+` `+userFilters+`
		ORDER BY created_at DESC, identity_id DESC LIMIT $4 OFFSET $5`, tenantID, f.Roles, f.Status, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	users := []port.Registered{}
	total := 0
	for rows.Next() {
		var u port.Registered
		var status string
		var temporary, changedAt *time.Time
		if err := rows.Scan(&u.Account.ID, &u.Account.TenantID, &u.Account.EmailNormalized, &status, &temporary,
			&u.FullName, &u.Phone, &u.EmailVerified, &u.Role, &u.CreatedAt, &total, &changedAt, &u.Changed.By, &u.Changed.Reason); err != nil {
			return nil, 0, err
		}
		if u.Account.Status, err = statusOf(status); err != nil {
			return nil, 0, err
		}
		u.Account.TemporaryUntil, u.CreatedAt, u.Changed.At = utc(temporary), u.CreatedAt.UTC(), utc(changedAt)
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(users) == 0 && offset > 0 {
		// a page beyond the end has no row to carry the total, and the caller still needs it; read apart from the page, so a
		// write in between can make it differ by one, which a count of users tolerates
		if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM security.identity `+userRole+` `+userFilters, tenantID, f.Roles, f.Status).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	return users, total, nil
}

var _ port.UserDirectory = (*UserDirectory)(nil)
