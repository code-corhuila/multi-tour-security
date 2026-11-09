package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

var _ port.SupportAccesses = (*SupportAccesses)(nil)

// SupportAccesses keeps the support accesses of the Platform Administrator in security.support_access (HU-SEC-007 part A, plan D-01).
type SupportAccesses struct{ pool *pgxpool.Pool }

// NewSupportAccesses expects a non-nil pool; the composition root owns it.
func NewSupportAccesses(pool *pgxpool.Pool) *SupportAccesses { return &SupportAccesses{pool: pool} }

// the columns of a request, in the order scanAccess reads them
const supportColumns = `support_access_id::text, tenant_id::text, requested_by::text, reason, areas, hours, status, requested_at,
	COALESCE(decided_by::text, ''), decided_at, COALESCE(decision_reason, ''), expires_at, opened_at, closed_at, COALESCE(closed_reason, '')`

func scanAccess(row pgx.Row) (supportaccess.Access, error) {
	var a supportaccess.Access
	var areas []string
	var status string
	var decidedAt, expiresAt, openedAt, closedAt *time.Time
	err := row.Scan(&a.ID, &a.TenantID, &a.RequestedBy, &a.Reason, &areas, &a.Hours, &status, &a.RequestedAt,
		&a.DecidedBy, &decidedAt, &a.DecisionReason, &expiresAt, &openedAt, &closedAt, &a.ClosedReason)
	if err != nil {
		return supportaccess.Access{}, err
	}
	if a.Areas, err = supportaccess.ParseAreas(areas); err != nil {
		return supportaccess.Access{}, err
	}
	a.Status = supportaccess.Status(status)
	a.RequestedAt = a.RequestedAt.UTC()
	a.DecidedAt, a.ExpiresAt, a.OpenedAt, a.ClosedAt = utc(decidedAt), utc(expiresAt), utc(openedAt), utc(closedAt)
	return a, nil
}

// One statement: the request is stored, or the unique key of its author refuses it (conflict) and nothing is written. Two requests with
// one key at once have one winner, because the second waits for the key and then finds it.
const insertSupportAccess = `
INSERT INTO security.support_access (tenant_id, requested_by, request_key, reason, areas, hours, status, requested_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5::text[], $6, 'PENDING', $7::timestamptz)
ON CONFLICT (requested_by, request_key) DO NOTHING
RETURNING ` + supportColumns

// Create stores the request, or returns the one the author's key already made.
func (s *SupportAccesses) Create(ctx context.Context, a supportaccess.Access, key string) (supportaccess.Access, bool, error) {
	made, err := scanAccess(s.pool.QueryRow(ctx, insertSupportAccess, a.TenantID, a.RequestedBy, key, a.Reason, a.Scope(), a.Hours, a.RequestedAt))
	if err == nil {
		return made, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return supportaccess.Access{}, false, err
	}
	prior, _, err := s.FindByKey(ctx, a.RequestedBy, key)
	return prior, false, err
}

// FindByKey returns the request that the key of that author made.
func (s *SupportAccesses) FindByKey(ctx context.Context, requestedBy, key string) (supportaccess.Access, bool, error) {
	a, err := scanAccess(s.pool.QueryRow(ctx, `SELECT `+supportColumns+` FROM security.support_access WHERE requested_by = $1::uuid AND request_key = $2`, requestedBy, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return supportaccess.Access{}, false, nil
	}
	return a, err == nil, err
}

// ListByRequester is one query: the page and, in each row, the total of the filter. Only the rows of that author are read.
func (s *SupportAccesses) ListByRequester(ctx context.Context, requestedBy, status string, limit, offset int) ([]supportaccess.Access, int, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+supportColumns+`, count(*) OVER () FROM security.support_access
		WHERE requested_by = $1::uuid AND ($2 = '' OR status = $2) ORDER BY requested_at DESC, support_access_id DESC LIMIT $3 OFFSET $4`,
		requestedBy, status, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list, total := []supportaccess.Access{}, 0
	for rows.Next() {
		var a supportaccess.Access
		var areas []string
		var st string
		var decidedAt, expiresAt, openedAt, closedAt *time.Time
		if err := rows.Scan(&a.ID, &a.TenantID, &a.RequestedBy, &a.Reason, &areas, &a.Hours, &st, &a.RequestedAt,
			&a.DecidedBy, &decidedAt, &a.DecisionReason, &expiresAt, &openedAt, &closedAt, &a.ClosedReason, &total); err != nil {
			return nil, 0, err
		}
		if a.Areas, err = supportaccess.ParseAreas(areas); err != nil {
			return nil, 0, err
		}
		a.Status, a.RequestedAt = supportaccess.Status(st), a.RequestedAt.UTC()
		a.DecidedAt, a.ExpiresAt, a.OpenedAt, a.ClosedAt = utc(decidedAt), utc(expiresAt), utc(openedAt), utc(closedAt)
		list = append(list, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(list) == 0 && offset > 0 {
		// a page past the end has no row to carry the total, and the caller still needs it
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.support_access WHERE requested_by = $1::uuid AND ($2 = '' OR status = $2)`, requestedBy, status).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	return list, total, nil
}

// ExpirePending marks the requests of that author that nobody decided within the window as expired. A request that was decided, or that is
// already expired, is not touched, so asking twice changes nothing.
func (s *SupportAccesses) ExpirePending(ctx context.Context, requestedBy string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE security.support_access SET status = 'EXPIRED' WHERE requested_by = $3::uuid AND status = 'PENDING'
		AND requested_at + make_interval(secs => $2::double precision) <= $1::timestamptz`,
		now, supportaccess.DecisionWindow.Seconds(), requestedBy)
	return err
}
