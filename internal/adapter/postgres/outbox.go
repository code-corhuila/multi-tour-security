package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ outbox.Store = (*Outbox)(nil)

// Outbox reads and updates security.outbox_event. The events are written by the same statements that change accounts.
type Outbox struct {
	pool *pgxpool.Pool
}

func NewOutbox(pool *pgxpool.Pool) *Outbox { return &Outbox{pool: pool} }

const eventColumns = `outbox_event_id::text, COALESCE(tenant_id::text, ''), event_type, event_version, aggregate_id::text,
	COALESCE(actor_id::text, ''), COALESCE(reason, ''), payload, correlation_id, occurred_at, published_at, status, attempts,
	COALESCE(last_error, ''), next_attempt_at`

func scanEvent(row pgx.Row) (outbox.Event, error) {
	var e outbox.Event
	var payload []byte
	var published *time.Time
	var status string
	err := row.Scan(&e.ID, &e.TenantID, &e.Type, &e.Version, &e.AggregateID, &e.ActorID, &e.Reason, &payload, &e.CorrelationID,
		&e.OccurredAt, &published, &status, &e.Attempts, &e.LastError, &e.NextAttemptAt)
	if err != nil {
		return outbox.Event{}, err
	}
	e.Payload, e.Status = payload, outbox.Status(status)
	e.OccurredAt, e.NextAttemptAt, e.PublishedAt = e.OccurredAt.UTC(), e.NextAttemptAt.UTC(), utc(published)
	return e, nil
}

// ListDue gives the pending events whose time has come, the one due for longest first, then the one that happened
// first, then by id so that the order is total and the pages never overlap.
func (r *Outbox) ListDue(ctx context.Context, now time.Time, page, limit int) ([]outbox.Event, int, error) {
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE status = 'PENDING' AND next_attempt_at <= $1`, now).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT `+eventColumns+` FROM security.outbox_event WHERE status = 'PENDING' AND next_attempt_at <= $1
		ORDER BY next_attempt_at, occurred_at, outbox_event_id LIMIT $2 OFFSET $3`, now, limit, (page-1)*limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var events []outbox.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

// sameState compares what a change can alter.
func sameState(a, b outbox.Event) bool {
	return a.Status == b.Status && a.Attempts == b.Attempts && a.LastError == b.LastError &&
		a.PublishedAt.Equal(b.PublishedAt) && a.NextAttemptAt.Equal(b.NextAttemptAt)
}

// Modify reads the event under the lock of its row, lets the domain change it and writes the result: a report that
// arrives while another is being written waits for it and sees its result.
func (r *Outbox) Modify(ctx context.Context, id string, change func(outbox.Event) outbox.Event) (outbox.Event, bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return outbox.Event{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := scanEvent(tx.QueryRow(ctx, `SELECT `+eventColumns+` FROM security.outbox_event WHERE outbox_event_id = $1::uuid FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return outbox.Event{}, false, nil
	}
	if err != nil {
		return outbox.Event{}, false, err
	}
	changed := change(current)
	if sameState(current, changed) {
		return changed, true, nil // a repeat, or a report that came late: nothing to write
	}
	var published *time.Time
	if !changed.PublishedAt.IsZero() {
		published = &changed.PublishedAt
	}
	if _, err := tx.Exec(ctx, `UPDATE security.outbox_event SET published_at = $2, status = $3, attempts = $4, last_error = NULLIF($5, ''),
		next_attempt_at = $6 WHERE outbox_event_id = $1::uuid`, id, published, string(changed.Status), changed.Attempts, changed.LastError, changed.NextAttemptAt); err != nil {
		return outbox.Event{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return outbox.Event{}, false, err
	}
	return changed, true, nil
}
