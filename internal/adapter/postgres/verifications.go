package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Verifications reads and writes security.email_verification (HU-SEC-003). It only ever sees the hash of a link.
type Verifications struct {
	pool *pgxpool.Pool
}

func NewVerifications(pool *pgxpool.Pool) *Verifications { return &Verifications{pool: pool} }

func (v *Verifications) Issue(context.Context, string, port.NewLink, time.Time, int, time.Duration) (bool, error) {
	return false, errors.New("not implemented")
}

func (v *Verifications) Find(context.Context, string) (port.LinkState, bool, error) {
	return port.LinkState{}, false, errors.New("not implemented")
}
