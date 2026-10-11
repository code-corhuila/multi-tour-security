package postgres

import (
	"context"
	"errors"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ port.AccountRegistry = (*Registry)(nil)

// Registry creates the accounts of HU-SEC-002 and remembers which idempotency key made which account.
type Registry struct {
	pool *pgxpool.Pool
}

func NewRegistry(pool *pgxpool.Pool) *Registry { return &Registry{pool: pool} }

func (r *Registry) FindKey(ctx context.Context, scope, key string) (port.Registered, bool, error) {
	return port.Registered{}, false, errors.New("not implemented")
}

func (r *Registry) Create(ctx context.Context, n port.NewAccount, scope, key string) (port.Registered, error) {
	return port.Registered{}, errors.New("not implemented")
}
