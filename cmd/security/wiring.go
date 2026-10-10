package main

import (
	"log/slog"
	"net/http"
	"time"

	bcryptadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/bcrypt"
	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	jwtadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/jwt"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildHandler is the only place where the adapters meet the core. The dummy hash is made here, once, so that every
// sign-in costs a bcrypt comparison even when there is no account.
func buildHandler(pool *pgxpool.Pool, cfg config, logger *slog.Logger) (http.Handler, error) {
	dummy, err := bcryptadapter.NewDummyHash()
	if err != nil {
		return nil, err
	}
	service := &signin.Service{
		Tenants:   postgres.NewTenants(pool),
		Accounts:  postgres.NewAccounts(pool),
		Sessions:  postgres.NewSessions(pool),
		Hasher:    bcryptadapter.Hasher{},
		Signer:    jwtadapter.NewSigner(cfg.privateKey),
		DummyHash: dummy,
		Clock:     time.Now,
	}
	return httpadapter.New(httpadapter.NewVerifier(cfg.publicKey), logger, httpadapter.WithSignIn(service)), nil
}
