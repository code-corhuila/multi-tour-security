package main

import (
	"log/slog"
	"net/http"
	"time"

	bcryptadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/bcrypt"
	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	jwtadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/jwt"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/core/changepassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
	"github.com/code-corhuila/multi-tour-security/internal/core/refresh"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenantevent"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildHandler is the only place where the adapters meet the core. The dummy hash is made here, once, so that every
// sign-in costs a bcrypt comparison even when there is no account.
func buildHandler(pool *pgxpool.Pool, cfg config, logger *slog.Logger) (http.Handler, error) {
	dummy, err := bcryptadapter.NewDummyHash()
	if err != nil {
		return nil, err
	}
	tenants, accounts, sessions := postgres.NewTenants(pool), postgres.NewAccounts(pool), postgres.NewSessions(pool)
	signer := jwtadapter.NewSigner(cfg.privateKey)
	signIn := &signin.Service{
		Tenants: tenants, Accounts: accounts, Sessions: sessions, Hasher: bcryptadapter.Hasher{}, Signer: signer,
		DummyHash: dummy, Clock: time.Now,
	}
	renewal := &refresh.Service{Tenants: tenants, Accounts: accounts, Sessions: sessions, Signer: signer, Clock: time.Now}
	firstPassword := &changepassword.Service{Accounts: accounts, Hasher: bcryptadapter.Hasher{}, Clock: time.Now}
	newAccounts := &createaccount.Service{
		Tenants: tenants, Accounts: accounts, Registry: postgres.NewRegistry(pool), Hasher: bcryptadapter.Hasher{}, Clock: time.Now,
	}
	events := &outbox.Service{Store: postgres.NewOutbox(pool), Clock: time.Now, Policy: outbox.DefaultPolicy}
	return httpadapter.New(httpadapter.NewVerifier(cfg.publicKey), logger,
		httpadapter.WithSignIn(signIn), httpadapter.WithRefresh(renewal), httpadapter.WithChangePassword(firstPassword),
		httpadapter.WithCreateAccount(newAccounts, tenants), httpadapter.WithCreateFirstAdministrator(newAccounts), httpadapter.WithOutbox(events), httpadapter.WithTenantEvents(&tenantevent.Service{Tenants: tenants})), nil
}
