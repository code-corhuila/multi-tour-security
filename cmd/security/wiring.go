package main

import (
	"crypto/rand"
	"log/slog"
	"net/http"
	"time"

	bcryptadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/bcrypt"
	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	jwtadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/jwt"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/smtpmail"
	"github.com/code-corhuila/multi-tour-security/internal/core/changepassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
	"github.com/code-corhuila/multi-tour-security/internal/core/refresh"
	"github.com/code-corhuila/multi-tour-security/internal/core/requestlink"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenantevent"
	"github.com/code-corhuila/multi-tour-security/internal/core/verifyemail"
	"github.com/jackc/pgx/v5/pgxpool"
)

// backgroundTimeout bounds the work that is done after an answer: it is longer than the 30 seconds of a mail exchange.
const backgroundTimeout = 45 * time.Second

// build is the only place where the adapters meet the core. The dummy hash is made here, once, so that every sign-in costs a
// bcrypt comparison even when there is no account. It also returns the runner of the work that is done after an answer, which
// the shutdown waits for. At most twice the size of the pool run at once: the extra ones wait for a connection of the pool until
// their own deadline, and a work that does not fit is dropped, so the gateway limit on these routes is the first brake.
func build(pool *pgxpool.Pool, cfg config, logger *slog.Logger) (http.Handler, *httpadapter.Background, error) {
	dummy, err := bcryptadapter.NewDummyHash()
	if err != nil {
		return nil, nil, err
	}
	mailer, err := smtpmail.New(cfg.mail)
	if err != nil {
		return nil, nil, err
	}
	tenants, accounts, sessions := postgres.NewTenants(pool), postgres.NewAccounts(pool), postgres.NewSessions(pool)
	links := postgres.NewVerifications(pool)
	signer := jwtadapter.NewSigner(cfg.privateKey)
	signIn := &signin.Service{
		Tenants: tenants, Accounts: accounts, Sessions: sessions, Hasher: bcryptadapter.Hasher{}, Signer: signer,
		DummyHash: dummy, Clock: time.Now,
	}
	renewal := &refresh.Service{Tenants: tenants, Accounts: accounts, Sessions: sessions, Signer: signer, Clock: time.Now}
	firstPassword := &changepassword.Service{Accounts: accounts, Hasher: bcryptadapter.Hasher{}, Clock: time.Now}
	newAccounts := &createaccount.Service{
		Tenants: tenants, Accounts: accounts, Registry: postgres.NewRegistry(pool), Hasher: bcryptadapter.Hasher{}, Clock: time.Now,
		Verifications: links, Mailer: mailer, Random: rand.Reader,
	}
	askForLink := &requestlink.Service{Tenants: tenants, Accounts: accounts, Verifications: links, Mailer: mailer, Random: rand.Reader, Clock: time.Now}
	confirmEmail := &verifyemail.Service{Tenants: tenants, Accounts: accounts, Verifications: links, Hasher: bcryptadapter.Hasher{}, Clock: time.Now}
	events := &outbox.Service{Store: postgres.NewOutbox(pool), Clock: time.Now, Policy: outbox.DefaultPolicy}
	background := httpadapter.NewBackground(logger, backgroundTimeout, 2*dbPoolSize)
	return httpadapter.New(httpadapter.NewVerifier(cfg.publicKey), logger,
		httpadapter.WithSignIn(signIn), httpadapter.WithRefresh(renewal), httpadapter.WithChangePassword(firstPassword),
		httpadapter.WithCreateAccount(newAccounts, tenants), httpadapter.WithCreateFirstAdministrator(newAccounts), httpadapter.WithOutbox(events),
		httpadapter.WithTenantEvents(&tenantevent.Service{Tenants: tenants}),
		httpadapter.WithLinkRequests(askForLink, background), httpadapter.WithEmailConfirmation(confirmEmail)), background, nil
}
