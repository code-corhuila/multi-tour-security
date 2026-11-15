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
	"github.com/code-corhuila/multi-tour-security/internal/core/changepermission"
	"github.com/code-corhuila/multi-tour-security/internal/core/changestatus"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/issuetemp"
	"github.com/code-corhuila/multi-tour-security/internal/core/listusers"
	"github.com/code-corhuila/multi-tour-security/internal/core/optionalrole"
	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
	"github.com/code-corhuila/multi-tour-security/internal/core/recoverpassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/refresh"
	"github.com/code-corhuila/multi-tour-security/internal/core/requestlink"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportdecision"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportemergency"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportrequest"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportsession"
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
		Tenants: tenants, Accounts: accounts, Registry: postgres.NewRegistry(pool), Held: accounts, Hasher: bcryptadapter.Hasher{}, Clock: time.Now,
		Verifications: links, Mailer: mailer, Random: rand.Reader,
	}
	askForLink := &requestlink.Service{Tenants: tenants, Accounts: accounts, Verifications: links, Mailer: mailer, Random: rand.Reader, Clock: time.Now}
	confirmEmail := &verifyemail.Service{Tenants: tenants, Accounts: accounts, Verifications: links, Hasher: bcryptadapter.Hasher{}, Clock: time.Now}
	recovery := &recoverpassword.Service{
		Tenants: tenants, Accounts: accounts, Codes: postgres.NewRecoveryCodes(pool), Mailer: mailer, Hasher: bcryptadapter.Hasher{},
		Key: cfg.recoveryKey, Random: rand.Reader, Clock: time.Now,
	}
	events := &outbox.Service{Store: postgres.NewOutbox(pool), Clock: time.Now, Policy: outbox.DefaultPolicy}
	background := httpadapter.NewBackground(logger, backgroundTimeout, 2*dbPoolSize)
	return httpadapter.New(httpadapter.NewVerifier(cfg.publicKey), logger,
		httpadapter.WithSignIn(signIn), httpadapter.WithRefresh(renewal), httpadapter.WithChangePassword(firstPassword),
		httpadapter.WithCreateAccount(newAccounts, tenants), httpadapter.WithCreateFirstAdministrator(newAccounts), httpadapter.WithCreateInternalUser(newAccounts), httpadapter.WithListInternalUsers(&listusers.Service{Directory: postgres.NewUserDirectory(pool)}),
		httpadapter.WithIssueTemporaryCredential(&issuetemp.Service{Store: postgres.NewTemporaryCredentials(pool), Hasher: bcryptadapter.Hasher{}, Clock: time.Now}),
		httpadapter.WithOptionalRoles(&optionalrole.Service{Store: postgres.NewOptionalRoles(pool), Clock: time.Now}),
		httpadapter.WithChangePermission(&changepermission.Service{Store: postgres.NewUserPermissions(pool), Clock: time.Now}),
		httpadapter.WithChangeUserStatus(&changestatus.Service{Store: postgres.NewUserStatus(pool), Clock: time.Now}),
		httpadapter.WithSupportRequests(&supportrequest.Service{Tenants: tenants, Store: postgres.NewSupportAccesses(pool), Clock: time.Now}),
		httpadapter.WithEmergencyAccess(&supportemergency.Service{Tenants: tenants, Store: postgres.NewSupportAccesses(pool), Clock: time.Now}),
		httpadapter.WithSupportDecisions(&supportdecision.Service{Store: postgres.NewSupportAccesses(pool), Clock: time.Now}),
		httpadapter.WithSupportSessions(&supportsession.Service{Store: postgres.NewSupportAccesses(pool), Signer: signer, Clock: time.Now}),
		httpadapter.WithOutbox(events),
		httpadapter.WithTenantEvents(&tenantevent.Service{Tenants: tenants}),
		httpadapter.WithLinkRequests(askForLink, background), httpadapter.WithEmailConfirmation(confirmEmail),
		httpadapter.WithPasswordRecovery(recovery, recovery, background)), background, nil
}
