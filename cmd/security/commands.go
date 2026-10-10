package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	bcryptadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/bcrypt"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/bootstrap"
)

// maxConsoleLine is far above any password the policy accepts (72 bytes): a longer line is not read to the end.
const maxConsoleLine = 1024

// execute runs a one-shot command of the service, in the tooling profile, and not the server. What a command prints
// never holds a password or a key.
func execute(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout io.Writer) error {
	switch args[0] {
	case "bootstrap-platform-admin":
		return bootstrapPlatformAdmin(ctx, getenv, stdin, stdout)
	default:
		// the argument is not echoed: someone may have typed a secret where a command goes
		return errors.New("unknown command; the commands are: bootstrap-platform-admin")
	}
}

// bootstrapPlatformAdmin makes the first Platform Administrator (plan D-08): the e-mail comes from the environment, the
// temporary password from the first line of the console, and only its hash is stored. Run again, it does nothing.
func bootstrapPlatformAdmin(ctx context.Context, getenv func(string) string, stdin io.Reader, stdout io.Writer) error {
	email, databaseURL := getenv("PLATFORM_ADMIN_EMAIL"), getenv("DATABASE_URL")
	switch {
	case email == "":
		return errors.New("PLATFORM_ADMIN_EMAIL is required")
	case databaseURL == "":
		return errors.New("DATABASE_URL is required")
	}
	// shortcut: only the scheme is checked. The server also demands the password of security_app (checkDatabaseURL); the
	// command does not, because the CI runs it as the administrator of a throwaway instance. In the tooling profile the
	// variable is the one of security_app. Upgrade when the profile has an integration test of its own.
	if parsed, err := url.Parse(databaseURL); err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		return errors.New("DATABASE_URL must be a postgres URL")
	}
	line, err := bufio.NewReader(io.LimitReader(stdin, maxConsoleLine)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("the temporary password could not be read from the console")
	}
	temporary := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r") // one line end, and nothing of the password
	if temporary == "" {
		return errors.New("the temporary password is read from the first line of the console, and it was empty")
	}

	pool, err := postgres.Open(ctx, databaseURL, postgres.Limits{MaxConns: 2, ConnectTimeout: dbConnectionWait, StatementTimeout: dbStatementTimeout})
	if err != nil {
		return err
	}
	defer pool.Close()
	service := &bootstrap.Service{Admins: postgres.NewPlatformAdmins(pool), Hasher: bcryptadapter.Hasher{}, Clock: time.Now}
	made, err := service.CreateFirst(ctx, email, temporary)
	if err != nil {
		return err
	}
	if !made {
		_, err = fmt.Fprintln(stdout, "a platform administrator already exists; nothing was done")
		return err
	}
	_, err = fmt.Fprintf(stdout, "platform administrator created: %s\nthe temporary password is valid for 72 hours and only serves to choose another one at the platform sign-in\n",
		account.NormalizeEmail(email))
	return err
}
