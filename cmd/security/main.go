// Command security is the composition root of the security microservice: the only place that
// wires adapters to the core and fixes the runtime limits.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
)

// Runtime limits of Annex C, with the values of ADR-004 D10. Declaring them here makes each one a
// decision: a Go default left unset is not.
const (
	readHeaderTimeout = 5 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
	shutdownTimeout   = 20 * time.Second

	// Applied by postgres.Open.
	dbPoolSize         = 10
	dbConnectionWait   = 5 * time.Second
	dbStatementTimeout = 5 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("security stopped", "reason", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	if len(os.Args) > 1 {
		// a command of the tooling profile, not the server
		return execute(context.Background(), os.Args[1:], os.Getenv, os.Stdin, os.Stdout)
	}
	cfg, err := loadConfig(os.Getenv, os.ReadFile)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", ":"+cfg.port)
	if err != nil {
		return fmt.Errorf("cannot listen on port %s", cfg.port)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// After the first signal the default behavior returns, so a second one ends the process.
	go func() { <-ctx.Done(); stop() }()

	pool, err := postgres.Open(ctx, cfg.databaseURL, postgres.Limits{
		MaxConns: dbPoolSize, ConnectTimeout: dbConnectionWait, StatementTimeout: dbStatementTimeout,
	})
	if err != nil {
		return err
	}
	defer pool.Close()
	handler, err := buildHandler(pool, cfg, logger)
	if err != nil {
		return err
	}
	return serve(ctx, listener, handler, logger)
}

// serve answers until ctx ends, then drains the requests in flight within shutdownTimeout.
func serve(ctx context.Context, listener net.Listener, handler http.Handler, logger *slog.Logger) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	failed := make(chan error, 1)
	go func() { failed <- server.Serve(listener) }()
	logger.Info("security listening", "address", listener.Addr().String())

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close() // the drain ran out of time: cut what is still open
		return err
	}
	if err := <-failed; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
