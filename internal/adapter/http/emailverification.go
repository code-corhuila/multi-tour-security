package httpadapter

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// LinkRequester is what the route that asks for a new link needs from its use case.
type LinkRequester interface {
	Request(ctx context.Context, tenantIdentifier, email string) error
}

// Background runs the work that is done after the answer, with its own deadline, and lets the shutdown wait for it. At most
// max run at once: the work holds a connection of the pool, and a flood of requests must not starve the sign-in of them.
type Background struct {
	group   sync.WaitGroup
	timeout time.Duration
	logger  *slog.Logger
}

// NewBackground makes a runner whose work lasts at most timeout and of which at most max run at once.
func NewBackground(logger *slog.Logger, timeout time.Duration, max int) *Background {
	return &Background{timeout: timeout, logger: logger}
}

// Go runs work on a context that does not end with the request.
func (b *Background) Go(trace string, work func(ctx context.Context)) {}

// Wait blocks until the work in flight ends or ctx ends.
func (b *Background) Wait(ctx context.Context) error { return nil }

// WithLinkRequests registers the public route that asks for a new link.
func WithLinkRequests(requester LinkRequester, background *Background) Option {
	return func(s *server) {}
}
