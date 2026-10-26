package httpadapter

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/verifyemail"
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
	slots   chan struct{}
}

// NewBackground makes a runner whose work lasts at most timeout and of which at most max run at once.
func NewBackground(logger *slog.Logger, timeout time.Duration, max int) *Background {
	return &Background{timeout: timeout, logger: logger, slots: make(chan struct{}, max)}
}

// Go runs work on a context that does not end with the request. When max works are running, the new one is dropped with a
// warning: the caller has been answered the same either way, and the person asks again. A panic of the work is logged by its
// type, never its value (which could quote an e-mail), and ends that work and nothing else.
func (b *Background) Go(trace string, work func(ctx context.Context)) {
	select {
	case b.slots <- struct{}{}:
	default:
		b.logger.Warn("background work dropped: too many at once", "traceId", trace)
		return
	}
	b.group.Add(1)
	go func() {
		defer func() { <-b.slots; b.group.Done() }()
		defer func() {
			if r := recover(); r != nil {
				b.logger.Error("background work panicked", "traceId", trace, "panicType", fmt.Sprintf("%T", r))
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
		defer cancel()
		work(ctx)
	}()
}

// Wait blocks until the work in flight ends or ctx ends. The shutdown calls it after the server has drained its requests,
// so no new work can start meanwhile.
func (b *Background) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() { b.group.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WithLinkRequests registers the public route that asks for a new link. A person who is waiting for a link has no token yet.
func WithLinkRequests(requester LinkRequester, background *Background) Option {
	return func(s *server) { s.linkRequester, s.background = requester, background }
}

type linkRequestBody struct {
	Email *string `json:"email"`
}

// askForLink answers 202 to every well-formed request before anything is looked up, and does the work afterwards: the
// time of the answer, its body and its status are the same whether the account exists, is pending, is verified or has
// already received three links, so the route tells nobody which e-mails have an account. Only a request that cannot be
// an e-mail is refused, which says nothing about any account; an identifier that cannot be a tenant is answered 202 and
// asked of nobody.
func (s *server) askForLink(w http.ResponseWriter, r *http.Request) {
	var body linkRequestBody
	if !readJSON(w, r, &body) {
		return
	}
	if body.Email == nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with an email")
		return
	}
	email := account.NormalizeEmail(*body.Email)
	if !account.ValidEmail(email) {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the email is not valid")
		return
	}
	if identifier := r.PathValue("identifier"); validIdentifier(identifier) {
		trace := traceID(r.Context())
		s.background.Go(trace, func(ctx context.Context) {
			if err := s.linkRequester.Request(ctx, identifier, email); err != nil {
				// only the type: the text of a driver error can quote the e-mail
				s.logger.ErrorContext(ctx, "asking for a new link failed", "traceId", trace, "errorType", fmt.Sprintf("%T", err))
			}
		})
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
}

// EmailConfirmer is what the route that confirms the e-mail needs from its use case.
type EmailConfirmer interface {
	Confirm(ctx context.Context, r verifyemail.Request) error
}

// WithEmailConfirmation registers the public route that confirms the e-mail with the link and the password.
func WithEmailConfirmation(confirmer EmailConfirmer) Option {
	return func(s *server) {}
}
