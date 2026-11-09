// Package supportsession is the use case where the Platform Administrator takes the token of a support access that a Tenant Administrator
// approved, and closes the access before its time (HU-SEC-007 part A, security spec 009: RN-SEC-009-05, -06). It imports only the standard
// library and the rest of the core.
package supportsession

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// ErrInvalid and FieldError are those every use case shares.
var ErrInvalid = validate.ErrInvalid

type FieldError = validate.FieldError

// ErrNotFound is an access that does not exist or that another administrator asked for: from here it is the same answer.
var ErrNotFound = errors.New("the support access does not exist")

var errNotWired = errors.New("support sessions are not wired: every piece is needed")

// TokenCommand is one request for the token. The actor is the Platform Administrator of the credential, never of the body.
type TokenCommand struct {
	ActorID       string
	ID            string
	CorrelationID string
}

// CloseCommand is one early closing, with its reason.
type CloseCommand struct {
	ActorID       string
	ID            string
	Reason        string
	CorrelationID string
}

// Token is what the Platform Administrator gets: the token, until when it works and what it reaches.
type Token struct {
	AccessToken     string
	ExpiresAt       time.Time
	ExpiresIn       time.Duration
	Scope           []string
	AuthorizationID string
}

// Service holds the pieces of the use case; the composition root fills every one.
type Service struct {
	Store  port.SupportSessions
	Signer port.TokenSigner
	Clock  func() time.Time
}

// Token opens the access the first time it is asked and signs a token that ends when the access ends. Only while the access is approved, not over
// and the caller's; the opening and the signing are separate steps, so a failure to sign after the opening leaves the access open and a retry gives
// the token without writing the fact twice.
func (s *Service) Token(ctx context.Context, c TokenCommand) (Token, error) {
	if s.Store == nil || s.Signer == nil || s.Clock == nil {
		return Token{}, errNotWired
	}
	if err := check(c.ActorID, c.CorrelationID); err != nil {
		return Token{}, err
	}
	now := s.Clock().Truncate(time.Microsecond)
	access, err := s.find(ctx, c.ActorID, c.ID, now)
	if err != nil {
		return Token{}, err
	}
	if err := access.CanTakeToken(now); err != nil {
		return Token{}, err
	}
	opened, ok, err := s.Store.Open(ctx, c.ActorID, c.ID, now, c.CorrelationID)
	if err != nil {
		return Token{}, err
	}
	if !ok {
		return Token{}, supportaccess.ErrInvalidTransition
	}
	// the access is read again after it opened: a closing or the end of its hours between the two leaves it without a token
	if err := opened.CanTakeToken(now); err != nil {
		return Token{}, err
	}
	claims, err := token.Exceptional(opened.RequestedBy, opened.TenantID, opened.Scope(), opened.ID, opened.ExpiresAt, now)
	if err != nil {
		return Token{}, err
	}
	signed, err := s.Signer.Sign(claims)
	if err != nil {
		return Token{}, err
	}
	return Token{AccessToken: signed, ExpiresAt: opened.ExpiresAt, ExpiresIn: opened.ExpiresAt.Sub(now), Scope: opened.Scope(), AuthorizationID: opened.ID}, nil
}

// Close ends an approved access before its time. In one store call the sessions of the Platform Administrator are cut and the facts are written.
func (s *Service) Close(ctx context.Context, c CloseCommand) (supportaccess.Access, error) {
	if s.Store == nil || s.Clock == nil {
		return supportaccess.Access{}, errNotWired
	}
	if err := check(c.ActorID, c.CorrelationID); err != nil {
		return supportaccess.Access{}, err
	}
	reason := strings.TrimSpace(c.Reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > supportaccess.MaxText {
		return supportaccess.Access{}, &FieldError{Field: "reason"}
	}
	now := s.Clock().Truncate(time.Microsecond)
	access, err := s.find(ctx, c.ActorID, c.ID, now)
	if err != nil {
		return supportaccess.Access{}, err
	}
	closed, err := access.Close(reason, now)
	if err != nil {
		return supportaccess.Access{}, err
	}
	stored, err := s.Store.Close(ctx, closed, c.CorrelationID)
	if err != nil {
		return supportaccess.Access{}, err
	}
	if !stored {
		return supportaccess.Access{}, supportaccess.ErrInvalidTransition
	}
	return closed, nil
}

// find marks as expired what ran out of the caller's accesses, then reads the one asked for; another administrator's is the same as none.
func (s *Service) find(ctx context.Context, actor, id string, now time.Time) (supportaccess.Access, error) {
	if !validate.UUID(id) {
		return supportaccess.Access{}, ErrNotFound
	}
	if err := s.Store.ExpireApproved(ctx, actor, "", now); err != nil {
		return supportaccess.Access{}, err
	}
	access, found, err := s.Store.FindOwn(ctx, actor, id)
	if err != nil {
		return supportaccess.Access{}, err
	}
	if !found {
		return supportaccess.Access{}, ErrNotFound
	}
	return access, nil
}

func check(actor, correlationID string) error {
	switch {
	case !validate.UUID(actor):
		return &FieldError{Field: "actorId"}
	case !validate.CorrelationID(correlationID):
		return &FieldError{Field: "correlationId"}
	}
	return nil
}
