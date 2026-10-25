// Package requestlink is the person who asks for a new verification link (HU-SEC-003). Its answer never tells whether the
// account exists, so it returns nothing but a refusal of the request itself.
package requestlink

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/verification"
)

// ErrInvalidRequest is an e-mail the service cannot even look up.
var ErrInvalidRequest = errors.New("the e-mail is not valid")

// ErrNotWired is a piece the composition root did not give.
var ErrNotWired = errors.New("request link is not wired: every piece is needed")

// Service holds the pieces of the use case; a missing one stops it.
type Service struct {
	Tenants       port.Tenants
	Accounts      port.Accounts
	Verifications port.Verifications
	Mailer        port.Mailer
	Random        io.Reader
	Clock         func() time.Time
}

// Request sends a new link when the rules allow it and says nothing of whether it did: the tenant must be active, the
// account must exist and be pending, and it must have received fewer than three links in the last hour (ADR-004 D10).
func (s *Service) Request(ctx context.Context, tenantIdentifier, email string) error {
	if s.Tenants == nil || s.Accounts == nil || s.Verifications == nil || s.Mailer == nil || s.Random == nil || s.Clock == nil {
		return ErrNotWired
	}
	email = account.NormalizeEmail(email)
	if !account.ValidEmail(email) {
		return ErrInvalidRequest
	}
	tn, found, err := s.Tenants.FindByIdentifier(ctx, tenantIdentifier)
	if err != nil || !found || !tn.IsActive() {
		return err
	}
	acct, found, err := s.Accounts.FindByEmail(ctx, tn.TenantID, email)
	if err != nil || !found || acct.TenantID != tn.TenantID || acct.Status != account.Pending {
		return err
	}
	now := s.Clock()
	link, err := verification.New(s.Random, now)
	if err != nil {
		return err
	}
	issued, err := s.Verifications.Issue(ctx, acct.ID, port.NewLink{TokenHash: link.Hash, ExpiresAt: link.ExpiresAt}, now,
		verification.LinksPerWindow, verification.Window)
	if err != nil || !issued {
		return err
	}
	// a failed send is recorded on the link and the person asks again: nothing else changes (spec RN-SEC-004-07)
	mail := port.Mail{To: email, TenantName: tn.DisplayName(), TenantIdentifier: tn.Identifier, Token: link.Raw}
	return verification.Deliver(ctx, s.Mailer, s.Verifications, s.Clock, mail, link)
}
