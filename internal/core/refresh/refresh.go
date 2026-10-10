// Package refresh is the use case that renews a session with the value the person got at sign-in or at the last
// renewal (ADR-004 D5). It imports only the standard library and the rest of the core.
package refresh

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/session"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

const (
	platformAdministrator = "PLATFORM_ADMINISTRATOR"
	minValue              = 20
	maxValue              = 256
)

// Service holds the pieces of the use case; the composition root fills every one, and a missing one stops it.
type Service struct {
	Tenants  port.Tenants
	Accounts port.Accounts
	Sessions port.Sessions
	Signer   port.TokenSigner
	Clock    func() time.Time
}

// Renew consumes the value and gives a new pair. Whatever the reason a renewal cannot be made, the answer is
// signin.ErrRefused: an unknown value, an used one (its session is revoked by the store), a revoked or expired
// session, an account stopped, a tenant that is not active.
func (s *Service) Renew(ctx context.Context, value string) (signin.Tokens, error) {
	if s.Tenants == nil || s.Accounts == nil || s.Sessions == nil || s.Signer == nil || s.Clock == nil {
		return signin.Tokens{}, errors.New("renewal is not wired: every piece is needed")
	}
	if len(value) < minValue || len(value) > maxValue {
		return signin.Tokens{}, signin.ErrInvalidRequest
	}
	now := s.Clock()
	next, nextHash, err := session.NewRefreshValue()
	if err != nil {
		return signin.Tokens{}, err
	}
	// shortcut: the value is consumed here, before the account, the roles, the tenant and the signature are looked at,
	// because the account is only known after the rotation. A transient failure after it answers 500 with the old value
	// already used, and the retry of the client counts as a reuse and revokes the session: a forced sign-in, not a
	// breach. Upgrade by rotating in a transaction that this use case commits after the checks.
	renewed, err := s.Sessions.Rotate(ctx, session.Hash(value), nextHash, now)
	if errors.Is(err, port.ErrRefreshInvalid) || errors.Is(err, port.ErrRefreshReused) {
		return signin.Tokens{}, signin.ErrRefused
	}
	if err != nil {
		return signin.Tokens{}, err
	}

	acct, found, err := s.Accounts.FindByID(ctx, renewed.AccountID)
	if err != nil {
		return signin.Tokens{}, err
	}
	// a password reset to a temporary one must force the change: an old session does not keep full access
	if !found || acct.Status == account.Inactive || acct.UsesTemporaryCredential(now) {
		return signin.Tokens{}, signin.ErrRefused
	}
	roles, err := s.Accounts.RolesOf(ctx, acct.ID)
	if err != nil {
		return signin.Tokens{}, err
	}
	if len(roles) == 0 {
		return signin.Tokens{}, signin.ErrRefused
	}
	open, err := s.placeIsOpen(ctx, acct, roles)
	if err != nil {
		return signin.Tokens{}, err
	}
	if !open {
		return signin.Tokens{}, signin.ErrRefused
	}

	claims := token.Access(acct, roles, nil, false, now)
	access, err := s.Signer.Sign(claims)
	if err != nil {
		return signin.Tokens{}, err
	}
	return signin.Tokens{AccessToken: access, RefreshToken: next, ExpiresIn: claims.ExpiresAt.Sub(claims.IssuedAt)}, nil
}

// placeIsOpen: the platform account renews only as the Platform Administrator, and the account of a tenant only while
// the tenant is active. An inactive tenant ends the renewals: its Administrator signs in again for a restricted
// access, which is never renewed.
func (s *Service) placeIsOpen(ctx context.Context, acct account.Account, roles []string) (bool, error) {
	if acct.IsPlatform() {
		return slices.Contains(roles, platformAdministrator), nil
	}
	if slices.Contains(roles, platformAdministrator) {
		return false, nil // the platform role never mixes with a tenant (the same rule as the services apply)
	}
	c, found, err := s.Tenants.FindByID(ctx, acct.TenantID)
	if err != nil {
		return false, err
	}
	return found && c.IsActive(), nil
}
