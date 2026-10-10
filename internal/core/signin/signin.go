// Package signin is the use case of a person who proves who they are with an e-mail and a password inside the tenant
// of a link, or at the platform (ADR-004 D5). It imports only the standard library and the rest of the core.
package signin

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/session"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

var (
	// ErrRefused is every refusal, whatever the reason, so that nothing tells a wrong password from an unknown e-mail,
	// an account of another tenant, a blocked or inactive account or a tenant that is not open (RN-SEC-001-02).
	ErrRefused = errors.New("the credentials were not accepted")
	// ErrInvalidRequest is an e-mail or a password that cannot be one; it is told apart because it says nothing about
	// any account.
	ErrInvalidRequest = errors.New("the e-mail or the password is not valid")
)

const (
	tenantAdministrator   = "TENANT_ADMINISTRATOR"
	platformAdministrator = "PLATFORM_ADMINISTRATOR"
	maxEmail              = 254
	minEmail              = 3
	maxPassword           = 128
	maxCorrelationID      = 128
)

// Request is a sign-in. TenantIdentifier is the one of the link and is ignored at the platform.
type Request struct {
	TenantIdentifier string
	Email            string
	Password         string
	CorrelationID    string
}

// Tokens is the answer. RefreshToken is empty for a temporary credential and for a restricted access: neither opens a
// session, so neither can be renewed into a wider access.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
}

// Service holds the pieces of the use case; the composition root fills every one, and a missing one stops it.
type Service struct {
	Tenants  port.Tenants
	Accounts port.Accounts
	Sessions port.Sessions
	Hasher   port.Hasher
	Signer   port.TokenSigner
	// DummyHash is compared when there is no account, so that every sign-in costs one comparison (plan D-07).
	DummyHash string
	Clock     func() time.Time
}

// SignIn signs in inside the tenant of the link.
func (s *Service) SignIn(ctx context.Context, r Request) (Tokens, error) {
	return s.signIn(ctx, r, false)
}

// SignInPlatform signs in the Platform Administrator, whose account has no tenant.
func (s *Service) SignInPlatform(ctx context.Context, r Request) (Tokens, error) {
	return s.signIn(ctx, r, true)
}

func (s *Service) signIn(ctx context.Context, r Request, platform bool) (Tokens, error) {
	if s.Tenants == nil || s.Accounts == nil || s.Sessions == nil || s.Hasher == nil || s.Signer == nil || s.Clock == nil ||
		s.DummyHash == "" {
		return Tokens{}, errors.New("sign-in is not wired: every piece is needed, or the answers would tell the accounts apart")
	}
	email, ok := validate(r)
	if !ok {
		return Tokens{}, ErrInvalidRequest
	}
	now := s.Clock()

	tenantID, open, inactive := "", platform, false
	if !platform {
		c, found, err := s.Tenants.FindByIdentifier(ctx, r.TenantIdentifier)
		if err != nil {
			return Tokens{}, err
		}
		// a tenant that is unknown, pending or failed is answered like an account that does not exist
		if found && (c.Status == tenant.Active || c.Status == tenant.Inactive) {
			tenantID, open, inactive = c.TenantID, true, c.Status == tenant.Inactive
		}
	}
	var acct account.Account
	found := false
	if open {
		var err error
		if acct, found, err = s.Accounts.FindByEmail(ctx, tenantID, email); err != nil {
			return Tokens{}, err
		}
		// defence in depth: the store filters by tenant, and an account of another place is never trusted
		found = found && acct.TenantID == tenantID
	}
	hash := s.DummyHash
	if found {
		hash = acct.PasswordHash
	}
	matched := s.Hasher.Compare(hash, r.Password)
	if !found {
		return Tokens{}, ErrRefused
	}
	if !matched {
		if _, _, err := s.Accounts.RecordFailure(ctx, acct.ID, now, r.CorrelationID); err != nil {
			return Tokens{}, err
		}
		return Tokens{}, ErrRefused
	}
	if acct.CanAuthenticate(now) != nil {
		return Tokens{}, ErrRefused
	}
	roles, err := s.Accounts.RolesOf(ctx, acct.ID)
	if err != nil {
		return Tokens{}, err
	}
	// an account with no role would open nothing; the platform lets in only its Administrator and an inactive tenant
	// only its own
	if len(roles) == 0 || (platform && !slices.Contains(roles, platformAdministrator)) || (inactive && !slices.Contains(roles, tenantAdministrator)) {
		return Tokens{}, ErrRefused
	}
	if err := s.Accounts.RecordSuccess(ctx, acct.ID); err != nil {
		return Tokens{}, err
	}

	var claims token.Claims
	switch {
	case acct.UsesTemporaryCredential(now):
		claims = token.PasswordChange(acct, now)
	default:
		claims = token.Access(acct, roles, nil, inactive, now)
	}
	access, err := s.Signer.Sign(claims)
	if err != nil {
		return Tokens{}, err
	}
	out := Tokens{AccessToken: access, ExpiresIn: claims.ExpiresAt.Sub(claims.IssuedAt)}
	if claims.Access != "" {
		return out, nil
	}
	value, valueHash, err := session.NewRefreshValue()
	if err != nil {
		return Tokens{}, err
	}
	if _, err := s.Sessions.Open(ctx, acct.ID, valueHash, now); err != nil {
		return Tokens{}, err
	}
	out.RefreshToken = value
	return out, nil
}

// validate normalizes the e-mail and checks both fields. The e-mail is plain ASCII with no space or control character,
// which is all the service accepts as an address (the rule of 06-data is open, spec section 6).
func validate(r Request) (string, bool) {
	email := account.NormalizeEmail(r.Email)
	if len(email) < minEmail || len(email) > maxEmail {
		return "", false
	}
	for i := 0; i < len(email); i++ {
		if email[i] <= 0x20 || email[i] >= 0x7f {
			return "", false
		}
	}
	// the correlation id is written with a failure and with the event of a block: one that cannot be stored must be
	// refused for everyone, or the answer would tell which accounts exist
	if len(r.CorrelationID) < 1 || len(r.CorrelationID) > maxCorrelationID {
		return "", false
	}
	if at := strings.IndexByte(email, '@'); at < 1 || at == len(email)-1 {
		return "", false
	}
	// bcrypt reads 72 bytes at most: the password policy of HU-SEC-002 caps new passwords there, and a longer one
	// typed at sign-in is a valid request that simply does not match
	if n := utf8.RuneCountInString(r.Password); n < 1 || n > maxPassword {
		return "", false
	}
	return email, true
}
