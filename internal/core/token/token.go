// Package token builds the claims of the tokens this service issues (ADR-004 D5). It signs nothing: the signer is
// an adapter, and the core imports only the standard library and the account.
package token

import (
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

const (
	// Issuer and Audience are what the services check when the operator names them (JWT_ISSUER, JWT_AUDIENCE).
	Issuer   = "multi-tour-security"
	Audience = "multi-tour"

	AccessLife         = 15 * time.Minute
	PasswordChangeLife = 10 * time.Minute
	// MaxExceptionalLife is the longest a support access lasts (PDR section 9).
	MaxExceptionalLife = 24 * time.Hour
	MinServiceLife     = time.Minute
	MaxServiceLife     = 90 * 24 * time.Hour

	// RestrictedAccess marks the Administrator of an inactive tenant; PasswordChangeAccess marks the token of a
	// temporary credential, which only serves the route that chooses a password.
	RestrictedAccess     = "restricted"
	PasswordChangeAccess = "password-change"
	// ExceptionalAccess marks the token of a support access of the Platform Administrator to one tenant (ADR-004 D5).
	ExceptionalAccess = "exceptional"
	// EmergencyAccess marks the token of an emergency access, which the Platform Administrator opens alone (HU-SEC-007 part B, ADR-004 D5).
	EmergencyAccess = "emergency"
)

// IsSupportAccess tells whether the mark is one of the two tokens of an access of the Platform Administrator to one tenant: the one that a
// Tenant Administrator authorized and the emergency one. Both carry a tenant, a scope and the id of their authorization.
func IsSupportAccess(access string) bool {
	return access == ExceptionalAccess || access == EmergencyAccess
}

// ErrServiceName is a name that the services would refuse as a subject.
var ErrServiceName = errors.New("a service name is 1 to 100 characters with no space at its ends and no control character")

// ErrServiceLife is a service token asked for a life under a minute or over 90 days.
var ErrServiceLife = errors.New("a service token lasts from one minute to 90 days")

// ErrExceptionalLife is the token of a support access that would end before it starts or after 24 hours.
var ErrExceptionalLife = errors.New("a support access token ends after it starts and within 24 hours")

// ErrExceptionalClaims is the token of a support access with no person, tenant, area or authorization.
var ErrExceptionalClaims = errors.New("a support access token needs a person, a tenant, an area and its authorization")

// Claims are the claims of an access token. TenantID is empty for the platform and for a service. Scope and AuthorizationID are the claims of
// the token of a support access (ADR-004 D5) and are empty in any other.
type Claims struct {
	Issuer          string
	Audience        string
	Subject         string
	TenantID        string
	Roles           []string
	Permissions     []string
	Access          string
	Scope           []string
	AuthorizationID string
	IssuedAt        time.Time
	NotBefore       time.Time
	ExpiresAt       time.Time
}

func claims(subject, tenantID string, roles, permissions []string, access string, now time.Time, life time.Duration) Claims {
	if roles == nil {
		roles = []string{}
	}
	if permissions == nil {
		permissions = []string{}
	}
	return Claims{
		Issuer: Issuer, Audience: Audience, Subject: subject, TenantID: tenantID, Roles: roles,
		Permissions: permissions, Access: access, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(life),
	}
}

// Access is the token of a person who signed in. The tenant is the one of the account and nothing else decides it.
func Access(a account.Account, roles, permissions []string, restricted bool, now time.Time) Claims {
	access := ""
	if restricted {
		access = RestrictedAccess
	}
	return claims(a.ID, a.TenantID, roles, permissions, access, now, AccessLife)
}

// PasswordChange is the token of a temporary credential: no role, so that no other service lets it in.
func PasswordChange(a account.Account, now time.Time) Claims {
	return claims(a.ID, a.TenantID, nil, nil, PasswordChangeAccess, now, PasswordChangeLife)
}

// Service is the token of a worker or a workflow: its name, the role SERVICE and no tenant.
func Service(name string, life time.Duration, now time.Time) (Claims, error) {
	// the same rules the services apply to a subject: they refuse the token otherwise, with a plain 401
	if name == "" || name != strings.TrimSpace(name) || len(name) > 100 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return Claims{}, ErrServiceName
	}
	if life < MinServiceLife || life > MaxServiceLife {
		return Claims{}, ErrServiceLife
	}
	return claims(name, "", []string{"SERVICE"}, nil, "", now, life), nil
}

// Exceptional is the token of a support access: the Platform Administrator for one tenant, the approved areas as the scope, the id of the
// authorization and an end equal to the end of the access, never later than 24 hours from now. It has no special permission and no renewal.
func Exceptional(platformAdministratorID, tenantID string, scope []string, authorizationID string, ends, now time.Time) (Claims, error) {
	return supportToken(ExceptionalAccess, platformAdministratorID, tenantID, scope, authorizationID, ends, now)
}

// Emergency is the token of an emergency access: the same claims and the same limits as the one of a support access, with its own mark so that a
// service can tell who authorized it (HU-SEC-007 part B). The scope may carry SENSITIVE.
func Emergency(platformAdministratorID, tenantID string, scope []string, authorizationID string, ends, now time.Time) (Claims, error) {
	return supportToken(EmergencyAccess, platformAdministratorID, tenantID, scope, authorizationID, ends, now)
}

func supportToken(access, platformAdministratorID, tenantID string, scope []string, authorizationID string, ends, now time.Time) (Claims, error) {
	if !plainText(platformAdministratorID) || !plainText(tenantID) || !plainText(authorizationID) || len(scope) == 0 {
		return Claims{}, ErrExceptionalClaims
	}
	for i, area := range scope {
		if !plainText(area) || slices.Contains(scope[:i], area) {
			return Claims{}, ErrExceptionalClaims
		}
	}
	if !ends.After(now) || ends.After(now.Add(MaxExceptionalLife)) {
		return Claims{}, ErrExceptionalLife
	}
	c := claims(platformAdministratorID, tenantID, []string{"PLATFORM_ADMINISTRATOR"}, nil, access, now, ends.Sub(now))
	c.Scope, c.AuthorizationID = append([]string{}, scope...), authorizationID
	return c, nil
}

// plainText is a value with something in it, no space at its ends and no control character: what the services read as a name or an id.
func plainText(s string) bool {
	return s != "" && s == strings.TrimSpace(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
