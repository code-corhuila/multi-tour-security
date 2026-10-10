// Package jwtadapter signs the tokens of the core with the private key of the service, the only one that holds it
// (ADR-004 D5). The services validate them with the public half, with no call to this one.
package jwtadapter

import (
	"crypto/rsa"
	"errors"

	"github.com/code-corhuila/multi-tour-security/internal/core/token"
	"github.com/golang-jwt/jwt/v5"
)

// minKeyBits is the shortest key the service signs with (norm 5.3.7); the composition root checks it at start-up too.
const minKeyBits = 2048

// Signer signs with RS256 and nothing else.
type Signer struct {
	key *rsa.PrivateKey
}

// NewSigner takes the key that the composition root validated at start-up.
func NewSigner(key *rsa.PrivateKey) *Signer {
	return &Signer{key: key}
}

// Sign turns the claims into a compact token. The tenant and the access mark are written only when they exist, so a
// token of the platform has no tenantId and an ordinary one has no access.
func (s *Signer) Sign(c token.Claims) (string, error) {
	if s == nil || s.key == nil {
		return "", errors.New("the signer has no private key")
	}
	if s.key.N.BitLen() < minKeyBits {
		return "", errors.New("the private key is too short to sign")
	}
	if c.Subject == "" || c.Issuer == "" || !c.ExpiresAt.After(c.IssuedAt) {
		return "", errors.New("the claims are not those of a token: they need a subject, an issuer and a life")
	}
	body := jwt.MapClaims{
		"iss":         c.Issuer,
		"aud":         jwt.ClaimStrings{c.Audience},
		"sub":         c.Subject,
		"iat":         jwt.NewNumericDate(c.IssuedAt),
		"nbf":         jwt.NewNumericDate(c.NotBefore),
		"exp":         jwt.NewNumericDate(c.ExpiresAt),
		"roles":       c.Roles,
		"permissions": c.Permissions,
	}
	if c.TenantID != "" {
		body["tenantId"] = c.TenantID
	}
	if c.Access != "" {
		body["access"] = c.Access
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, body).SignedString(s.key)
}
