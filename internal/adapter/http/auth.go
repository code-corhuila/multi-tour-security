package httpadapter

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenLeeway is the clock tolerance of ADR-004 D10.
const tokenLeeway = 30 * time.Second

var errMissingSubject = errors.New("token has no subject")

// Claims is what the rest of the service may know about the caller.
type Claims struct {
	Subject string
	// TenantID is empty for the platform and for a service; Access is the mark of a token that serves one purpose
	// only ("password-change", "restricted") and empty for an ordinary one.
	TenantID string
	Access   string
}

// Verifier validates the access tokens of this service with the public key only: no service
// owns the private key outside the signer (ADR-004 D5).
type Verifier struct {
	key *rsa.PublicKey
}

// NewVerifier expects a non-nil key; the composition root validates it at start-up.
func NewVerifier(key *rsa.PublicKey) *Verifier {
	return &Verifier{key: key}
}

// Verify accepts exactly RS256 and requires exp and sub; every other algorithm, `none` included, is
// refused before the signature is looked at.
func (v *Verifier) Verify(raw string) (Claims, error) {
	token, err := jwt.Parse(raw,
		func(*jwt.Token) (any, error) { return v.key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(tokenLeeway),
	)
	if err != nil {
		return Claims{}, err
	}
	subject, err := token.Claims.GetSubject()
	if err != nil || subject == "" {
		return Claims{}, errMissingSubject
	}
	claims := Claims{Subject: subject}
	if body, ok := token.Claims.(jwt.MapClaims); ok {
		claims.TenantID, _ = body["tenantId"].(string)
		claims.Access, _ = body["access"].(string)
	}
	return claims, nil
}
