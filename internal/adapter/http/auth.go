package httpadapter

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenLeeway is the clock tolerance of ADR-004 D10.
const tokenLeeway = 30 * time.Second

var (
	errMissingSubject = errors.New("token has no subject")
	errMalformedClaim = errors.New("token has a claim of the wrong type")
)

// textClaim reads a claim that is text when it is there: absent or null is empty, any other type is not acceptable.
func textClaim(body jwt.MapClaims, name string) (string, bool) {
	raw, present := body[name]
	if !present || raw == nil {
		return "", true
	}
	text, isText := raw.(string)
	return text, isText
}

// Claims is what the rest of the service may know about the caller.
type Claims struct {
	Subject string
	// TenantID is empty for the platform and for a service; Access is the mark of a token that serves one purpose
	// only ("password-change", "restricted") and empty for an ordinary one.
	TenantID string
	Access   string
	// Roles are the roles of the token that are text; nil when the claim is absent.
	Roles []string
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
	body, _ := token.Claims.(jwt.MapClaims)
	// fail closed: a claim that is present with the wrong type is a token this service did not issue, and it is refused
	// instead of read as an absent one (a tenant or a mark erased by its type would widen who may enter)
	var ok bool
	if claims.TenantID, ok = textClaim(body, "tenantId"); !ok {
		return Claims{}, errMalformedClaim
	}
	if claims.Access, ok = textClaim(body, "access"); !ok {
		return Claims{}, errMalformedClaim
	}
	if raw, present := body["roles"]; present && raw != nil {
		list, isList := raw.([]any)
		if !isList {
			return Claims{}, errMalformedClaim
		}
		for _, role := range list {
			name, isText := role.(string)
			if !isText {
				return Claims{}, errMalformedClaim
			}
			claims.Roles = append(claims.Roles, name)
		}
	}
	return claims, nil
}
