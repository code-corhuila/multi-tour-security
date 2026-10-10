package port

import "github.com/code-corhuila/multi-tour-security/internal/core/token"

// Hasher compares a password with the hash that was stored for it. The algorithm and its cost are the adapter's.
type Hasher interface {
	Compare(hash, password string) bool
}

// TokenSigner turns the claims of an access token into the compact token the services check.
type TokenSigner interface {
	Sign(c token.Claims) (string, error)
}
