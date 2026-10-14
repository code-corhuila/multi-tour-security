package port

import "github.com/code-corhuila/multi-tour-security/internal/core/token"

// Hasher makes and compares the hashes of passwords. The algorithm and its cost are the adapter's.
type Hasher interface {
	Compare(hash, password string) bool
	// Hash makes the hash to store for a password; it is the only thing that is ever stored of it.
	Hash(password string) (string, error)
}

// TokenSigner turns the claims of an access token into the compact token the services check.
type TokenSigner interface {
	Sign(c token.Claims) (string, error)
}
