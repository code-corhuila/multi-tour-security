// Package bcryptadapter hashes and compares passwords with bcrypt at cost 12 (ADR-004 D5). The core knows it only
// through port.Hasher.
package bcryptadapter

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const (
	cost = 12
	// maxBytes is how much of a password bcrypt reads.
	maxBytes = 72
)

// Hasher compares a password with a stored hash.
type Hasher struct{}

// Compare says whether the password is the one the hash was made from. A password longer than bcrypt reads is never
// accepted for its first 72 bytes, and it still costs one comparison: the time must not tell it from another.
func (Hasher) Compare(hash, password string) bool {
	read := password
	if len(read) > maxBytes {
		read = read[:maxBytes]
	}
	matched := bcrypt.CompareHashAndPassword([]byte(hash), []byte(read)) == nil
	return matched && len(password) <= maxBytes
}

// Hash makes the hash to store for a password, so that Hasher satisfies port.Hasher.
func (Hasher) Hash(password string) (string, error) { return Hash(password) }

// Hash makes the hash to store for a password of 1 to 72 bytes.
func Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("a password cannot be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(hash), err
}

// NewDummyHash is the hash compared when there is no account, made at start-up from random bytes: it costs what a real
// one costs, matches nothing and is not a constant anyone can read in the source.
func NewDummyHash() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return Hash(base64.RawURLEncoding.EncodeToString(raw))
}
