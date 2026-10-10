// Package session holds what the core knows of a session and of its renewal values (ADR-004 D5). It imports only
// the standard library: the store is the adapter's business.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// Life is how long a session lasts, however often it renews (the table checks it too).
const Life = 7 * 24 * time.Hour

// NewRefreshValue makes a renewal value of 256 random bits and its hash. The value goes to the person and is never
// stored; the hash is what the store keeps, so a copy of the database does not renew anything.
func NewRefreshValue() (value, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	value = base64.RawURLEncoding.EncodeToString(raw)
	return value, Hash(value), nil
}

// Hash is the SHA-256 of a value in lower-case hex, the shape the table checks.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
