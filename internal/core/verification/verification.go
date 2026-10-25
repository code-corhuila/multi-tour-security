// Package verification is the link that proves the owner of an e-mail: a random value sent to the person and kept only as
// its SHA-256 (HU-SEC-003, plan D-02). It imports only the standard library.
package verification

import (
	"errors"
	"io"
	"time"
)

const (
	// Life is how long a link works (ADR-004 D10).
	Life = 24 * time.Hour
	// LinksPerWindow links within Window is the most an account receives (ADR-004 D10).
	LinksPerWindow = 3
	Window         = time.Hour
)

// Link is a new link: Raw goes to the person once, Hash is what the store keeps.
type Link struct {
	Raw       string
	Hash      string
	ExpiresAt time.Time
}

// New makes a link from 32 random bytes read from random.
func New(random io.Reader, now time.Time) (Link, error) { return Link{}, errors.New("not implemented") }

// Hash is the SHA-256, in lower-case hexadecimal, of a link as the person sends it back.
func Hash(raw string) string { return "" }

// ValidShape tells whether a value can be a link: 43 characters of the URL-safe alphabet.
func ValidShape(raw string) bool { return false }
