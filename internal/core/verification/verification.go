// Package verification is the link that proves the owner of an e-mail: a random value sent to the person and kept only as
// its SHA-256 (HU-SEC-003, plan D-02). It imports only the standard library.
package verification

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

const (
	// Life is how long a link works (ADR-004 D10).
	Life = 24 * time.Hour
	// LinksPerWindow links within Window is the most an account receives (ADR-004 D10).
	LinksPerWindow = 3
	Window         = time.Hour

	randomBytes = 32
	// rawLength is 32 bytes in base64url without padding.
	rawLength = 43
	// MaxCause is the longest cause of a failed send that is recorded.
	MaxCause = 200
	// SendTimeout bounds the send and the record of its failure, which do not depend on the caller staying connected.
	SendTimeout = 15 * time.Second
)

// Link is a new link: Raw goes to the person once, Hash is what the store keeps.
type Link struct {
	Raw       string
	Hash      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// New makes a link from 32 random bytes read from random; fewer bytes, or a failing source, make no link.
func New(random io.Reader, now time.Time) (Link, error) {
	b := make([]byte, randomBytes)
	if _, err := io.ReadFull(random, b); err != nil {
		return Link{}, err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	return Link{Raw: raw, Hash: Hash(raw), CreatedAt: now, ExpiresAt: now.Add(Life)}, nil
}

// Hash is the SHA-256, in lower-case hexadecimal, of a link as the person sends it back.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ValidShape tells whether a value can be a link: 43 characters of the URL-safe alphabet.
func ValidShape(raw string) bool {
	if len(raw) != rawLength {
		return false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Cause is the reason of a failed send as it is recorded: the link never appears in it and it fits MaxCause bytes.
func Cause(err error, raw string) string {
	if err == nil {
		return ""
	}
	cause := err.Error()
	if raw != "" {
		cause = strings.ReplaceAll(cause, raw, "[link]")
	}
	if len(cause) > MaxCause {
		cause = cause[:MaxCause]
		for !utf8.ValidString(cause) {
			cause = cause[:len(cause)-1]
		}
	}
	return cause
}

// Deliver sends the e-mail of a link. A failure is recorded on the link, without the link, and is returned only when even
// that could not be recorded; the account never changes (spec RN-SEC-004-07). The send happens after the account or the link
// is stored, so it must not stop when the person closes the connection: it runs on a context that outlives the request
// and has its own timeout.
func Deliver(ctx context.Context, mailer port.Mailer, links port.Verifications, now func() time.Time, mail port.Mail, link Link) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), SendTimeout)
	defer cancel()
	if err := mailer.SendVerification(ctx, mail); err != nil {
		return links.MarkSendFailed(ctx, link.Hash, now(), Cause(err, link.Raw))
	}
	return nil
}
