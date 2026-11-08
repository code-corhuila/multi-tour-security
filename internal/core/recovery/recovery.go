// Package recovery is the code that lets a person choose a new password: eight random digits sent to the registered e-mail
// and kept only as an HMAC (HU-SEC-004, plan D-01 and D-02). It imports only the standard library.
package recovery

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

const (
	// Life is how long a code works (PDR section 9, ADR-004 D10).
	Life = 30 * time.Minute
	// CodesPerWindow codes within Window is the most an account receives (ADR-004 D10).
	CodesPerWindow = 3
	Window         = time.Hour
	// MaxWrongTries is how many wrong tries retire a code (ADR-004 D10).
	MaxWrongTries = 5
	// MaxCause is the longest cause of a failed send that is recorded.
	MaxCause = 200
	// SendTimeout bounds the send and the record of its failure, which do not depend on the caller staying connected.
	SendTimeout = 8 * time.Second

	digits = 8
	// unbiasedLimit is the largest multiple of 10^8 that fits in 32 bits: a value at or over it is skipped, so every code
	// is equally likely.
	unbiasedLimit = 4_200_000_000
	modulus       = 100_000_000
	// attempts bounds the draws of one code: a value is skipped about one time in fifty, so sixteen skips in a row mean the
	// source is not random.
	attempts = 16
)

// Code is a new code: Raw goes to the person once, HMAC is what the store keeps.
type Code struct {
	Raw       string
	HMAC      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// New makes a code of eight digits from a random source, without bias; a failing or exhausted source makes no code.
func New(random io.Reader, key []byte, accountID string, now time.Time) (Code, error) {
	var b [4]byte
	for i := 0; i < attempts; i++ {
		if _, err := io.ReadFull(random, b[:]); err != nil {
			return Code{}, err
		}
		n := binary.BigEndian.Uint32(b[:])
		if n >= unbiasedLimit {
			continue
		}
		raw := fmt.Sprintf("%0*d", digits, n%modulus)
		return Code{Raw: raw, HMAC: HMAC(key, accountID, raw), CreatedAt: now, ExpiresAt: now.Add(Life)}, nil
	}
	return Code{}, errors.New("the random source gave no usable value")
}

// HMAC is the HMAC-SHA-256, in lower-case hexadecimal, of a code as the person sends it back, bound to its account so that
// the same digits sent to two accounts are two different values. With only 10^8 possible codes a plain hash could be
// reversed at once; the key is what a copy of the database does not have.
func HMAC(key []byte, accountID, raw string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(accountID))
	mac.Write([]byte{0})
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// Equal tells whether two HMACs are the same, in a time that does not depend on where they differ.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidShape tells whether a value can be a code: exactly eight ASCII digits.
func ValidShape(raw string) bool {
	if len(raw) != digits {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	return true
}

// Cause is the reason of a failed send as it is recorded: the code never appears in it and it fits MaxCause bytes.
func Cause(err error, raw string) string {
	if err == nil {
		return ""
	}
	cause := err.Error()
	if raw != "" {
		cause = strings.ReplaceAll(cause, raw, "[code]")
	}
	if len(cause) > MaxCause {
		cause = cause[:MaxCause]
		for !utf8.ValidString(cause) {
			cause = cause[:len(cause)-1]
		}
	}
	return cause
}

// Deliver sends the e-mail of a code. A failure is recorded on the code, without the code, and is returned only when even
// that could not be recorded; the account never changes (spec RN-SEC-006-10). The send happens after the code is stored, so it
// must not stop when the person closes the connection: it runs on a context that outlives the request and has its own timeout.
func Deliver(ctx context.Context, mailer port.RecoveryMailer, codes port.RecoveryCodes, now func() time.Time, accountID string, mail port.RecoveryMail, code Code) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), SendTimeout)
	defer cancel()
	if err := mailer.SendRecoveryCode(ctx, mail); err != nil {
		return codes.MarkSendFailed(ctx, accountID, code.HMAC, now(), Cause(err, code.Raw))
	}
	return nil
}
