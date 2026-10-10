package port

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrRefreshInvalid is every renewal that cannot work, whatever the reason: unknown, expired, revoked session, an
	// account revoked after the session opened or inactive. The caller answers one and the same 401.
	ErrRefreshInvalid = errors.New("the renewal value is not valid")
	// ErrRefreshReused is a value that was already consumed: a copy was probably stolen, and its session is revoked.
	ErrRefreshReused = errors.New("the renewal value was already used")
)

// Renewed says whose session a renewal belongs to.
type Renewed struct {
	AccountID string
	SessionID string
}

// Sessions keeps the sessions and the hashes of their renewal values.
type Sessions interface {
	// Open starts a session of Life with its first value, both or neither.
	Open(ctx context.Context, accountID, valueHash string, now time.Time) (sessionID string, err error)
	// Rotate consumes oldHash and stores newHash in one transaction. The second use of a value revokes its session,
	// and that revocation stands although the call returns ErrRefreshReused.
	Rotate(ctx context.Context, oldHash, newHash string, now time.Time) (Renewed, error)
	// RevokeAll makes the sessions opened up to the cutoff unable to renew and writes AccountSessionsRevoked with the
	// cutoff in the same transaction. A cutoff never moves backwards.
	RevokeAll(ctx context.Context, accountID string, cutoff time.Time, correlationID string) error
}
