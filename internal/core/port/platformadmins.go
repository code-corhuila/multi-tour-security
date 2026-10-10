package port

import (
	"context"
	"time"
)

// PlatformAdmins is where the first Platform Administrator is made.
type PlatformAdmins interface {
	// CreateFirst makes the account, its membership and its role only when no account without a tenant exists, in one
	// transaction that two runs at once cannot both pass. It says whether it made one.
	CreateFirst(ctx context.Context, email, hash string, temporaryUntil time.Time) (bool, error)
}
