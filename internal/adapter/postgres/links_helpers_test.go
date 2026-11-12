package postgres_test

import (
	"fmt"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// linkN is a link as the store keeps it: a distinct 64-character hash, created at the given instant and valid 24 hours.
func linkN(n int, at time.Time) port.NewLink {
	return port.NewLink{TokenHash: fmt.Sprintf("%064x", n), CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour)}
}
