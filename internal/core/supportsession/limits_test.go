package supportsession_test

import (
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// PDR section 9: an access lasts at most 24 hours. The aggregate counts them in hours and the token in a duration; the two must say the same
// (pillar review of HU-SEC-007, finding on the number written twice).
func TestD_TheLimitOfTheAccessAndTheLimitOfItsTokenAreTheSame24Hours(t *testing.T) {
	if got := time.Duration(supportaccess.MaxHours) * time.Hour; got != token.MaxExceptionalLife {
		t.Fatalf("an access lasts %v and its token %v: one of the two moved", got, token.MaxExceptionalLife)
	}
}
