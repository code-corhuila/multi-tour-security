// Package smtpmail sends the e-mail that carries a credential straight over SMTP, with the standard library only
// (HU-SEC-003, plan D-04, D-11). It is an adapter of port.Mailer: nothing of it reaches the core.
package smtpmail

import (
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// buildMessage makes the message of a verification e-mail and the link inside it. from is the address of the platform, and
// baseURL is where the pages of the portal live.
func buildMessage(from, baseURL string, m port.Mail, at time.Time, messageID string) (raw []byte, link string) {
	return nil, ""
}
