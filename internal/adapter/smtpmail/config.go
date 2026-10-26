package smtpmail

import (
	"crypto/tls"
	"errors"
)

// Config is what the composition root reads from the environment (SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD,
// SMTP_FROM, SMTP_REQUIRE_TLS, PUBLIC_BASE_URL). TLSConfig lets a test trust its own certificate; it is nil in production.
type Config struct {
	Host          string
	Port          int
	User          string
	Password      string
	From          string
	RequireTLS    bool
	PublicBaseURL string
	TLSConfig     *tls.Config
}

// Mailer sends the verification e-mail.
type Mailer struct {
	c Config
}

func New(c Config) (*Mailer, error) { return nil, errors.New("not implemented") }
