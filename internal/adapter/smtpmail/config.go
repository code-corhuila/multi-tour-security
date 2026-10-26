package smtpmail

import (
	"crypto/tls"
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strings"
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

// New refuses a configuration that could never send, or that would send the link in clear to a server across the internet,
// when the service starts and not at the first customer. Plain SMTP is for the local machine and for a host of the network
// of the composition (a name without dots, such as mailpit); a provider needs SMTP_REQUIRE_TLS.
func New(c Config) (*Mailer, error) {
	switch {
	case c.Host == "":
		return nil, errors.New("smtp: the host is required")
	case c.Port < 1 || c.Port > 65535:
		return nil, errors.New("smtp: the port must be between 1 and 65535")
	case (c.User == "") != (c.Password == ""):
		return nil, errors.New("smtp: the user and the password go together")
	case !c.RequireTLS && !localHost(c.Host):
		return nil, errors.New("smtp: a host outside the local machine and the composition needs SMTP_REQUIRE_TLS")
	}
	if a, err := mail.ParseAddress(c.From); err != nil || a.Address != c.From {
		return nil, errors.New("smtp: the sender must be one plain e-mail address")
	}
	u, err := url.Parse(c.PublicBaseURL)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
		return nil, errors.New("smtp: the public base url must be an absolute http or https url")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil:
		return nil, errors.New("smtp: the public base url has no query, fragment or credentials, or the link would break")
	case c.RequireTLS && u.Scheme != "https":
		return nil, errors.New("smtp: the link must travel over https when TLS is required")
	}
	return &Mailer{c: c}, nil
}

func localHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost" || !strings.Contains(host, ".")
}
