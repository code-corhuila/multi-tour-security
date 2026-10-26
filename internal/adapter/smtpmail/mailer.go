package smtpmail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

var _ port.Mailer = (*Mailer)(nil)

// defaultTimeout bounds an exchange whose caller set no deadline.
const defaultTimeout = 30 * time.Second

// SendVerification delivers the e-mail, or says why not. The error never holds the link, the address of the person or the
// password: it is recorded and logged.
func (m *Mailer) SendVerification(ctx context.Context, mm port.Mail) error {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return errors.New("smtp: no randomness for the message id")
	}
	domain := m.c.From[strings.LastIndexByte(m.c.From, '@')+1:]
	raw, _ := buildMessage(m.c.From, m.c.PublicBaseURL, mm, time.Now().UTC(), hex.EncodeToString(id)+"@"+domain)
	if err := m.deliver(ctx, mm.To, raw); err != nil {
		return redact(err, mm, m.c.Password)
	}
	return nil
}

func (m *Mailer) deliver(ctx context.Context, to string, raw []byte) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(m.c.Host, strconv.Itoa(m.c.Port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(defaultTimeout)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })() // a cancelled caller does not wait for the server

	c, err := smtp.NewClient(conn, m.c.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	if offered, _ := c.Extension("STARTTLS"); offered {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if m.c.TLSConfig != nil {
			config = m.c.TLSConfig.Clone()
		}
		if config.ServerName == "" {
			config.ServerName = m.c.Host
		}
		if err := c.StartTLS(config); err != nil {
			return err
		}
	} else if m.c.RequireTLS {
		// nothing else is said to a server that cannot protect the link, not even the credentials
		return errors.New("the server does not offer STARTTLS and TLS is required")
	}
	if m.c.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.c.User, m.c.Password, m.c.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.c.From); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// redact keeps the code and the reason of a failure and drops what must not be recorded: the link, the address of the person
// (a server quotes it in its refusal) and the password.
func redact(err error, m port.Mail, password string) error {
	text := err.Error()
	for secret, label := range map[string]string{m.Token: "[link]", m.To: "[recipient]", password: "[password]"} {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, label)
		}
	}
	return errors.New("smtp: " + text)
}
