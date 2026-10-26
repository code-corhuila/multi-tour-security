package smtpmail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

var _ port.Mailer = (*Mailer)(nil)

// defaultTimeout bounds an exchange, whatever longer deadline its caller has.
const defaultTimeout = 30 * time.Second

// Error is a failed delivery: the code of the server when it gave one, and the reason without what must not be recorded.
// Only the cause of a cancelled or expired caller is reachable with errors.Is; the error of the server is not, because it
// quotes the address of the person.
type Error struct {
	Code  int
	Text  string
	temp  bool
	cause error
}

func (e *Error) Error() string { return "smtp: " + e.Text }
func (e *Error) Unwrap() error { return e.cause }

// Temporary tells a failure that a later try may fix (4xx, network, a caller that gave up) from one that it will not (5xx).
func (e *Error) Temporary() bool { return e.temp }

// SendVerification delivers the e-mail, or says why not. The error never holds the link, the address of the person or the
// password: it is recorded and logged.
func (m *Mailer) SendVerification(ctx context.Context, mm port.Mail) error {
	if !plainAddress(mm.To) {
		return &Error{Text: "the recipient is not one e-mail address"}
	}
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return &Error{Text: "no randomness for the message id", temp: true}
	}
	domain := m.c.From[strings.LastIndexByte(m.c.From, '@')+1:]
	raw, _ := buildMessage(m.c.From, m.c.PublicBaseURL, mm, time.Now().UTC(), hex.EncodeToString(id)+"@"+domain)
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	if err := m.deliver(ctx, mm.To, raw); err != nil {
		return m.fail(ctx, err, mm)
	}
	return nil
}

// plainAddress tells one address with nothing else in it: the recipient goes to the server as RCPT TO:<address>, so a
// bracket, a comma, a quote or a line break would be read by the server as something other than the address.
func plainAddress(to string) bool {
	if a, err := mail.ParseAddress(to); err != nil || a.Address != to {
		return false
	}
	return !strings.ContainsAny(to, "<>,;\"\\ \r\n\t")
}

func (m *Mailer) deliver(ctx context.Context, to string, raw []byte) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(m.c.Host, strconv.Itoa(m.c.Port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline() // always set: SendVerification bounds the exchange
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
	// the server accepted the message: if it fails to say goodbye the e-mail is sent all the same, and reporting a failure
	// would record one and send a second e-mail when the person asks again
	_ = c.Quit()
	return nil
}

// fail turns what the exchange returned into an Error that keeps the code and the reason and drops the link, the address of
// the person and the password, whatever their case, longest first so that a secret inside another is not left in pieces.
func (m *Mailer) fail(ctx context.Context, err error, mm port.Mail) error {
	e := &Error{Text: redact(err.Error(), mm.Token, mm.To, m.c.Password), temp: true}
	var protocol *textproto.Error
	if errors.As(err, &protocol) {
		e.Code, e.temp = protocol.Code, protocol.Code >= 400 && protocol.Code < 500
	}
	if ctx.Err() != nil {
		e.cause = ctx.Err()
	}
	return e
}

func redact(text string, token, to, password string) string {
	secrets := []struct{ value, label string }{{token, "[link]"}, {to, "[recipient]"}, {password, "[password]"}}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i].value) > len(secrets[j].value) })
	for _, s := range secrets {
		if s.value == "" {
			continue
		}
		text = replaceFold(text, s.value, s.label)
	}
	return text
}

// replaceFold replaces every occurrence of old, whatever its case; the addresses and the tokens it is used for are ASCII.
func replaceFold(text, old, label string) string {
	lower, needle := strings.ToLower(text), strings.ToLower(old)
	if len(lower) != len(text) {
		return strings.ReplaceAll(text, old, label)
	}
	var b strings.Builder
	for {
		i := strings.Index(lower, needle)
		if i < 0 {
			b.WriteString(text)
			return b.String()
		}
		b.WriteString(text[:i])
		b.WriteString(label)
		text, lower = text[i+len(old):], lower[i+len(old):]
	}
}
