// Package smtpmail sends the e-mail that carries a credential straight over SMTP, with the standard library only
// (HU-SEC-003, plan D-04, D-11; HU-SEC-004, plan D-09). It is an adapter of port.Mailer and port.RecoveryMailer: nothing of
// it reaches the core.
package smtpmail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

const platform = "Multitour"

// buildMessage makes the message of a verification e-mail and the link inside it. from is the address of the platform, and
// baseURL is where the pages of the portal live. The link has its value after the hash, so a browser never sends it to a
// server: it is in no log of the gateway or of a service, and it is in the body only, never in a header.
func buildMessage(from, baseURL string, m port.Mail, at time.Time, messageID string) (raw []byte, link string) {
	link = strings.TrimRight(baseURL, "/") + "/t/" + url.PathEscape(m.TenantIdentifier) + "/verificar-correo#token=" + m.Token
	sender := senderName(m.TenantName)
	text := "Hola,\r\n\r\nTe registraste en " + sender + ". Para activar tu cuenta, abre este enlace y escribe tu contraseña:\r\n\r\n" +
		link + "\r\n\r\nEl enlace funciona una sola vez y vence en 24 horas.\r\nSi no creaste esta cuenta, ignora este mensaje.\r\n"
	page := "<p>Hola,</p><p>Te registraste en " + html.EscapeString(sender) + ". Para activar tu cuenta, abre este enlace y escribe tu contraseña:</p>" +
		`<p><a href="` + html.EscapeString(link) + `">` + html.EscapeString(link) + "</a></p>" +
		"<p>El enlace funciona una sola vez y vence en 24 horas.<br>Si no creaste esta cuenta, ignora este mensaje.</p>"
	return assemble(from, m.To, sender, "Verifica tu correo electrónico", text, page, at, messageID), link
}

// buildRecoveryMessage makes the message of a password recovery e-mail. It carries the code and no link: the person types it
// on the page they already have open, so there is nothing to follow and nothing to imitate (HU-SEC-004, plan D-09).
func buildRecoveryMessage(from string, m port.RecoveryMail, at time.Time, messageID string) []byte {
	sender := senderName(m.TenantName)
	text := "Hola,\r\n\r\nPediste recuperar el acceso a tu cuenta de " + sender + ". Tu código es:\r\n\r\n" + m.Code +
		"\r\n\r\nEscríbelo en la página de recuperación junto con tu nueva contraseña. El código funciona una sola vez y vence en 30 minutos.\r\n" +
		"Si no lo pediste, ignora este mensaje: tu contraseña no cambia.\r\n"
	page := "<p>Hola,</p><p>Pediste recuperar el acceso a tu cuenta de " + html.EscapeString(sender) + ". Tu código es:</p>" +
		"<p><strong>" + html.EscapeString(m.Code) + "</strong></p>" +
		"<p>Escríbelo en la página de recuperación junto con tu nueva contraseña. El código funciona una sola vez y vence en 30 minutos.<br>" +
		"Si no lo pediste, ignora este mensaje: tu contraseña no cambia.</p>"
	return assemble(from, m.To, sender, "Tu código para recuperar el acceso", text, page, at, messageID)
}

// senderName is the visible name of the sender: the tenant's, on the platform, or the platform's alone.
func senderName(tenantName string) string {
	name := clean(tenantName)
	if name == "" || name == platform {
		return platform
	}
	return name + " vía " + platform
}

// assemble writes a message of two alternatives, plain text and HTML, from the platform address with the sender as its
// visible name. The headers hold no secret: the body does.
func assemble(from, to, sender, subject, text, page string, at time.Time, messageID string) []byte {
	digest := sha256.Sum256([]byte(messageID))
	boundary := "mt-" + hex.EncodeToString(digest[:8])

	var b bytes.Buffer
	header := func(name, value string) { fmt.Fprintf(&b, "%s: %s\r\n", name, value) }
	header("From", (&mail.Address{Name: sender, Address: from}).String())
	header("To", (&mail.Address{Address: to}).String())
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", at.Format(time.RFC1123Z))
	header("Message-ID", "<"+messageID+">")
	header("MIME-Version", "1.0")
	header("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	for _, p := range []struct{ kind, body string }{{"text/plain", text}, {"text/html", page}} {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, p.kind)
		w := quotedprintable.NewWriter(&b)
		_, _ = w.Write([]byte(p.body))
		_ = w.Close()
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

// clean makes a name fit on one line: a control character, a line break above all, becomes a space.
func clean(s string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
}
