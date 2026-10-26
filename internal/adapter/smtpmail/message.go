// Package smtpmail sends the e-mail that carries a credential straight over SMTP, with the standard library only
// (HU-SEC-003, plan D-04, D-11). It is an adapter of port.Mailer: nothing of it reaches the core.
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
	name := clean(m.TenantName)
	sender := name + " vía " + platform
	if name == "" || name == platform {
		sender = platform
	}
	boundary := "mt-" + hex.EncodeToString(sha256.New().Sum([]byte(messageID))[:8])

	var b bytes.Buffer
	header := func(name, value string) { fmt.Fprintf(&b, "%s: %s\r\n", name, value) }
	header("From", (&mail.Address{Name: sender, Address: from}).String())
	header("To", (&mail.Address{Address: m.To}).String())
	header("Subject", mime.QEncoding.Encode("utf-8", "Verifica tu correo electrónico"))
	header("Date", at.Format(time.RFC1123Z))
	header("Message-ID", "<"+messageID+">")
	header("MIME-Version", "1.0")
	header("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")

	text := "Hola,\r\n\r\nTe registraste en " + sender + ". Para activar tu cuenta, abre este enlace y escribe tu contraseña:\r\n\r\n" +
		link + "\r\n\r\nEl enlace funciona una sola vez y vence en 24 horas.\r\nSi no creaste esta cuenta, ignora este mensaje.\r\n"
	page := "<p>Hola,</p><p>Te registraste en " + html.EscapeString(sender) + ". Para activar tu cuenta, abre este enlace y escribe tu contraseña:</p>" +
		`<p><a href="` + html.EscapeString(link) + `">` + html.EscapeString(link) + "</a></p>" +
		"<p>El enlace funciona una sola vez y vence en 24 horas.<br>Si no creaste esta cuenta, ignora este mensaje.</p>"
	for _, p := range []struct{ kind, body string }{{"text/plain", text}, {"text/html", page}} {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, p.kind)
		w := quotedprintable.NewWriter(&b)
		_, _ = w.Write([]byte(p.body))
		_ = w.Close()
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), link
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
