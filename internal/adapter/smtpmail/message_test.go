package smtpmail

import (
	"encoding/hex"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

const token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE"

var sent = time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)

func verification() port.Mail {
	return port.Mail{To: "ana@example.com", TenantName: "Travesía Natural SAS", TenantIdentifier: "travesia", Token: token}
}

// parts reads a message as a receiver does: the headers and the decoded text of each alternative.
func parts(t *testing.T, raw []byte) (mail.Header, map[string]string) {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("not a message: %v\n%s", err, raw)
	}
	kind, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/alternative" {
		t.Fatalf("content type = %q %v, want multipart/alternative", msg.Header.Get("Content-Type"), err)
	}
	texts := map[string]string{}
	reader := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(part)
		texts[strings.SplitN(part.Header.Get("Content-Type"), ";", 2)[0]] = string(body)
	}
	return msg.Header, texts
}

func TestD_TheMessageComesFromTheTenantNameWithTheAddressOfThePlatform(t *testing.T) {
	raw, _ := buildMessage("no-reply@multitour.example", "https://app.multitour.example", verification(), sent, "id-1@multitour.example")
	header, _ := parts(t, raw)
	from, err := mail.ParseAddress(header.Get("From"))
	if err != nil || from.Address != "no-reply@multitour.example" || from.Name != "Travesía Natural SAS vía Multitour" {
		t.Fatalf("From = %q parsed as %+v %v, want the tenant name in the visible sender", header.Get("From"), from, err)
	}
	if to, err := mail.ParseAddress(header.Get("To")); err != nil || to.Address != "ana@example.com" {
		t.Fatalf("To = %q %v", header.Get("To"), err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(header.Get("Subject"))
	if err != nil || !strings.Contains(subject, "Verifica") {
		t.Fatalf("subject = %q %v, want Spanish", subject, err)
	}
	if date, err := header.Date(); err != nil || !date.Equal(sent) || header.Get("Message-Id") != "<id-1@multitour.example>" {
		t.Fatalf("Date/Message-Id = %v %v %q", date, err, header.Get("Message-Id"))
	}
}

func TestD_TheLinkHasItsValueAfterTheHashInBothAlternatives(t *testing.T) {
	raw, link := buildMessage("no-reply@multitour.example", "https://app.multitour.example", verification(), sent, "id-1@multitour.example")
	want := "https://app.multitour.example/t/travesia/verificar-correo#token=" + token
	if link != want {
		t.Fatalf("link = %q, want %q", link, want)
	}
	_, texts := parts(t, raw)
	for _, kind := range []string{"text/plain", "text/html"} {
		body, ok := texts[kind]
		if !ok || !strings.Contains(body, want) {
			t.Fatalf("%s alternative = %q, want the link", kind, body)
		}
		if !strings.Contains(body, "24 horas") || !strings.Contains(body, "Travesía Natural SAS") {
			t.Fatalf("%s alternative lacks the life of the link or the tenant: %q", kind, body)
		}
	}
}

func TestD_TheTokenIsOnlyInTheBodyNeverInAHeader(t *testing.T) {
	raw, _ := buildMessage("no-reply@multitour.example", "https://app.multitour.example", verification(), sent, "id-1@multitour.example")
	header, texts := parts(t, raw)
	for name, values := range header {
		for _, v := range values {
			if strings.Contains(v, token) {
				t.Fatalf("the header %s carries the token", name)
			}
		}
	}
	// the body is quoted-printable, which wraps long lines, so it is read as a receiver reads it
	if !strings.Contains(texts["text/plain"], token) || !strings.Contains(texts["text/html"], token) {
		t.Fatal("the token must be in both alternatives of the body")
	}
}

func TestD_ALineBreakInTheTenantNameCannotAddAHeaderOrARecipient(t *testing.T) {
	m := verification()
	m.TenantName = "Evil\r\nBcc: victim@example.com\r\n\r\nInjected"
	raw, _ := buildMessage("no-reply@multitour.example", "https://app.multitour.example", m, sent, "id-1@multitour.example")
	header, _ := parts(t, raw)
	if header.Get("Bcc") != "" || len(header["From"]) != 1 {
		t.Fatalf("the name added a header: Bcc=%q From=%v", header.Get("Bcc"), header["From"])
	}
	head := strings.SplitN(string(raw), "\r\n\r\n", 2)[0]
	if strings.Contains(head, "victim@example.com") && !strings.Contains(strings.ToLower(head), "=?utf-8?") {
		t.Fatalf("the name leaked into the headers in clear: %q", head)
	}
}

func TestD_TheBaseUrlLosesItsTrailingSlashAndTheIdentifierIsEscaped(t *testing.T) {
	m := verification()
	m.TenantIdentifier = "a/b?c"
	_, link := buildMessage("no-reply@multitour.example", "https://app.multitour.example/", m, sent, "id-1@multitour.example")
	if link != "https://app.multitour.example/t/a%2Fb%3Fc/verificar-correo#token="+token {
		t.Fatalf("link = %q", link)
	}
}

func TestD_TheBodiesEscapeWhatTheTenantNameCouldInjectIntoTheHtml(t *testing.T) {
	m := verification()
	m.TenantName = `<script>alert("x")</script> & Co`
	raw, _ := buildMessage("no-reply@multitour.example", "https://app.multitour.example", m, sent, "id-1@multitour.example")
	_, texts := parts(t, raw)
	if strings.Contains(texts["text/html"], "<script>") || !strings.Contains(texts["text/html"], "&lt;script&gt;") {
		t.Fatalf("the html alternative did not escape the name: %q", texts["text/html"])
	}
}

func TestD_TheBoundaryIsADigestOfTheMessageIdAndDiffersFromOneMessageToAnother(t *testing.T) {
	boundary := func(id string) string {
		raw, _ := buildMessage("no-reply@multitour.example", "https://app.multitour.example", verification(), sent, id)
		msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
		return params["boundary"]
	}
	a, b := boundary("id-1@multitour.example"), boundary("id-2@multitour.example")
	if written := "mt-" + hex.EncodeToString([]byte("id-1@multitour.example")[:8]); a == b || a == written {
		t.Fatalf("boundaries %q and %q: they must be a digest, not the first bytes of the id written in hexadecimal (%q)", a, b, written)
	}
}
