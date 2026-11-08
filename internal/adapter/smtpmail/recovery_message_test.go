package smtpmail

import (
	"mime"
	"net/mail"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

const recoveryCode = "48213907"

func recovery() port.RecoveryMail {
	return port.RecoveryMail{To: "ana@example.com", TenantName: "Travesía Natural SAS", TenantIdentifier: "travesia", Code: recoveryCode}
}

func TestD_TheRecoveryMessageCarriesTheCodeAndItsLifeInBothAlternatives(t *testing.T) {
	raw := buildRecoveryMessage("no-reply@multitour.example", recovery(), sent, "id-1@multitour.example")
	header, texts := parts(t, raw)
	if len(texts) != 2 {
		t.Fatalf("alternatives = %d, want text and html", len(texts))
	}
	for kind, body := range texts {
		if !strings.Contains(body, recoveryCode) || !strings.Contains(body, "30 minutos") || !strings.Contains(body, "una sola vez") {
			t.Errorf("%s: the code, its 30 minutes and its single use must be said: %q", kind, body)
		}
		if !strings.Contains(strings.ToLower(body), "ignora") {
			t.Errorf("%s: a person who did not ask must be told to ignore it: %q", kind, body)
		}
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(header.Get("Subject"))
	if err != nil || subject != "Tu código para recuperar el acceso" || strings.Contains(subject, recoveryCode) {
		t.Fatalf("Subject = %q %v", subject, err)
	}
}

func TestD_TheRecoveryMessageComesFromTheTenantNameOrFromThePlatform(t *testing.T) {
	for _, c := range []struct{ name, want string }{
		{"Travesía Natural SAS", "Travesía Natural SAS vía Multitour"},
		{"", "Multitour"},
		{"Multitour", "Multitour"},
	} {
		m := recovery()
		m.TenantName = c.name
		header, _ := parts(t, buildRecoveryMessage("no-reply@multitour.example", m, sent, "id-1@multitour.example"))
		from, err := mail.ParseAddress(header.Get("From"))
		if err != nil || from.Address != "no-reply@multitour.example" || from.Name != c.want {
			t.Errorf("From = %q parsed as %+v %v, want %q", header.Get("From"), from, err, c.want)
		}
	}
}

func TestD_TheCodeIsOnlyInTheBodyNeverInAHeader(t *testing.T) {
	raw := string(buildRecoveryMessage("no-reply@multitour.example", recovery(), sent, "id-1@multitour.example"))
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	if strings.Contains(head, recoveryCode) {
		t.Fatalf("the code is in a header:\n%s", head)
	}
}

func TestD_ALineBreakInTheTenantNameCannotAddAHeaderToARecoveryMessage(t *testing.T) {
	m := recovery()
	m.TenantName = "Acme\r\nBcc: spy@example.com"
	header, _ := parts(t, buildRecoveryMessage("no-reply@multitour.example", m, sent, "id-1@multitour.example"))
	if header.Get("Bcc") != "" {
		t.Fatalf("a header was injected: %v", header)
	}
	from, err := mail.ParseAddress(header.Get("From"))
	if err != nil || strings.ContainsAny(from.Name, "\r\n") {
		t.Fatalf("the visible sender carries a line break: %q %v", from, err)
	}
}

func TestD_TheSenderNameIsOneLineWhateverTheTenantNameHolds(t *testing.T) {
	if got := senderName("Acme\r\nBcc: spy@example.com"); strings.ContainsAny(got, "\r\n") {
		t.Fatalf("senderName = %q", got)
	}
}

func TestD_TheRecoveryBodiesEscapeWhatTheTenantNameCouldInjectIntoTheHtml(t *testing.T) {
	m := recovery()
	m.TenantName = `<script>alert(1)</script>`
	_, texts := parts(t, buildRecoveryMessage("no-reply@multitour.example", m, sent, "id-1@multitour.example"))
	if strings.Contains(texts["text/html"], "<script>") {
		t.Fatalf("html = %q", texts["text/html"])
	}
}

func TestD_TheRecoveryMessageNamesNoLink(t *testing.T) {
	// a code is typed on a page the person already has open: a link in the e-mail would be one more thing to phish
	_, texts := parts(t, buildRecoveryMessage("no-reply@multitour.example", recovery(), sent, "id-1@multitour.example"))
	for kind, body := range texts {
		if strings.Contains(body, "http://") || strings.Contains(body, "https://") || strings.Contains(body, "href=") || strings.Contains(body, "#token") {
			t.Errorf("%s holds a link: %q", kind, body)
		}
	}
}
