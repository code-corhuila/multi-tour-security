package smtpmail_test

import (
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/smtpmail"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

const recoveryCode = "48213907"

var _ port.RecoveryMailer = (*smtpmail.Mailer)(nil)

func recoveryMail() port.RecoveryMail {
	return port.RecoveryMail{To: "ana@example.com", TenantName: "Travesía Natural SAS", TenantIdentifier: "travesia", Code: recoveryCode}
}

func TestI_TheRecoveryCodeReachesTheAddressOverPlainSmtpInDevelopment(t *testing.T) {
	s := startServer(t, &fakeServer{})
	if err := mustMailer(t, config(s)).SendRecoveryCode(ctx, recoveryMail()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.took()
	if len(got) != 1 || !strings.Contains(got[0].from, "no-reply@multitour.example") || !strings.Contains(got[0].to, "ana@example.com") {
		t.Fatalf("deliveries = %+v", got)
	}
	decoded, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(got[0].data)))
	if !strings.Contains(got[0].data, "Subject:") || !strings.Contains(string(decoded), recoveryCode) {
		t.Fatalf("data = %q", got[0].data)
	}
}

func TestI_ARefusedRecipientOfARecoveryCodeQuotesNeitherTheAddressNorTheCode(t *testing.T) {
	s := startServer(t, &fakeServer{rejectRecipient: true})
	err := mustMailer(t, config(s)).SendRecoveryCode(ctx, recoveryMail())
	if err == nil {
		t.Fatal("a refused recipient was a success")
	}
	if strings.Contains(err.Error(), "ana@example.com") || strings.Contains(err.Error(), recoveryCode) || !strings.Contains(err.Error(), "550") {
		t.Fatalf("err = %q: it must keep the code of the refusal and drop the address and the recovery code", err)
	}
}

func TestI_AServerThatQuotesTheMessageNeverGetsTheCodeBackInTheError(t *testing.T) {
	s := startServer(t, &fakeServer{rejectData: true})
	err := mustMailer(t, config(s)).SendRecoveryCode(ctx, recoveryMail())
	if err == nil {
		t.Fatal("a refused message was a success")
	}
	if strings.Contains(err.Error(), recoveryCode) || !strings.Contains(err.Error(), "[code]") || !strings.Contains(err.Error(), "554") {
		t.Fatalf("err = %q: it must keep the status and drop the code, whatever the server quotes", err)
	}
}

func TestI_ARecipientThatIsNotOneAddressIsRefusedBeforeAnyRecoveryCodeIsSaid(t *testing.T) {
	s := startServer(t, &fakeServer{})
	m := recoveryMail()
	m.To = "ana@example.com, spy@example.com"
	if err := mustMailer(t, config(s)).SendRecoveryCode(ctx, m); err == nil {
		t.Fatal("two recipients were accepted")
	}
	if got, _ := s.took(); len(got) != 0 {
		t.Fatalf("something was said to the server: %+v", got)
	}
}

func TestI_TlsIsRequiredForARecoveryCodeWhenTheConfigurationSaysSo(t *testing.T) {
	s := startServer(t, &fakeServer{})
	c := config(s)
	c.RequireTLS = true
	if err := mustMailer(t, c).SendRecoveryCode(ctx, recoveryMail()); err == nil {
		t.Fatal("a server without STARTTLS was used although TLS is required")
	}
	if got, _ := s.took(); len(got) != 0 {
		t.Fatalf("the code was sent in the clear: %+v", got)
	}
}
