package createaccount_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
	"github.com/code-corhuila/multi-tour-security/internal/core/verification"
)

func TestA_CreatingACustomerAccountSendsOneLink(t *testing.T) {
	w := newWorld()
	w.tenants.copies[tenantID] = tenant.Copy{TenantID: tenantID, Identifier: "travesia", Status: tenant.Active, CommercialName: "Travesía Natural SAS"}
	if _, created, err := w.service.Create(ctx, customer()); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if len(w.mailer.sent) != 1 {
		t.Fatalf("sent %d e-mails, want exactly one", len(w.mailer.sent))
	}
	mail, n := w.mailer.sent[0], w.registry.created[0]
	if mail.To != "ana@example.com" || mail.TenantName != "Travesía Natural SAS" || mail.TenantIdentifier != "travesia" {
		t.Fatalf("mail = %+v", mail)
	}
	if !verification.ValidShape(mail.Token) {
		t.Fatalf("the token %q is not the shape of a link", mail.Token)
	}
	if n.Link == nil || n.Link.TokenHash != verification.Hash(mail.Token) || !n.Link.ExpiresAt.Equal(now.Add(24*time.Hour)) || !n.Link.CreatedAt.Equal(now) {
		t.Fatalf("the store must get only the hash of the link and its expiry: %+v", n.Link)
	}
	if strings.Contains(n.Link.TokenHash, mail.Token) {
		t.Fatal("the link must not travel to the store")
	}
}

func TestA_ATenantWithoutACommercialNameSendsAsMultitour(t *testing.T) {
	w := newWorld()
	if _, _, err := w.service.Create(ctx, customer()); err != nil {
		t.Fatal(err)
	}
	if got := w.mailer.sent[0].TenantName; got != "Multitour" {
		t.Fatalf("tenant name = %q, want the platform name", got)
	}
}

func TestA_ARepeatedCreationSendsNoSecondLink(t *testing.T) {
	w := newWorld()
	if _, created, err := w.service.Create(ctx, customer()); err != nil || !created {
		t.Fatalf("first: created=%v err=%v", created, err)
	}
	if _, created, err := w.service.Create(ctx, customer()); err != nil || created {
		t.Fatalf("repeat: created=%v err=%v", created, err)
	}
	if len(w.mailer.sent) != 1 || len(w.registry.created) != 1 {
		t.Fatalf("sent=%d created=%d, want one of each", len(w.mailer.sent), len(w.registry.created))
	}
}

func TestA_AFailedSendIsRecordedAndChangesNothing(t *testing.T) {
	w := newWorld()
	w.mailer.err = errSMTP
	got, created, err := w.service.Create(ctx, customer())
	if err != nil || !created {
		t.Fatalf("a failed send must not undo the account: created=%v err=%v", created, err)
	}
	if got.Account.Status != account.Pending || len(w.registry.created) != 1 {
		t.Fatalf("the account must stay as created and pending: %+v", got.Account)
	}
	if len(w.verifications.failedHashes) != 1 || w.verifications.failedHashes[0] != w.registry.created[0].Link.TokenHash {
		t.Fatalf("the failure must be recorded against the link: %v", w.verifications.failedHashes)
	}
	if !strings.Contains(w.verifications.causes[0], "connection refused") {
		t.Fatalf("the cause = %q, want the reason of the failure", w.verifications.causes[0])
	}
}

func TestA_TheCauseOfAFailedSendNeverHoldsTheLinkAndIsBounded(t *testing.T) {
	w := newWorld()
	token := ""
	w.mailer.err = nil
	// the first send learns the token; the second creation fails with an error that quotes it
	if _, _, err := w.service.Create(ctx, customer()); err != nil {
		t.Fatal(err)
	}
	token = w.mailer.sent[0].Token

	w2 := newWorld()
	w2.mailer.err = errors.New("rejected https://app.example/verificar#token=" + token + " " + strings.Repeat("x", 500))
	if _, _, err := w2.service.Create(ctx, customer()); err != nil {
		t.Fatal(err)
	}
	cause := w2.verifications.causes[0]
	if strings.Contains(cause, token) || len(cause) > 200 {
		t.Fatalf("cause (%d characters) = %q: it must not hold the link and must fit 200", len(cause), cause)
	}
}

func TestA_InternalAndAdministratorAccountsAreNotPending(t *testing.T) {
	for _, c := range []createaccount.Command{internalUser(), firstAdministrator()} {
		w := newWorld()
		got, created, err := w.service.Create(ctx, c)
		if err != nil || !created {
			t.Fatalf("kind %d: created=%v err=%v", c.Kind, created, err)
		}
		n := w.registry.created[0]
		if n.Pending || n.Link != nil || got.Account.Status != account.Active || len(w.mailer.sent) != 0 {
			t.Fatalf("kind %d must be active with no link and no e-mail: %+v sent=%d", c.Kind, n, len(w.mailer.sent))
		}
	}
}

func TestA_ACustomerCreationNeedsTheMailerTheStoreOfLinksAndRandomness(t *testing.T) {
	for _, drop := range []func(*createaccount.Service){
		func(s *createaccount.Service) { s.Mailer = nil },
		func(s *createaccount.Service) { s.Verifications = nil },
		func(s *createaccount.Service) { s.Random = nil },
	} {
		w := newWorld()
		drop(w.service)
		if _, _, err := w.service.Create(ctx, customer()); !errors.Is(err, createaccount.ErrNotWired) {
			t.Fatalf("err = %v, want a wiring error before anything is written", err)
		}
		nothingWritten(t, w)
	}
}

func TestA_TheOtherKindsNeedNeitherMailerNorRandomness(t *testing.T) {
	w := newWorld()
	w.service.Mailer, w.service.Verifications, w.service.Random = nil, nil, nil
	if _, created, err := w.service.Create(ctx, internalUser()); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}

func TestA_ASourceOfRandomnessThatFailsCreatesNothing(t *testing.T) {
	w := newWorld()
	w.service.Random = bytes.NewReader([]byte{1, 2, 3})
	if _, created, err := w.service.Create(ctx, customer()); err == nil || created {
		t.Fatalf("created=%v err=%v, want a refusal", created, err)
	}
	if len(w.registry.created) != 0 || len(w.mailer.sent) != 0 {
		t.Fatal("no account may exist without its link")
	}
}
