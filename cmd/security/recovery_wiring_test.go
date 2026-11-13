package main

import (
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// End to end against PostgreSQL and a mailbox, through HTTP: a person forgets the password, asks for a code, receives it,
// chooses a new password with it, and every session of the account ends (spec 006-hu-sec-004).

const (
	recoveryAskURL      = "/api/v1/security/public/tenants/travesia-natural/password-recoveries"
	recoveryResetURL    = "/api/v1/security/public/tenants/travesia-natural/password-recoveries/resets"
	recoveryPlatformAsk = "/api/v1/security/public/platform/password-recoveries"
	recoveryPlatformSet = "/api/v1/security/public/platform/password-recoveries/resets"
	platformSignInURL   = "/api/v1/security/public/platform/sessions"
	chosenPass          = "Viaje-2026!nuevo"
)

var codePattern = regexp.MustCompile(`\b([0-9]{8})\b`)

// codeOf reads the code out of a message as a person does: the body is quoted-printable.
func codeOf(t *testing.T, raw string) string {
	t.Helper()
	body, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(raw)))
	m := codePattern.FindSubmatch(body)
	if m == nil {
		t.Fatalf("the e-mail carries no code: %s", raw)
	}
	return string(m[1])
}

func resetting(email, code, pass string) string {
	body, _ := json.Marshal(map[string]string{"email": email, "code": code, "newPassword": pass, "newPasswordConfirmation": pass})
	return string(body)
}

func (s *stack) events(t *testing.T, kind string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security.outbox_event WHERE event_type = $1`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestC_ACustomerAsksForACodeResetsThePasswordAndEverySessionEnds(t *testing.T) {
	s, box := newStackWithMailbox(t)
	id := s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	old := s.signedIn(t, "ana@example.com")

	// an e-mail with no account gets the same answer and no e-mail
	if rec := s.postJSON(t, recoveryAskURL, asking("nobody@example.com")); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("asking for nobody: %d %s", rec.Code, rec.Body)
	}
	s.drain(t)
	box.none(t)

	if rec := s.postJSON(t, recoveryAskURL, asking("ana@example.com")); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("asking: %d %s", rec.Code, rec.Body)
	}
	s.drain(t)
	code := codeOf(t, box.next(t))

	if rec := s.postJSON(t, recoveryResetURL, resetting("ana@example.com", "00000000", chosenPass)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a wrong code: %d %s", rec.Code, rec.Body)
	}
	if rec := s.postJSON(t, recoveryResetURL, resetting("ana@example.com", code, "weak")); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "newPassword") {
		t.Fatalf("a password that breaks the policy: %d %s", rec.Code, rec.Body)
	}
	if rec := s.postJSON(t, recoveryResetURL, resetting("ana@example.com", code, chosenPass)); rec.Code != http.StatusNoContent {
		t.Fatalf("the right code resets: %d %s", rec.Code, rec.Body)
	}
	if rec := s.postJSON(t, recoveryResetURL, resetting("ana@example.com", code, chosenPass)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a code works once: %d %s", rec.Code, rec.Body)
	}

	if rec := s.signIn(tenantURL, "ana@example.com", password); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the old password still signs in: %d %s", rec.Code, rec.Body)
	}
	if _, claims := s.claims(t, s.signIn(tenantURL, "ana@example.com", chosenPass)); claims["sub"] != id {
		t.Fatalf("the new password does not sign in: %v", claims)
	}
	if rec := s.refresh(old.RefreshToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session of before the reset was renewed: %d %s", rec.Code, rec.Body)
	}
	if s.events(t, "PasswordRecoveryRequested") != 1 || s.events(t, "PasswordReset") != 1 || s.events(t, "AccountSessionsRevoked") != 1 {
		t.Fatal("the facts of the recovery were not written")
	}
	if strings.Contains(s.logs.String(), code) || strings.Contains(s.logs.String(), chosenPass) || strings.Contains(s.logs.String(), "ana@example.com") {
		t.Fatalf("the log carries a secret: %s", s.logs)
	}
}

func TestC_ThreeCodesAnHourAndNoMoreAndTheNewestIsTheOnlyOneThatWorks(t *testing.T) {
	s, box := newStackWithMailbox(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	var codes []string
	for i := 0; i < 3; i++ {
		if rec := s.postJSON(t, recoveryAskURL, asking("ana@example.com")); rec.Code != http.StatusAccepted {
			t.Fatalf("asking %d: %d", i, rec.Code)
		}
		s.drain(t)
		codes = append(codes, codeOf(t, box.next(t)))
	}
	if rec := s.postJSON(t, recoveryAskURL, asking("ana@example.com")); rec.Code != http.StatusAccepted {
		t.Fatalf("a fourth ask is answered the same: %d", rec.Code)
	}
	s.drain(t)
	box.none(t)
	if codes[0] != codes[2] {
		if rec := s.postJSON(t, recoveryResetURL, resetting("ana@example.com", codes[0], chosenPass)); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("an earlier code was accepted: %d %s", rec.Code, rec.Body)
		}
	}
	if rec := s.postJSON(t, recoveryResetURL, resetting("ana@example.com", codes[2], chosenPass)); rec.Code != http.StatusNoContent {
		t.Fatalf("the newest code: %d %s", rec.Code, rec.Body)
	}
}

func TestC_TheFifthWrongTryRetiresTheCodeAndTheRightOneNoLongerWorks(t *testing.T) {
	s, box := newStackWithMailbox(t)
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	s.postJSON(t, recoveryAskURL, asking("ana@example.com"))
	s.drain(t)
	code := codeOf(t, box.next(t))
	wrong := "00000000"
	if code == wrong {
		wrong = "11111111"
	}
	for i := 0; i < 5; i++ {
		if rec := s.postJSON(t, recoveryResetURL, resetting("ana@example.com", wrong, chosenPass)); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("wrong try %d: %d", i, rec.Code)
		}
	}
	if rec := s.postJSON(t, recoveryResetURL, resetting("ana@example.com", code, chosenPass)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("the right code after five wrong tries: %d %s", rec.Code, rec.Body)
	}
}

func TestC_AFailedResetOfAnAdministratorIsAFactAndTheSuccessfulOneToo(t *testing.T) {
	s, box := newStackWithMailbox(t)
	s.account(t, tenantA, "boss@example.com", pgtest.Options{}, "TENANT_ADMINISTRATOR")
	s.postJSON(t, recoveryAskURL, asking("boss@example.com"))
	s.drain(t)
	code := codeOf(t, box.next(t))
	s.postJSON(t, recoveryResetURL, resetting("boss@example.com", "00000000", chosenPass))
	s.postJSON(t, recoveryResetURL, resetting("boss@example.com", code, "weak"))
	if got := s.events(t, "PasswordResetFailed"); got != 2 {
		t.Fatalf("failed attempts recorded = %d, want the wrong code and the weak password", got)
	}
	if rec := s.postJSON(t, recoveryResetURL, resetting("boss@example.com", code, chosenPass)); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if s.events(t, "PasswordReset") != 1 {
		t.Fatal("the successful reset of an administrator is not a fact")
	}
}

func TestC_ThePlatformAdministratorRecoversAtThePlatform(t *testing.T) {
	s, box := newStackWithMailbox(t)
	s.account(t, "", "root@multitour.example", pgtest.Options{}, "PLATFORM_ADMINISTRATOR")
	if rec := s.postJSON(t, recoveryPlatformAsk, asking("root@multitour.example")); rec.Code != http.StatusAccepted {
		t.Fatalf("asking: %d %s", rec.Code, rec.Body)
	}
	s.drain(t)
	code := codeOf(t, box.next(t))
	if rec := s.postJSON(t, recoveryPlatformSet, resetting("root@multitour.example", code, chosenPass)); rec.Code != http.StatusNoContent {
		t.Fatalf("resetting: %d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(platformSignInURL, "root@multitour.example", chosenPass); rec.Code != http.StatusOK {
		t.Fatalf("the new password does not sign in at the platform: %d %s", rec.Code, rec.Body)
	}
	// a customer of a tenant is not found at the platform
	s.account(t, tenantA, "ana@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	s.postJSON(t, recoveryPlatformAsk, asking("ana@example.com"))
	s.drain(t)
	box.none(t)
}

func TestC_AResetOfAPendingAccountVerifiesItsEmail(t *testing.T) {
	s, box := newStackWithMailbox(t)
	s.account(t, tenantA, "late@example.com", pgtest.Options{Pending: true}, "FINAL_CUSTOMER")
	s.postJSON(t, recoveryAskURL, asking("late@example.com"))
	s.drain(t)
	code := codeOf(t, box.next(t))
	if rec := s.postJSON(t, recoveryResetURL, resetting("late@example.com", code, chosenPass)); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "late@example.com", chosenPass); rec.Code != http.StatusOK {
		t.Fatalf("the account is still pending: %d %s", rec.Code, rec.Body)
	}
	if s.events(t, "AccountEmailVerified") != 1 {
		t.Fatal("the verified fact was not written")
	}
}
