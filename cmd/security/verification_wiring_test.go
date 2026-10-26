package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/smtpmail"
)

// End to end against PostgreSQL and a mailbox, through HTTP: a Final Customer creates an account, receives one link, cannot
// sign in until the link and the password of the account verify the e-mail, and signs in after (spec 004-hu-sec-003).

const (
	askURL     = "/api/v1/security/public/tenants/travesia-natural/email-verifications"
	confirmURL = "/api/v1/security/public/tenants/travesia-natural/email-verifications/confirmations"
)

// mailbox is an SMTP server that keeps the messages it receives, so that a test can read the link that a person would.
type mailbox struct {
	addr     string
	mu       sync.Mutex
	received chan string
}

func startMailbox(t *testing.T) *mailbox {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	m := &mailbox{addr: ln.Addr().String(), received: make(chan string, 32)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(conn)
		}
	}()
	return m
}

func (m *mailbox) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	say := func(line string) { fmt.Fprintf(conn, "%s\r\n", line) }
	say("220 mailbox")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch verb := strings.ToUpper(strings.Fields(line + " x")[0]); verb {
		case "EHLO", "HELO":
			say("250 mailbox")
		case "DATA":
			say("354 go")
			var body strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				body.WriteString(l)
			}
			say("250 queued")
			m.received <- body.String()
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (m *mailbox) config() smtpmail.Config {
	host, port, _ := net.SplitHostPort(m.addr)
	var p int
	fmt.Sscan(port, &p)
	return smtpmail.Config{Host: host, Port: p, From: "no-reply@multitour.example", PublicBaseURL: "http://localhost:4200"}
}

// next waits for the next message; none checks that no other arrives.
func (m *mailbox) next(t *testing.T) string {
	t.Helper()
	select {
	case message := <-m.received:
		return message
	case <-time.After(5 * time.Second):
		t.Fatal("no e-mail arrived")
		return ""
	}
}

func (m *mailbox) none(t *testing.T) {
	t.Helper()
	select {
	case message := <-m.received:
		t.Fatalf("an e-mail arrived that should not have: %s", message)
	case <-time.After(500 * time.Millisecond):
	}
}

var linkPattern = regexp.MustCompile(`/t/travesia-natural/verificar-correo#token=([A-Za-z0-9_-]{43})`)

// tokenOf reads the link out of a message as a mail client does: the body is quoted-printable.
func tokenOf(t *testing.T, raw string) string {
	t.Helper()
	body, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(raw)))
	m := linkPattern.FindSubmatch(body)
	if m == nil {
		t.Fatalf("the e-mail carries no link: %s", raw)
	}
	return string(m[1])
}

func newStackWithMailbox(t *testing.T) (*stack, *mailbox) {
	t.Helper()
	box := startMailbox(t)
	return newStackOnMail(t, pgtest.Open(t), box.config()), box
}

// drain waits for the work that was started after an answer, so that "nothing was sent" is judged after it could have been.
func (s *stack) drain(t *testing.T) {
	t.Helper()
	waiting, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	if err := s.background.Wait(waiting); err != nil {
		t.Fatalf("the work after the answer did not end: %v", err)
	}
}

func (s *stack) postJSON(t *testing.T, url, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "e2e-ver")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	validateAgainstContract(t, req, rec)
	return rec
}

func confirmation(token, pass string) string {
	body, _ := json.Marshal(map[string]string{"token": token, "password": pass})
	return string(body)
}

func asking(email string) string {
	body, _ := json.Marshal(map[string]string{"email": email})
	return string(body)
}

func TestC_ACustomerGetsOneLinkIsRefusedUntilTheEmailIsVerifiedAndThenSignsIn(t *testing.T) {
	s, box := newStackWithMailbox(t)
	rec := s.register(t, accountsURL, "customer-key-0001", customerFields())
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	c := decodeCreated(t, rec)
	if c.AccountStatus != "PENDING" || c.EmailVerified {
		t.Fatalf("the account waits for its e-mail: %+v", c)
	}
	token := tokenOf(t, box.next(t))

	if rec := s.signIn(tenantURL, "laura.perez@example.com", customerPass); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "EMAIL_NOT_VERIFIED") {
		t.Fatalf("a pending account with its right password is told to verify: %d %s", rec.Code, rec.Body)
	}
	if rec := s.signIn(tenantURL, "laura.perez@example.com", "Another-pass-1!"); rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "EMAIL_NOT_VERIFIED") {
		t.Fatalf("a stranger learns nothing: %d %s", rec.Code, rec.Body)
	}
	if rec := s.postJSON(t, confirmURL, confirmation(token, "Another-pass-1!")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the link alone does not verify: %d %s", rec.Code, rec.Body)
	}
	if rec := s.postJSON(t, confirmURL, confirmation(token, customerPass)); rec.Code != http.StatusNoContent {
		t.Fatalf("the link and the password verify: %d %s", rec.Code, rec.Body)
	}
	if rec := s.postJSON(t, confirmURL, confirmation(token, customerPass)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a link works once: %d %s", rec.Code, rec.Body)
	}

	_, claims := s.claims(t, s.signIn(tenantURL, "laura.perez@example.com", customerPass))
	if claims["sub"] != c.AccountID || claims["tenantId"] != tenantA {
		t.Fatalf("the customer signs in as the account that was created: %v", claims)
	}
	if roles, _ := claims["roles"].([]any); len(roles) != 1 || roles[0] != "FINAL_CUSTOMER" {
		t.Fatalf("roles = %v", claims["roles"])
	}
	if _, restricted := claims["access"]; restricted {
		t.Fatalf("the password is ordinary, not temporary: %v", claims)
	}
	var status string
	var verified bool
	var events int
	var payload string
	if err := s.pool.QueryRow(ctx, `SELECT identity_status, email_verified FROM security.identity WHERE identity_id = $1::uuid`, c.AccountID).Scan(&status, &verified); err != nil ||
		status != "ACTIVE" || !verified {
		t.Fatalf("account = %s %v %v", status, verified, err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*), COALESCE(max(payload::text), '') FROM security.outbox_event WHERE event_type = 'AccountEmailVerified'`).Scan(&events, &payload); err != nil ||
		events != 1 || !strings.Contains(payload, "laura.perez@example.com") || strings.Contains(payload, token) {
		t.Fatalf("one fact without the link: %d %s %v", events, payload, err)
	}
	box.none(t)
}

func TestC_AskingForANewLinkSendsOneAndTheFirstOneStopsWorking(t *testing.T) {
	s, box := newStackWithMailbox(t)
	s.register(t, accountsURL, "customer-key-0001", customerFields())
	first := tokenOf(t, box.next(t))
	if rec := s.postJSON(t, askURL, asking("Laura.Perez@Example.com")); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	second := tokenOf(t, box.next(t))
	if first == second {
		t.Fatal("a new link is a new value")
	}
	if rec := s.postJSON(t, confirmURL, confirmation(first, customerPass)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("the replaced link: %d %s", rec.Code, rec.Body)
	}
	if rec := s.postJSON(t, confirmURL, confirmation(second, customerPass)); rec.Code != http.StatusNoContent {
		t.Fatalf("the newest link: %d %s", rec.Code, rec.Body)
	}
}

func TestC_ANewLinkIsSentOnlyToAPendingAccountAndTheAnswerIsAlwaysTheSame(t *testing.T) {
	s, box := newStackWithMailbox(t)
	s.register(t, accountsURL, "customer-key-0001", customerFields())
	s.postJSON(t, confirmURL, confirmation(tokenOf(t, box.next(t)), customerPass)) // now verified
	for name, c := range map[string]struct{ url, email string }{
		"an account that is already verified": {askURL, "laura.perez@example.com"},
		"an e-mail nobody has":                {askURL, "nobody@example.com"},
		"a tenant that does not exist":        {"/api/v1/security/public/tenants/nowhere/email-verifications", "laura.perez@example.com"},
	} {
		rec := s.postJSON(t, c.url, asking(c.email))
		if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
			t.Fatalf("%s: %d %q", name, rec.Code, rec.Body)
		}
	}
	s.drain(t)
	box.none(t)
}

func TestC_AtMostThreeLinksAnHourAreSentTheFourthAskIsAnsweredTheSameAndSendsNothing(t *testing.T) {
	s, box := newStackWithMailbox(t)
	s.register(t, accountsURL, "customer-key-0001", customerFields())
	box.next(t) // the link of the creation counts as the first
	for i := 0; i < 2; i++ {
		if rec := s.postJSON(t, askURL, asking("laura.perez@example.com")); rec.Code != http.StatusAccepted {
			t.Fatalf("ask %d: %d", i, rec.Code)
		}
		box.next(t)
	}
	if rec := s.postJSON(t, askURL, asking("laura.perez@example.com")); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("the fourth is answered like the others: %d %q", rec.Code, rec.Body)
	}
	s.drain(t)
	box.none(t)
}

func TestC_AFailedSendIsRecordedWithoutTheLinkAndTheAccountIsStillCreated(t *testing.T) {
	s := newStack(t) // the mail settings point at a server nobody listens on
	rec := s.register(t, accountsURL, "customer-key-0001", customerFields())
	if rec.Code != http.StatusCreated || decodeCreated(t, rec).AccountStatus != "PENDING" {
		t.Fatalf("a failed send does not undo the account: %d %s", rec.Code, rec.Body)
	}
	var failedAt *time.Time
	var cause *string
	if err := s.pool.QueryRow(ctx, `SELECT send_failed_at, send_error FROM security.email_verification`).Scan(&failedAt, &cause); err != nil || failedAt == nil || cause == nil {
		t.Fatalf("the failure is recorded: %v %v %v", failedAt, cause, err)
	}
	for _, leak := range []string{"laura.perez@example.com", customerPass} {
		if strings.Contains(*cause, leak) || strings.Contains(s.logs.String(), leak) {
			t.Fatalf("the cause or the log shows %q: %s %s", leak, *cause, s.logs)
		}
	}
	if !bytes.Contains([]byte(*cause), []byte("smtp")) {
		t.Fatalf("the cause says where it failed: %s", *cause)
	}
}
