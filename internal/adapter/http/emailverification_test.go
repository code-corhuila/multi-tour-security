package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/verifyemail"
)

// The tests below cover the public route that asks for a new verification link (spec 004-hu-sec-003, RN-SEC-004-03 to -06).

const (
	requestRoute = "/api/v1/security/public/tenants/travesia-natural/email-verifications"
	askBody      = `{"email":"ana@example.com"}`
	confirmRoute = "/api/v1/security/public/tenants/travesia-natural/email-verifications/confirmations"
	linkToken    = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE"
	linkPassword = "Correct-Horse-9"
	confirmBody  = `{"token":"` + linkToken + `","password":"` + linkPassword + `"}`
)

type fakeRequester struct {
	mu       sync.Mutex
	calls    [][2]string
	contexts []context.Context
	err      error
	release  chan struct{} // when set, the work waits for it
	finished chan struct{}
}

func (f *fakeRequester) Request(ctx context.Context, identifier, email string) error {
	f.mu.Lock()
	f.calls, f.contexts = append(f.calls, [2]string{identifier, email}), append(f.contexts, ctx)
	f.mu.Unlock()
	if f.release != nil {
		<-f.release
	}
	if f.finished != nil {
		close(f.finished)
	}
	return f.err
}

func (f *fakeRequester) called() [][2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]string(nil), f.calls...)
}

// background is a runner that logs to nowhere and has room for twenty at a time.
func background(timeout time.Duration) *httpadapter.Background {
	return httpadapter.NewBackground(slog.New(slog.NewJSONHandler(io.Discard, nil)), timeout, 20)
}

func askHandler(req httpadapter.LinkRequester, bg *httpadapter.Background, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithLinkRequests(req, bg))
}

func TestC_AskingForALinkIsAnsweredBeforeTheWorkAndWithNoBody(t *testing.T) {
	requester := &fakeRequester{release: make(chan struct{})}
	bg := background(5 * time.Second)
	rec := post(askHandler(requester, bg, io.Discard), requestRoute, "application/json", askBody, "trace-1")
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "trace-1" {
		t.Fatalf("%d %q headers %v", rec.Code, rec.Body, rec.Header())
	}
	close(requester.release) // the answer was given while the work was still waiting: its time tells nothing
	if err := bg.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := requester.called(); len(got) != 1 || got[0] != [2]string{"travesia-natural", "ana@example.com"} {
		t.Fatalf("the use case was called with %v", got)
	}
}

func TestC_TheAnswerIsTheSameWhateverTheUseCaseEndsUpDoing(t *testing.T) {
	answers := map[string]string{}
	for name, err := range map[string]error{"nothing": nil, "a failure": errors.New("pq: duplicate key (ana@example.com)")} {
		var logs bytes.Buffer
		bg := background(5 * time.Second)
		rec := post(askHandler(&fakeRequester{err: err}, bg, &logs), requestRoute, "application/json", askBody, "trace-1")
		_ = bg.Wait(context.Background())
		answers[name] = rec.Body.String() + http.StatusText(rec.Code)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("%s: %d", name, rec.Code)
		}
		if strings.Contains(logs.String(), "ana@example.com") {
			t.Fatalf("%s: the log quotes the e-mail of the person: %s", name, logs.String())
		}
	}
	if answers["nothing"] != answers["a failure"] {
		t.Fatalf("the answers differ: %v", answers)
	}
}

func TestC_ABodyThatIsNotAValidRequestIsRefusedBeforeAnyWork(t *testing.T) {
	for name, c := range map[string]struct {
		contentType, body string
		status            int
	}{
		"bad JSON":      {"application/json", `{"email":`, 400},
		"unknown field": {"application/json", `{"email":"a@b.co","x":1}`, 400},
		"no e-mail":     {"application/json", `{}`, 400},
		"not an e-mail": {"application/json", `{"email":"no-at-sign"}`, 400},
		"non-ASCII":     {"application/json", `{"email":"é@example.com"}`, 400},
		"wrong type":    {"text/plain", askBody, 415},
		"too large":     {"application/json", `{"email":"` + strings.Repeat("a", 4200) + `"}`, 413},
	} {
		requester := &fakeRequester{}
		bg := background(5 * time.Second)
		rec := post(askHandler(requester, bg, io.Discard), requestRoute, c.contentType, c.body, "trace-1")
		_ = bg.Wait(context.Background())
		if rec.Code != c.status || len(requester.called()) != 0 {
			t.Fatalf("%s: %d %s, calls %v", name, rec.Code, rec.Body, requester.called())
		}
	}
}

func TestC_TheWorkOutlivesTheRequestHasItsOwnDeadlineAndTheShutdownWaitsForIt(t *testing.T) {
	requester := &fakeRequester{release: make(chan struct{})}
	bg := background(2 * time.Second)
	h := askHandler(requester, bg, io.Discard)
	cancelled, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, requestRoute, strings.NewReader(askBody)).WithContext(cancelled)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)
	cancel() // the caller went away right after the answer

	waiting, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer stop()
	if err := bg.Wait(waiting); err == nil {
		t.Fatal("the shutdown did not wait for the work that was still running")
	}
	waitFor(t, func() bool { return len(requester.called()) > 0 }, "the work never started")
	work := requester.contexts[0]
	if work.Err() != nil {
		t.Fatalf("the work was cancelled with the request: %v", work.Err())
	}
	if _, ok := work.Deadline(); !ok {
		t.Fatal("the work has no deadline of its own")
	}
	close(requester.release)
	if err := bg.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestC_AnIdentifierThatCannotBeATenantIsAnsweredAcceptedAndAskedOfNobody(t *testing.T) {
	requester := &fakeRequester{}
	bg := background(time.Second)
	h := askHandler(requester, bg, io.Discard)
	if rec := post(h, "/api/v1/security/public/tenants/A_B/email-verifications", "application/json", askBody, "t"); rec.Code != http.StatusAccepted {
		t.Fatalf("asking: %d %s", rec.Code, rec.Body)
	}
	_ = bg.Wait(context.Background())
	if len(requester.called()) != 0 {
		t.Fatal("the use case was asked about an identifier that cannot be a tenant")
	}
}

func TestC_APanicInTheWorkIsLoggedByItsTypeWithTheTraceIdAndStopsNothing(t *testing.T) {
	var logs bytes.Buffer
	bg := httpadapter.NewBackground(slog.New(slog.NewJSONHandler(&logs, nil)), time.Second, 20)
	rec := post(askHandler(panicking{}, bg, &logs), requestRoute, "application/json", askBody, "trace-9")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d", rec.Code)
	}
	if err := bg.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if !strings.Contains(out, "trace-9") || !strings.Contains(out, "string") || strings.Contains(out, "ana@example.com") {
		t.Fatalf("the panic must be logged with the trace id and its type, never its value: %s", out)
	}
}

type panicking struct{}

func (panicking) Request(context.Context, string, string) error { panic("boom for ana@example.com") }

func TestC_AFloodIsBoundedEachExcessWorkIsDroppedWithAWarningAndEveryRequestIsStillAnswered202(t *testing.T) {
	var logs bytes.Buffer
	requester := &fakeRequester{release: make(chan struct{})}
	bg := httpadapter.NewBackground(slog.New(slog.NewJSONHandler(&logs, nil)), 5*time.Second, 2)
	h := askHandler(requester, bg, &logs)
	for i := 0; i < 6; i++ {
		if rec := post(h, requestRoute, "application/json", askBody, "flood"); rec.Code != http.StatusAccepted {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if running := len(requester.called()); running != 2 {
		t.Fatalf("%d works run at once, want the bound of 2", running)
	}
	if !strings.Contains(logs.String(), "dropped") || !strings.Contains(logs.String(), "flood") {
		t.Fatalf("a dropped work must say so with the trace id: %s", logs.String())
	}
	close(requester.release)
	_ = bg.Wait(context.Background())
}

// waitFor ends the test, instead of hanging it, when a condition does not come true within two seconds.
func waitFor(t *testing.T, condition func() bool, message string) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); !condition(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
	}
}

type fakeConfirmer struct {
	calls []verifyemail.Request
	err   error
	// release makes the confirmation wait; the context it ran on is kept for the test to read after it ends
	release chan struct{}
	ran     chan ranOn
}

// ranOn is what the context of the use case was while it was still running.
type ranOn struct {
	err         error
	hasDeadline bool
}

func (f *fakeConfirmer) Confirm(ctx context.Context, r verifyemail.Request) error {
	f.calls = append(f.calls, r)
	if f.release != nil {
		<-f.release
		_, has := ctx.Deadline()
		f.ran <- ranOn{err: ctx.Err(), hasDeadline: has}
	}
	return f.err
}

// verificationHandler registers both routes, for the tests that need to see them together.
func verificationHandler(req httpadapter.LinkRequester, conf httpadapter.EmailConfirmer, bg *httpadapter.Background, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)),
		httpadapter.WithLinkRequests(req, bg), httpadapter.WithEmailConfirmation(conf))
}

func TestC_ConfirmingGives204AndGivesTheUseCaseTheLinkThePasswordAndTheTraceId(t *testing.T) {
	confirmer := &fakeConfirmer{}
	rec := post(verificationHandler(&fakeRequester{}, confirmer, background(time.Second), io.Discard), confirmRoute, "application/json", confirmBody, "trace-77")
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %q headers %v", rec.Code, rec.Body, rec.Header())
	}
	if len(confirmer.calls) != 1 || confirmer.calls[0] != (verifyemail.Request{TenantIdentifier: "travesia-natural", Token: linkToken, Password: linkPassword, CorrelationID: "trace-77"}) {
		t.Fatalf("the use case was called with %+v", confirmer.calls)
	}
}

func TestC_EachRefusalOfTheConfirmationIsItsOwnAnswerInTheCommonEnvelope(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"a link that does not work":   {verifyemail.ErrBadLink, 422, "BUSINESS_RULE_VIOLATION"},
		"a wrong password":            {verifyemail.ErrWrongPassword, 401, "UNAUTHORIZED"},
		"an unknown tenant":           {verifyemail.ErrTenantNotFound, 404, "NOT_FOUND"},
		"a value that cannot be":      {verifyemail.ErrInvalidRequest, 400, "VALIDATION_ERROR"},
		"a failure":                   {errors.New("pq: connection reset"), 500, "INTERNAL_ERROR"},
		"a service that is not wired": {verifyemail.ErrNotWired, 500, "INTERNAL_ERROR"},
	} {
		var logs bytes.Buffer
		rec := post(verificationHandler(&fakeRequester{}, &fakeConfirmer{err: c.err}, background(time.Second), &logs), confirmRoute, "application/json", confirmBody, "trace-1")
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != c.status || env.Error != c.code || env.TraceID != "trace-1" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
		for _, secret := range []string{linkToken, linkPassword} {
			if strings.Contains(rec.Body.String(), secret) || strings.Contains(logs.String(), secret) {
				t.Fatalf("%s: the answer or the log carries %q", name, secret)
			}
		}
	}
}

func TestC_ABodyThatIsNotAValidConfirmationIsRefusedBeforeTheUseCase(t *testing.T) {
	for name, c := range map[string]struct {
		contentType, body string
		status            int
	}{
		"bad JSON":      {"application/json", `{"token":`, 400},
		"unknown field": {"application/json", `{"token":"t","password":"p","x":1}`, 400},
		"no token":      {"application/json", `{"password":"p"}`, 400},
		"no password":   {"application/json", `{"token":"` + linkToken + `"}`, 400},
		"wrong type":    {"text/plain", confirmBody, 415},
		"too large":     {"application/json", `{"token":"` + linkToken + `","password":"` + strings.Repeat("p", 4200) + `"}`, 413},
	} {
		confirmer := &fakeConfirmer{}
		rec := post(verificationHandler(&fakeRequester{}, confirmer, background(time.Second), io.Discard), confirmRoute, c.contentType, c.body, "trace-1")
		if rec.Code != c.status || len(confirmer.calls) != 0 {
			t.Fatalf("%s: %d %s, calls %v", name, rec.Code, rec.Body, confirmer.calls)
		}
	}
}

func TestC_AConfirmationThatTheCallerAbandonsStillCountsItsFailureOnAContextThatOutlivesTheRequest(t *testing.T) {
	confirmer := &fakeConfirmer{release: make(chan struct{}), ran: make(chan ranOn, 1)}
	h := verificationHandler(&fakeRequester{}, confirmer, background(time.Second), io.Discard)
	abandoned, abandon := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, confirmRoute, strings.NewReader(confirmBody)).WithContext(abandoned)
	req.Header.Set("Content-Type", "application/json")
	done := make(chan struct{})
	go func() { h.ServeHTTP(httptest.NewRecorder(), req); close(done) }()
	waitFor(t, func() bool { return len(confirmer.calls) > 0 }, "the confirmation never reached the use case")
	abandon() // the client closed the connection while the password was being compared
	close(confirmer.release)
	<-done
	ran := <-confirmer.ran
	if ran.err != nil {
		t.Fatalf("the use case ran on the context of the request and was cancelled with it (%v): a guess followed by a closed connection would not be counted toward the block", ran.err)
	}
	if !ran.hasDeadline {
		t.Fatal("the use case has no deadline of its own")
	}
}

func TestC_BothRoutesArePublicAndTheyAreNotThereWithoutTheOption(t *testing.T) {
	h := verificationHandler(&fakeRequester{}, &fakeConfirmer{}, background(time.Second), io.Discard)
	for _, route := range []string{requestRoute, confirmRoute} {
		if rec := post(h, route, "application/json", "{}", ""); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusNotFound {
			t.Fatalf("%s needs no token and exists: %d", route, rec.Code)
		}
	}
	bare := httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	for _, route := range []string{requestRoute, confirmRoute} {
		if rec := post(bare, route, "application/json", askBody, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without the option is a protected unknown route: %d", route, rec.Code)
		}
	}
}

func TestC_AnIdentifierThatCannotBeATenantIsRefusedOnConfirming(t *testing.T) {
	confirmer := &fakeConfirmer{}
	h := verificationHandler(&fakeRequester{}, confirmer, background(time.Second), io.Discard)
	if rec := post(h, "/api/v1/security/public/tenants/A_B/email-verifications/confirmations", "application/json", confirmBody, "t"); rec.Code != http.StatusBadRequest || len(confirmer.calls) != 0 {
		t.Fatalf("confirming: %d %s, calls %v", rec.Code, rec.Body, confirmer.calls)
	}
}
