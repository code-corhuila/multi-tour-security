package httpadapter_test

import (
	"bytes"
	"context"
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
)

// The tests below cover the public route that asks for a new verification link (spec 004-hu-sec-003, RN-SEC-004-03 to -06).

const (
	requestRoute = "/api/v1/security/public/tenants/travesia-natural/email-verifications"
	askBody      = `{"email":"ana@example.com"}`
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
