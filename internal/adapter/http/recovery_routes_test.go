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
	"github.com/code-corhuila/multi-tour-security/internal/core/recoverpassword"
)

// The tests below cover the public routes of the password recovery (spec 006-hu-sec-004, RN-SEC-006-01, -04, -07, -13, -14).

const (
	askRecoveryRoute   = "/api/v1/security/public/tenants/travesia-natural/password-recoveries"
	resetRoute         = "/api/v1/security/public/tenants/travesia-natural/password-recoveries/resets"
	askPlatformRoute   = "/api/v1/security/public/platform/password-recoveries"
	resetPlatformRoute = "/api/v1/security/public/platform/password-recoveries/resets"
	askRecoveryBody    = `{"email":"ana@example.com"}`
	resetCode          = "48213907"
	resetNewPassword   = "Viaje-2026!nuevo"
	resetBody          = `{"email":"ana@example.com","code":"` + resetCode + `","newPassword":"` + resetNewPassword + `","newPasswordConfirmation":"` + resetNewPassword + `"}`
)

type fakeRecoveryRequester struct {
	mu       sync.Mutex
	calls    []recoverpassword.RequestCode
	contexts []context.Context
	err      error
}

func (f *fakeRecoveryRequester) Request(ctx context.Context, r recoverpassword.RequestCode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.contexts = append(f.calls, r), append(f.contexts, ctx)
	return f.err
}

func (f *fakeRecoveryRequester) called() []recoverpassword.RequestCode {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recoverpassword.RequestCode(nil), f.calls...)
}

type fakeResetter struct {
	mu    sync.Mutex
	calls []recoverpassword.Reset
	ctxs  []context.Context
	// errsAtCall is what the context said when the use case was called: the handler cancels it when it returns
	errsAtCall []error
	err        error
}

func (f *fakeResetter) Reset(ctx context.Context, r recoverpassword.Reset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.ctxs, f.errsAtCall = append(f.calls, r), append(f.ctxs, ctx), append(f.errsAtCall, ctx.Err())
	return f.err
}

func recoveryHandler(req httpadapter.RecoveryRequester, res httpadapter.PasswordResetter, bg *httpadapter.Background, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithPasswordRecovery(req, res, bg))
}

// ---- asking for a code

func TestC_AskingForACodeAnswers202WithNoBodyAndIsTheSameForEveryOutcome(t *testing.T) {
	answers := map[string]string{}
	for name, err := range map[string]error{"nothing": nil, "a failure": errors.New("pq: duplicate key (ana@example.com)")} {
		var logs bytes.Buffer
		bg := background(5 * time.Second)
		rec := post(recoveryHandler(&fakeRecoveryRequester{err: err}, &fakeResetter{}, bg, &logs), askRecoveryRoute, "application/json", askRecoveryBody, "trace-1")
		_ = bg.Wait(context.Background())
		if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "trace-1" {
			t.Fatalf("%s: %d %q headers %v", name, rec.Code, rec.Body, rec.Header())
		}
		answers[name] = rec.Body.String() + http.StatusText(rec.Code)
		if strings.Contains(logs.String(), "ana@example.com") {
			t.Fatalf("%s: the log quotes the e-mail of the person: %s", name, logs.String())
		}
	}
	if answers["nothing"] != answers["a failure"] {
		t.Fatalf("the answers differ: %v", answers)
	}
}

func TestC_TheRequestForACodeIsAnsweredBeforeTheWorkAndCarriesTheTenantAndTheTrace(t *testing.T) {
	requester := &fakeRecoveryRequester{}
	bg := background(5 * time.Second)
	rec := post(recoveryHandler(requester, &fakeResetter{}, bg, io.Discard), askRecoveryRoute, "application/json", askRecoveryBody, "trace-7")
	_ = bg.Wait(context.Background())
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d", rec.Code)
	}
	got := requester.called()
	if len(got) != 1 || got[0].TenantIdentifier != "travesia-natural" || got[0].Email != "ana@example.com" || got[0].Platform || got[0].CorrelationID != "trace-7" {
		t.Fatalf("the use case was called with %+v", got)
	}
}

func TestC_ThePlatformRouteAsksForThePlatformAndIgnoresAnyTenant(t *testing.T) {
	requester := &fakeRecoveryRequester{}
	bg := background(5 * time.Second)
	rec := post(recoveryHandler(requester, &fakeResetter{}, bg, io.Discard), askPlatformRoute, "application/json", `{"email":"root@multitour.example"}`, "t")
	_ = bg.Wait(context.Background())
	got := requester.called()
	if rec.Code != http.StatusAccepted || len(got) != 1 || !got[0].Platform || got[0].TenantIdentifier != "" || got[0].Email != "root@multitour.example" {
		t.Fatalf("%d %+v", rec.Code, got)
	}
}

func TestC_ABodyThatIsNotAValidRequestForACodeIsRefusedBeforeAnyWork(t *testing.T) {
	for name, c := range map[string]struct {
		contentType, body string
		status            int
	}{
		"bad JSON":      {"application/json", `{"email":`, 400},
		"unknown field": {"application/json", `{"email":"a@b.co","x":1}`, 400},
		"no e-mail":     {"application/json", `{}`, 400},
		"not an e-mail": {"application/json", `{"email":"no-at-sign"}`, 400},
		"non-ASCII":     {"application/json", `{"email":"é@example.com"}`, 400},
		"wrong type":    {"text/plain", askRecoveryBody, 415},
		"too large":     {"application/json", `{"email":"` + strings.Repeat("a", 4200) + `"}`, 413},
	} {
		requester := &fakeRecoveryRequester{}
		bg := background(5 * time.Second)
		rec := post(recoveryHandler(requester, &fakeResetter{}, bg, io.Discard), askRecoveryRoute, c.contentType, c.body, "trace-1")
		_ = bg.Wait(context.Background())
		if rec.Code != c.status || len(requester.called()) != 0 {
			t.Fatalf("%s: %d %s, calls %v", name, rec.Code, rec.Body, requester.called())
		}
	}
}

func TestC_AnIdentifierThatCannotBeATenantIsAnsweredAcceptedAndNoCodeIsAskedFor(t *testing.T) {
	requester := &fakeRecoveryRequester{}
	bg := background(time.Second)
	rec := post(recoveryHandler(requester, &fakeResetter{}, bg, io.Discard), "/api/v1/security/public/tenants/A_B/password-recoveries", "application/json", askRecoveryBody, "t")
	_ = bg.Wait(context.Background())
	if rec.Code != http.StatusAccepted || len(requester.called()) != 0 {
		t.Fatalf("%d, calls %v", rec.Code, requester.called())
	}
}

func TestC_TheWorkOfAskingForACodeOutlivesTheRequestAndHasItsOwnDeadline(t *testing.T) {
	requester := &fakeRecoveryRequester{}
	bg := background(2 * time.Second)
	h := recoveryHandler(requester, &fakeResetter{}, bg, io.Discard)
	cancelled, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, askRecoveryRoute, strings.NewReader(askRecoveryBody)).WithContext(cancelled)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)
	cancel() // the caller went away right after the answer
	_ = bg.Wait(context.Background())
	if len(requester.contexts) != 1 {
		t.Fatalf("the work ran %d times", len(requester.contexts))
	}
	if _, ok := requester.contexts[0].Deadline(); !ok {
		t.Fatal("the work has no deadline of its own")
	}
}

// ---- resetting

func TestC_AValidResetAnswers204AndPassesEveryFieldAndTheTrace(t *testing.T) {
	resetter := &fakeResetter{}
	rec := post(recoveryHandler(&fakeRecoveryRequester{}, resetter, background(time.Second), io.Discard), resetRoute, "application/json", resetBody, "trace-3")
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "trace-3" {
		t.Fatalf("%d %q headers %v", rec.Code, rec.Body, rec.Header())
	}
	want := recoverpassword.Reset{TenantIdentifier: "travesia-natural", Email: "ana@example.com", Code: resetCode, NewPassword: resetNewPassword, Confirmation: resetNewPassword, CorrelationID: "trace-3"}
	if len(resetter.calls) != 1 || resetter.calls[0] != want {
		t.Fatalf("the use case was called with %+v", resetter.calls)
	}
}

func TestC_ThePlatformResetIsMarkedPlatform(t *testing.T) {
	resetter := &fakeResetter{}
	rec := post(recoveryHandler(&fakeRecoveryRequester{}, resetter, background(time.Second), io.Discard), resetPlatformRoute, "application/json", resetBody, "t")
	if rec.Code != http.StatusNoContent || len(resetter.calls) != 1 || !resetter.calls[0].Platform || resetter.calls[0].TenantIdentifier != "" {
		t.Fatalf("%d %+v", rec.Code, resetter.calls)
	}
}

func TestC_EveryRefusedCodeIsOneSingle422(t *testing.T) {
	// the use case says ErrCodeRefused for a wrong, used, expired or retired code and for an e-mail with no account
	rec := post(recoveryHandler(&fakeRecoveryRequester{}, &fakeResetter{err: recoverpassword.ErrCodeRefused}, background(time.Second), io.Discard), resetRoute, "application/json", resetBody, "t")
	first := rec.Body.String()
	e := decode(t, rec)
	if rec.Code != http.StatusUnprocessableEntity || e.Error != "BUSINESS_RULE_VIOLATION" || !strings.Contains(e.Message, "ask for a new one") {
		t.Fatalf("%d %+v", rec.Code, e)
	}
	// and the same refusal, byte for byte, whatever the cause the use case wrapped
	rec2 := post(recoveryHandler(&fakeRecoveryRequester{}, &fakeResetter{err: errors.Join(recoverpassword.ErrCodeRefused, errors.New("wrong try 3"))}, background(time.Second), io.Discard), resetRoute, "application/json", resetBody, "t")
	if first != rec2.Body.String() {
		t.Fatalf("the refusals differ: %q %q", first, rec2.Body)
	}
}

func TestC_AFieldThatCannotBeWhatItMustBeIsA400ThatNamesIt(t *testing.T) {
	for _, field := range []string{"email", "code", "newPassword", "newPasswordConfirmation"} {
		rec := post(recoveryHandler(&fakeRecoveryRequester{}, &fakeResetter{err: &recoverpassword.FieldError{Field: field}}, background(time.Second), io.Discard), resetRoute, "application/json", resetBody, "t")
		e := decode(t, rec)
		if rec.Code != http.StatusBadRequest || e.Error != "VALIDATION_ERROR" || len(e.Details) != 1 || e.Details[0].Field != field {
			t.Fatalf("%s: %d %+v", field, rec.Code, e)
		}
		if strings.Contains(rec.Body.String(), resetNewPassword) || strings.Contains(rec.Body.String(), resetCode) {
			t.Fatalf("the answer carries a secret: %s", rec.Body)
		}
	}
}

func TestC_AnUnknownTenantIsA404(t *testing.T) {
	rec := post(recoveryHandler(&fakeRecoveryRequester{}, &fakeResetter{err: recoverpassword.ErrTenantNotFound}, background(time.Second), io.Discard), resetRoute, "application/json", resetBody, "t")
	if e := decode(t, rec); rec.Code != http.StatusNotFound || e.Error != "NOT_FOUND" {
		t.Fatalf("%d %+v", rec.Code, e)
	}
}

func TestC_ABodyThatIsNotAValidResetIsRefusedBeforeTheUseCase(t *testing.T) {
	for name, c := range map[string]struct {
		contentType, body string
		status            int
		field             string
	}{
		"bad JSON":        {"application/json", `{"email":`, 400, ""},
		"unknown field":   {"application/json", `{"email":"a@b.co","code":"12345678","newPassword":"x","newPasswordConfirmation":"x","y":1}`, 400, ""},
		"no e-mail":       {"application/json", `{"code":"12345678","newPassword":"x","newPasswordConfirmation":"x"}`, 400, "email"},
		"no code":         {"application/json", `{"email":"a@b.co","newPassword":"x","newPasswordConfirmation":"x"}`, 400, "code"},
		"no new password": {"application/json", `{"email":"a@b.co","code":"12345678","newPasswordConfirmation":"x"}`, 400, "newPassword"},
		"no confirmation": {"application/json", `{"email":"a@b.co","code":"12345678","newPassword":"x"}`, 400, "newPasswordConfirmation"},
		"wrong type":      {"text/plain", resetBody, 415, ""},
		"too large":       {"application/json", `{"email":"a@b.co","code":"12345678","newPassword":"` + strings.Repeat("p", 4200) + `","newPasswordConfirmation":"x"}`, 413, ""},
	} {
		resetter := &fakeResetter{}
		rec := post(recoveryHandler(&fakeRecoveryRequester{}, resetter, background(time.Second), io.Discard), resetRoute, c.contentType, c.body, "t")
		if rec.Code != c.status || len(resetter.calls) != 0 {
			t.Fatalf("%s: %d %s, calls %v", name, rec.Code, rec.Body, resetter.calls)
		}
		if c.field != "" {
			if e := decode(t, rec); len(e.Details) != 1 || e.Details[0].Field != c.field {
				t.Fatalf("%s: details %+v", name, e.Details)
			}
		}
	}
}

func TestC_AnIdentifierThatCannotBeATenantIsA400OnAReset(t *testing.T) {
	resetter := &fakeResetter{}
	rec := post(recoveryHandler(&fakeRecoveryRequester{}, resetter, background(time.Second), io.Discard), "/api/v1/security/public/tenants/A_B/password-recoveries/resets", "application/json", resetBody, "t")
	if rec.Code != http.StatusBadRequest || len(resetter.calls) != 0 {
		t.Fatalf("%d, calls %v", rec.Code, resetter.calls)
	}
}

func TestC_AFailureOfOursIsA500WithTheTypeInTheLogAndNoSecretAnywhere(t *testing.T) {
	var logs bytes.Buffer
	rec := post(recoveryHandler(&fakeRecoveryRequester{}, &fakeResetter{err: errors.New("pq: could not update ana@example.com " + resetCode)}, background(time.Second), &logs), resetRoute, "application/json", resetBody, "trace-5")
	if e := decode(t, rec); rec.Code != http.StatusInternalServerError || e.Error != "INTERNAL_ERROR" {
		t.Fatalf("%d %+v", rec.Code, e)
	}
	for _, secret := range []string{"ana@example.com", resetCode, resetNewPassword} {
		if strings.Contains(rec.Body.String(), secret) || strings.Contains(logs.String(), secret) {
			t.Fatalf("%q reached the answer or the log: %s %s", secret, rec.Body, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "trace-5") {
		t.Fatalf("the log has no trace id: %s", logs.String())
	}
}

func TestC_TheResetRunsOnAContextThatOutlivesTheRequest(t *testing.T) {
	// a guess followed by a closed connection must still be counted toward the five tries of the code
	resetter := &fakeResetter{}
	h := recoveryHandler(&fakeRecoveryRequester{}, resetter, background(time.Second), io.Discard)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, resetRoute, strings.NewReader(resetBody)).WithContext(cancelled)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(resetter.ctxs) != 1 || resetter.errsAtCall[0] != nil {
		t.Fatal("the reset ran on the context of a request that was already over")
	}
	if _, ok := resetter.ctxs[0].Deadline(); !ok {
		t.Fatal("the reset has no deadline of its own")
	}
}

func TestC_TheRecoveryRoutesNeedNoToken(t *testing.T) {
	h := recoveryHandler(&fakeRecoveryRequester{}, &fakeResetter{}, background(time.Second), io.Discard)
	for _, c := range []struct{ path, body string }{{askRecoveryRoute, askRecoveryBody}, {askPlatformRoute, askRecoveryBody}, {resetRoute, resetBody}, {resetPlatformRoute, resetBody}} {
		rec := post(h, c.path, "application/json", c.body, "t")
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Fatalf("%s asked for a credential: %d", c.path, rec.Code)
		}
	}
}

func TestC_NoAnswerCarriesAPasswordOrTheCode(t *testing.T) {
	// RN-SEC-006-14: the process never shows or recovers a password
	h := recoveryHandler(&fakeRecoveryRequester{}, &fakeResetter{}, background(time.Second), io.Discard)
	for _, c := range []struct{ path, body string }{{askRecoveryRoute, askRecoveryBody}, {resetRoute, resetBody}} {
		rec := post(h, c.path, "application/json", c.body, "t")
		for _, secret := range []string{resetNewPassword, resetCode} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("%s answered with a secret: %s", c.path, rec.Body)
			}
		}
	}
}
