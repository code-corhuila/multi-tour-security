package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
)

// the two routes answer alike: every scenario below runs on both
var bothRoutes = []string{tenantRoute, platformRoute}

func TestC_BothRoutesGiveTheSameAnswerToABadBodyABadTypeAndAFailure(t *testing.T) {
	for _, route := range bothRoutes {
		cases := []struct {
			name, contentType, body string
			svc                     *fakeSignIn
			status                  int
			code                    string
		}{
			{"bad JSON", "application/json", `{"email":`, &fakeSignIn{}, 400, "VALIDATION_ERROR"},
			{"unknown field", "application/json", `{"email":"a@b.co","password":"x","x":1}`, &fakeSignIn{}, 400, "VALIDATION_ERROR"},
			{"wrong type", "text/plain", goodBody, &fakeSignIn{}, 415, "UNSUPPORTED_MEDIA_TYPE"},
			{"too large", "application/json", `{"email":"a@b.co","password":"` + strings.Repeat("p", 4200) + `"}`, &fakeSignIn{}, 413, "PAYLOAD_TOO_LARGE"},
			{"failure", "application/json", goodBody, &fakeSignIn{err: errors.New("down")}, 500, "INTERNAL_ERROR"},
			{"refusal", "application/json", goodBody, &fakeSignIn{err: signin.ErrRefused}, 401, "UNAUTHORIZED"},
		}
		for _, c := range cases {
			rec := post(signInHandler(c.svc, io.Discard), route, c.contentType, c.body, "trace-1")
			var env envelope
			_ = json.Unmarshal(rec.Body.Bytes(), &env)
			if rec.Code != c.status || env.Error != c.code || env.TraceID != "trace-1" || rec.Header().Get("X-Correlation-Id") != "trace-1" ||
				rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s: %d %s headers %v", route, c.name, rec.Code, rec.Body, rec.Header())
			}
			if c.status != 200 && len(c.svc.tenantReq)+len(c.svc.platformReq) > 0 && c.status != 401 && c.status != 500 {
				t.Errorf("%s %s reached the use case", route, c.name)
			}
		}
	}
}

func TestC_ABodyJustUnder4KBIsReadAndAChunkedOneOverItIsRefusedWithTheEnvelope(t *testing.T) {
	// {"email":"a@b.co","password":"<pad>"} is 32 bytes around the pad
	body := `{"email":"a@b.co","password":"` + strings.Repeat("p", 4096-32) + `"}`
	if len(body) != 4096 {
		t.Fatalf("the body of the test is %d bytes", len(body))
	}
	svc := &fakeSignIn{tokens: okTokens()}
	if rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", body, ""); rec.Code != http.StatusOK || len(svc.tenantReq) != 1 {
		t.Fatalf("a body of exactly 4096 bytes is read: %d", rec.Code)
	}
	svc = &fakeSignIn{tokens: okTokens()}
	req := httptest.NewRequest(http.MethodPost, tenantRoute, io.NopCloser(bytes.NewReader([]byte(body+" "))))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	signInHandler(svc, io.Discard).ServeHTTP(rec, req)
	var env envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if rec.Code != http.StatusRequestEntityTooLarge || env.Error != "PAYLOAD_TOO_LARGE" || len(svc.tenantReq) != 0 {
		t.Fatalf("one byte over, with no declared length: %d %s", rec.Code, rec.Body)
	}
}

func TestC_ThePasswordTravelsUntouchedAndAnIdentifierThatIsNotOneReachesTheUseCaseWhichRefusesIt(t *testing.T) {
	svc := &fakeSignIn{tokens: okTokens()}
	post(signInHandler(svc, io.Discard), tenantRoute, "application/json", `{"email":"ana@example.com","password":"  spaced pass  "}`, "")
	if svc.tenantReq[0].Password != "  spaced pass  " {
		t.Fatalf("the password was changed on the way: %q", svc.tenantReq[0].Password)
	}
	for _, identifier := range []string{"AB", "a--b", "Travesia", strings.Repeat("a", 41), "a_b"} {
		svc := &fakeSignIn{err: signin.ErrRefused}
		rec := post(signInHandler(svc, io.Discard), "/api/v1/security/public/tenants/"+identifier+"/sessions", "application/json", goodBody, "")
		if rec.Code != http.StatusUnauthorized || len(svc.tenantReq) != 1 || svc.tenantReq[0].TenantIdentifier != identifier {
			t.Errorf("identifier %q: %d, use case got %+v", identifier, rec.Code, svc.tenantReq)
		}
	}
}

func TestC_ABadTokenOnAPublicRouteIsIgnoredAndOtherMethodsAreNotThePublicRoute(t *testing.T) {
	svc := &fakeSignIn{tokens: okTokens()}
	req := httptest.NewRequest(http.MethodPost, tenantRoute, strings.NewReader(goodBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer garbage.not.ajwt")
	rec := httptest.NewRecorder()
	signInHandler(svc, io.Discard).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a person who signs in again with an old token in the browser is let in: %d", rec.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		signInHandler(&fakeSignIn{tokens: okTokens()}, io.Discard).ServeHTTP(rec, httptest.NewRequest(method, tenantRoute, nil))
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code == http.StatusOK || env.TraceID == "" {
			t.Errorf("%s answered %d without the envelope: %s", method, rec.Code, rec.Body)
		}
	}
}

func TestC_ACorrelationIdThatIsNotSafeIsReplacedAndTheBodyOfTheAnswerHasNoExtraKeys(t *testing.T) {
	svc := &fakeSignIn{tokens: okTokens()}
	rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", goodBody, strings.Repeat("x", 200))
	got := svc.tenantReq[0].CorrelationID
	if got == "" || len(got) > 128 || got != rec.Header().Get("X-Correlation-Id") {
		t.Fatalf("the use case got the correlation id %q", got)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &keys); err != nil || len(keys) != 4 {
		t.Fatalf("the answer has exactly accessToken, refreshToken, tokenType and expiresIn: %v %v", keys, err)
	}
}

func TestC_LogsShowNoCredentialEvenWhenTheBodyIsMalformedTooLargeOrOfTheWrongType(t *testing.T) {
	var logs bytes.Buffer
	secret := "p4ssw0rd-in-a-bad-body"
	bodies := []struct{ contentType, body string }{
		{"application/json", `{"email":"ana@example.com","password":"` + secret + `"`},
		{"application/json", `{"email":"ana@example.com","password":"` + secret + `","extra":1}`},
		{"application/json", goodBody + `{"password":"` + secret + `"}`},
		{"text/plain", `email=ana@example.com&password=` + secret},
		{"application/json", `{"email":"ana@example.com","password":"` + secret + strings.Repeat("p", 5000) + `"}`},
	}
	for _, b := range bodies {
		post(signInHandler(&fakeSignIn{}, &logs), tenantRoute, b.contentType, b.body, "")
	}
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), "ana@example.com") {
		t.Fatalf("the log shows a credential: %s", logs.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if !strings.Contains(line, "traceId") {
			t.Errorf("a log line without the trace id: %s", line)
		}
	}
}

func TestC_APendingAccountWithItsPasswordGets403AskingToVerifyTheEmailAndNoToken(t *testing.T) {
	svc := &fakeSignIn{err: signin.ErrEmailNotVerified}
	rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", goodBody, "trace-1")
	var env envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if rec.Code != http.StatusForbidden || env.Error != "FORBIDDEN" || env.TraceID != "trace-1" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(env.Details) != 1 || env.Details[0].Field != "email" || env.Details[0].Message != "EMAIL_NOT_VERIFIED" {
		t.Fatalf("details = %+v, want the one that lets the portal offer a new link", env.Details)
	}
	if strings.Contains(rec.Body.String(), "accessToken") || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("a refusal that asks to verify gives no token and is not an authentication challenge: %s %v", rec.Body, rec.Header())
	}
}

func TestC_TheGenericRefusalIsStillTheOnlyOneForEverythingElse(t *testing.T) {
	rec := post(signInHandler(&fakeSignIn{err: signin.ErrRefused}, io.Discard), tenantRoute, "application/json", goodBody, "trace-1")
	var env envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if rec.Code != http.StatusUnauthorized || env.Error != "UNAUTHORIZED" || len(env.Details) != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
