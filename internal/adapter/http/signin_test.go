package httpadapter_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
)

const (
	tenantRoute   = "/api/v1/security/public/tenants/travesia-natural/sessions"
	platformRoute = "/api/v1/security/public/platform/sessions"
	goodBody      = `{"email":"ana@example.com","password":"s3cret-pass"}`
)

// fakeSignIn records what the route hands to the use case and answers what the test says.
type fakeSignIn struct {
	tenantReq, platformReq []signin.Request
	tokens                 signin.Tokens
	err                    error
}

func (f *fakeSignIn) SignIn(_ context.Context, r signin.Request) (signin.Tokens, error) {
	f.tenantReq = append(f.tenantReq, r)
	return f.tokens, f.err
}

func (f *fakeSignIn) SignInPlatform(_ context.Context, r signin.Request) (signin.Tokens, error) {
	f.platformReq = append(f.platformReq, r)
	return f.tokens, f.err
}

func okTokens() signin.Tokens {
	return signin.Tokens{AccessToken: "access.jwt.value", RefreshToken: "refresh-value", ExpiresIn: 15 * time.Minute}
}

func signInHandler(svc httpadapter.SignInService, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithSignIn(svc))
}

func post(h http.Handler, path, contentType, body, correlationID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if correlationID != "" {
		req.Header.Set("X-Correlation-Id", correlationID)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestC_SignInAnswers200WithTheTokensAndForbidsCaching(t *testing.T) {
	svc := &fakeSignIn{tokens: okTokens()}
	rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", goodBody, "corr-9")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["accessToken"] != "access.jwt.value" || got["refreshToken"] != "refresh-value" || got["tokenType"] != "Bearer" || got["expiresIn"] != float64(900) {
		t.Fatalf("body = %v", got)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("headers = %v", rec.Header())
	}
	want := signin.Request{TenantIdentifier: "travesia-natural", Email: "ana@example.com", Password: "s3cret-pass", CorrelationID: "corr-9"}
	if len(svc.tenantReq) != 1 || svc.tenantReq[0] != want || len(svc.platformReq) != 0 {
		t.Fatalf("the use case got %+v", svc.tenantReq)
	}
}

func TestC_ATokenWithoutARenewalValueHasNoRefreshTokenKey(t *testing.T) {
	svc := &fakeSignIn{tokens: signin.Tokens{AccessToken: "a.b.c", ExpiresIn: 10 * time.Minute}}
	rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", goodBody, "")
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, present := got["refreshToken"]; present || got["expiresIn"] != float64(600) {
		t.Fatalf("a temporary credential or a restricted access has no refresh token: %v", got)
	}
}

func TestC_ThePlatformRouteSignsInWithNoTenantAndGeneratesTheCorrelationId(t *testing.T) {
	svc := &fakeSignIn{tokens: okTokens()}
	rec := post(signInHandler(svc, io.Discard), platformRoute, "application/json; charset=utf-8", goodBody, "")
	if rec.Code != http.StatusOK || len(svc.platformReq) != 1 || len(svc.tenantReq) != 0 {
		t.Fatalf("status %d, platform %d, tenant %d", rec.Code, len(svc.platformReq), len(svc.tenantReq))
	}
	got := svc.platformReq[0]
	if got.TenantIdentifier != "" || got.CorrelationID == "" || got.CorrelationID != rec.Header().Get("X-Correlation-Id") {
		t.Fatalf("the platform request: %+v", got)
	}
}

func TestC_EveryRefusalIsTheSame401WithTheSameBodyAndNeedsNoToken(t *testing.T) {
	bodies := map[string]string{}
	for _, err := range []error{signin.ErrRefused, errors.Join(signin.ErrRefused, errors.New("wrapped"))} {
		for _, route := range []string{tenantRoute, platformRoute} {
			rec := post(signInHandler(&fakeSignIn{err: err}, io.Discard), route, "application/json", goodBody, "same-trace")
			if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s: status %d headers %v", route, rec.Code, rec.Header())
			}
			var env envelope
			if e := json.Unmarshal(rec.Body.Bytes(), &env); e != nil || env.Error != "UNAUTHORIZED" || env.TraceID != "same-trace" {
				t.Fatalf("%s: body %s", route, rec.Body)
			}
			bodies[rec.Body.String()] = route
		}
	}
	if len(bodies) != 1 {
		t.Fatalf("a refusal must have one and the same body whatever its cause, got %v", bodies)
	}
}

func TestC_ARequestThatIsNotAnEmailAndAPasswordIsA400AndNeverReachesTheUseCase(t *testing.T) {
	bad := map[string]string{
		"not JSON":            `not json`,
		"empty body":          ``,
		"null":                `null`,
		"an array":            `[]`,
		"missing password":    `{"email":"ana@example.com"}`,
		"missing e-mail":      `{"password":"x"}`,
		"unknown field":       `{"email":"ana@example.com","password":"x","admin":true}`,
		"wrong type":          `{"email":12,"password":"x"}`,
		"trailing document":   goodBody + goodBody,
		"trailing garbage":    goodBody + ` x`,
		"e-mail not a string": `{"email":["a@b.co"],"password":"x"}`,
	}
	for name, body := range bad {
		svc := &fakeSignIn{tokens: okTokens()}
		rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", body, "")
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != http.StatusBadRequest || env.Error != "VALIDATION_ERROR" || env.TraceID == "" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if len(svc.tenantReq) != 0 {
			t.Errorf("%s reached the use case", name)
		}
	}
	svc := &fakeSignIn{err: signin.ErrInvalidRequest}
	if rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", goodBody, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("an invalid request judged by the use case is a 400, got %d", rec.Code)
	}
}

func TestC_OnlyJSONIsReadAndABodyOver4KBIsRefusedBeforeItIsParsed(t *testing.T) {
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/jsonx", "application/json-patch+json"} {
		svc := &fakeSignIn{tokens: okTokens()}
		rec := post(signInHandler(svc, io.Discard), tenantRoute, contentType, goodBody, "")
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != http.StatusUnsupportedMediaType || env.Error != "UNSUPPORTED_MEDIA_TYPE" || len(svc.tenantReq) != 0 {
			t.Errorf("content type %q: %d %s", contentType, rec.Code, rec.Body)
		}
	}
	big := `{"email":"ana@example.com","password":"` + strings.Repeat("p", 4096) + `"}`
	svc := &fakeSignIn{tokens: okTokens()}
	rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", big, "")
	var env envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if rec.Code != http.StatusRequestEntityTooLarge || env.Error != "PAYLOAD_TOO_LARGE" || len(svc.tenantReq) != 0 {
		t.Errorf("a body over 4 KB: %d %s", rec.Code, rec.Body)
	}
	// a body that declares no length is judged by what arrives
	req := httptest.NewRequest(http.MethodPost, tenantRoute, io.NopCloser(bytes.NewReader([]byte(big))))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	chunked := httptest.NewRecorder()
	signInHandler(svc, io.Discard).ServeHTTP(chunked, req)
	if chunked.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a chunked body over 4 KB: %d", chunked.Code)
	}
}

func TestC_AFailureOfTheUseCaseIsA500ThatNeverShowsItsCause(t *testing.T) {
	var logs bytes.Buffer
	svc := &fakeSignIn{err: errors.New("dial tcp 10.0.0.5:5432: connection refused")}
	rec := post(signInHandler(svc, &logs), tenantRoute, "application/json", goodBody, "trace-500")
	var env envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if rec.Code != http.StatusInternalServerError || env.Error != "INTERNAL_ERROR" || env.TraceID != "trace-500" ||
		strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), "trace-500") || !strings.Contains(logs.String(), "connection refused") {
		t.Fatalf("the cause goes to the log with the trace id: %s", logs.String())
	}
}

// one key for the tests of the route: generating a 2048-bit key per test would make the suite slow for nothing
var routeKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}()

func TestC_LogsShowNoCredentialNoEmailAndNoToken(t *testing.T) {
	var logs bytes.Buffer
	for _, svc := range []*fakeSignIn{{tokens: okTokens()}, {err: signin.ErrRefused}, {err: errors.New("boom")}, {err: signin.ErrInvalidRequest}} {
		post(signInHandler(svc, &logs), tenantRoute, "application/json", goodBody, "")
	}
	for _, secret := range []string{"s3cret-pass", "ana@example.com", "access.jwt.value", "refresh-value"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log shows %q", secret)
		}
	}
	if logs.Len() == 0 {
		t.Fatal("nothing was logged: the check proves nothing")
	}
}

func TestC_WithoutTheUseCaseTheSignInRoutesDoNotExistAndOtherRoutesStayProtected(t *testing.T) {
	key := newKey(t)
	if rec := post(newHandler(key), tenantRoute, "application/json", goodBody, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without a use case the route is just another protected path, got %d", rec.Code)
	}
	if rec := get(signInHandler(&fakeSignIn{}, io.Discard), protectedPath, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a protected route still asks for a token, got %d", rec.Code)
	}
}
