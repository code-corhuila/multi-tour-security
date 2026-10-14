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
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/changepassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	passwordRoute = "/api/v1/security/sessions/password"
	passwordBody  = `{"newPassword":"Tr4vesia-Natural"}`
)

type fakeChange struct {
	requests []changepassword.Request
	err      error
}

func (f *fakeChange) Change(_ context.Context, r changepassword.Request) error {
	f.requests = append(f.requests, r)
	return f.err
}

func changeHandler(svc httpadapter.ChangePasswordService, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithChangePassword(svc))
}

// bearer signs a token like the sign-in does: access says what it serves, and a normal token has none.
func bearer(t *testing.T, access string) string {
	t.Helper()
	claims := jwt.MapClaims{"sub": "acc-1", "tenantId": "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", "roles": []string{}, "exp": time.Now().Add(10 * time.Minute).Unix()}
	if access != "" {
		claims["access"] = access
	}
	return sign(t, jwt.SigningMethodRS256, routeKey, claims)
}

func put(h http.Handler, token, contentType, body, correlationID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, passwordRoute, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
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

func TestC_TheTokenOfATemporaryCredentialChoosesThePasswordAndGets204(t *testing.T) {
	svc := &fakeChange{}
	rec := put(changeHandler(svc, io.Discard), bearer(t, "password-change"), "application/json", passwordBody, "trace-p")
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "trace-p" {
		t.Fatalf("%d %q %v", rec.Code, rec.Body, rec.Header())
	}
	want := changepassword.Request{AccountID: "acc-1", TenantID: "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f", NewPassword: "Tr4vesia-Natural", CorrelationID: "trace-p"}
	if len(svc.requests) != 1 || svc.requests[0] != want {
		t.Fatalf("the use case got %+v", svc.requests)
	}
}

func TestC_OnlyThatTokenIsAcceptedAndEveryOtherIsTheSame401(t *testing.T) {
	cases := map[string]string{
		"no token":          "",
		"not a token":       "not-a-jwt",
		"an ordinary token": bearer(t, ""),
		"a restricted one":  bearer(t, "restricted"),
		"another mark":      bearer(t, "something-else"),
	}
	bodies := map[string]bool{}
	for name, token := range cases {
		svc := &fakeChange{}
		rec := put(changeHandler(svc, io.Discard), token, "application/json", passwordBody, "same")
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != http.StatusUnauthorized || env.Error != "UNAUTHORIZED" || rec.Header().Get("WWW-Authenticate") != "Bearer" || len(svc.requests) != 0 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		bodies[rec.Body.String()] = true
	}
	if len(bodies) != 1 {
		t.Errorf("a refusal has one body whatever the token, got %v", bodies)
	}
}

func TestC_ARefusalOfTheUseCaseIsA401AndAWeakPasswordIsA400(t *testing.T) {
	rec := put(changeHandler(&fakeChange{err: signin.ErrRefused}, io.Discard), bearer(t, "password-change"), "application/json", passwordBody, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a credential that cannot be changed: %d", rec.Code)
	}
	rec = put(changeHandler(&fakeChange{err: changepassword.ErrWeakPassword}, io.Discard), bearer(t, "password-change"), "application/json", passwordBody, "")
	var env envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if rec.Code != http.StatusBadRequest || env.Error != "VALIDATION_ERROR" || strings.Contains(rec.Body.String(), "Tr4vesia") {
		t.Fatalf("a weak password: %d %s", rec.Code, rec.Body)
	}
}

func TestC_ABodyThatIsNotANewPasswordIsA400A415A413Or500(t *testing.T) {
	big := `{"newPassword":"` + strings.Repeat("p", 4200) + `"}`
	cases := []struct {
		name, contentType, body string
		svc                     *fakeChange
		status                  int
		code                    string
	}{
		{"bad JSON", "application/json", `{"newPassword":`, &fakeChange{}, 400, "VALIDATION_ERROR"},
		{"missing field", "application/json", `{}`, &fakeChange{}, 400, "VALIDATION_ERROR"},
		{"unknown field", "application/json", `{"newPassword":"x","email":"a@b.co"}`, &fakeChange{}, 400, "VALIDATION_ERROR"},
		{"wrong type", "application/json", `{"newPassword":1}`, &fakeChange{}, 400, "VALIDATION_ERROR"},
		{"not JSON", "text/plain", passwordBody, &fakeChange{}, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"too large", "application/json", big, &fakeChange{}, 413, "PAYLOAD_TOO_LARGE"},
		{"failure", "application/json", passwordBody, &fakeChange{err: errors.New("dial tcp 10.0.0.5: refused")}, 500, "INTERNAL_ERROR"},
	}
	for _, c := range cases {
		rec := put(changeHandler(c.svc, io.Discard), bearer(t, "password-change"), c.contentType, c.body, "t-1")
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != c.status || env.Error != c.code || env.TraceID != "t-1" || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
		if c.status < 500 && len(c.svc.requests) != 0 {
			t.Errorf("%s reached the use case", c.name)
		}
	}
}

func TestC_LogsShowNoPasswordEvenForABadBody(t *testing.T) {
	var logs bytes.Buffer
	secret := "Sup3r-Secret-Pass!"
	for _, b := range []string{`{"newPassword":"` + secret + `"}`, `{"newPassword":"` + secret + `","x":1}`, `{"newPassword":"` + secret + `"`} {
		put(changeHandler(&fakeChange{err: errors.New("boom")}, &logs), bearer(t, "password-change"), "application/json", b, "")
		put(changeHandler(&fakeChange{err: changepassword.ErrWeakPassword}, &logs), bearer(t, "password-change"), "application/json", b, "")
	}
	if logs.Len() == 0 || strings.Contains(logs.String(), secret) {
		t.Fatalf("the log must exist and hold no password: %s", logs.String())
	}
}

func TestC_WithoutTheUseCaseTheRouteDoesNotExist(t *testing.T) {
	rec := put(newHandler(newKey(t)), bearer(t, "password-change"), "application/json", passwordBody, "")
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}
