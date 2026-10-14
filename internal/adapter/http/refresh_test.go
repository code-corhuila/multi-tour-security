package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
)

const refreshRoute = "/api/v1/security/public/sessions/refresh"

var refreshBody = `{"refreshToken":"` + strings.Repeat("r", 43) + `"}`

type fakeRefresh struct {
	values []string
	tokens signin.Tokens
	err    error
}

func (f *fakeRefresh) Renew(_ context.Context, value string) (signin.Tokens, error) {
	f.values = append(f.values, value)
	return f.tokens, f.err
}

func refreshHandler(svc httpadapter.RefreshService, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithRefresh(svc))
}

func TestC_ARenewalAnswers200WithTheNewPairAndForbidsCaching(t *testing.T) {
	svc := &fakeRefresh{tokens: signin.Tokens{AccessToken: "new.access.jwt", RefreshToken: "next-value", ExpiresIn: 15 * time.Minute}}
	rec := post(refreshHandler(svc, io.Discard), refreshRoute, "application/json", refreshBody, "trace-r")
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("%d %s %v", rec.Code, rec.Body, err)
	}
	if got["accessToken"] != "new.access.jwt" || got["refreshToken"] != "next-value" || got["tokenType"] != "Bearer" || got["expiresIn"] != float64(900) || len(got) != 4 {
		t.Fatalf("body = %v", got)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") != "trace-r" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if len(svc.values) != 1 || svc.values[0] != strings.Repeat("r", 43) {
		t.Fatalf("the use case got %v", svc.values)
	}
}

func TestC_EveryRefusalOfARenewalIsTheSame401AndNeedsNoToken(t *testing.T) {
	bodies := map[string]bool{}
	for _, err := range []error{signin.ErrRefused, errors.Join(signin.ErrRefused, errors.New("reused"))} {
		rec := post(refreshHandler(&fakeRefresh{err: err}, io.Discard), refreshRoute, "application/json", refreshBody, "same-trace")
		var env envelope
		if e := json.Unmarshal(rec.Body.Bytes(), &env); e != nil || rec.Code != http.StatusUnauthorized || env.Error != "UNAUTHORIZED" ||
			rec.Header().Get("WWW-Authenticate") != "Bearer" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %s %v", rec.Code, rec.Body, rec.Header())
		}
		bodies[rec.Body.String()] = true
	}
	if len(bodies) != 1 {
		t.Fatalf("one and the same body whatever the cause, got %v", bodies)
	}
}

func TestC_ARenewalRequestThatIsNotOneIsA400A415A413Or500AndRefusesNothingElse(t *testing.T) {
	big := `{"refreshToken":"` + strings.Repeat("r", 4200) + `"}`
	cases := []struct {
		name, contentType, body string
		svc                     *fakeRefresh
		status                  int
		code                    string
	}{
		{"bad JSON", "application/json", `{"refreshToken":`, &fakeRefresh{}, 400, "VALIDATION_ERROR"},
		{"missing field", "application/json", `{}`, &fakeRefresh{}, 400, "VALIDATION_ERROR"},
		{"unknown field", "application/json", `{"refreshToken":"x","a":1}`, &fakeRefresh{}, 400, "VALIDATION_ERROR"},
		{"wrong type", "application/json", `{"refreshToken":12}`, &fakeRefresh{}, 400, "VALIDATION_ERROR"},
		{"invalid for the use case", "application/json", refreshBody, &fakeRefresh{err: signin.ErrInvalidRequest}, 400, "VALIDATION_ERROR"},
		{"not JSON", "text/plain", refreshBody, &fakeRefresh{}, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"too large", "application/json", big, &fakeRefresh{}, 413, "PAYLOAD_TOO_LARGE"},
		{"failure", "application/json", refreshBody, &fakeRefresh{err: errors.New("dial tcp 10.0.0.5: refused")}, 500, "INTERNAL_ERROR"},
	}
	for _, c := range cases {
		rec := post(refreshHandler(c.svc, io.Discard), refreshRoute, c.contentType, c.body, "t-1")
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != c.status || env.Error != c.code || env.TraceID != "t-1" || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
		if c.status == 400 || c.status == 413 || c.status == 415 {
			if c.name != "invalid for the use case" && len(c.svc.values) != 0 {
				t.Errorf("%s reached the use case", c.name)
			}
		}
	}
}

func TestC_LogsShowNoRenewalValueEvenForABadBody(t *testing.T) {
	var logs bytes.Buffer
	secret := "renewal-value-that-must-not-be-logged"
	for _, b := range []string{`{"refreshToken":"` + secret + `"}`, `{"refreshToken":"` + secret + `","x":1}`, `{"refreshToken":"` + secret + `"`} {
		post(refreshHandler(&fakeRefresh{err: errors.New("boom")}, &logs), refreshRoute, "application/json", b, "")
		post(refreshHandler(&fakeRefresh{err: signin.ErrRefused}, &logs), refreshRoute, "application/json", b, "")
	}
	if logs.Len() == 0 || strings.Contains(logs.String(), secret) {
		t.Fatalf("the log must exist and hold no value: %s", logs.String())
	}
}

func TestC_WithoutTheRenewalUseCaseTheRouteDoesNotExist(t *testing.T) {
	if rec := post(newHandler(newKey(t)), refreshRoute, "application/json", refreshBody, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("it is just another protected path, got %d", rec.Code)
	}
}
