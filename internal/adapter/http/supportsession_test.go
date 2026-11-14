package httpadapter_test

import (
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
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportsession"
	"github.com/golang-jwt/jwt/v5"
)

// HU-SEC-007 part A, security spec 009: the routes where the Platform Administrator takes the token of an approved support access and closes it
// (RN-SEC-009-05, -06).

const (
	sessionBase = "/api/v1/security/platform-support-accesses/" + requestID
	tokenRoute  = sessionBase + "/token"
	closeRoute  = sessionBase + "/closure"
)

type fakeSession struct {
	tokens []supportsession.TokenCommand
	closes []supportsession.CloseCommand
	token  supportsession.Token
	access supportaccess.Access
	err    error
}

func (f *fakeSession) Token(_ context.Context, c supportsession.TokenCommand) (supportsession.Token, error) {
	f.tokens = append(f.tokens, c)
	return f.token, f.err
}

func (f *fakeSession) Close(_ context.Context, c supportsession.CloseCommand) (supportaccess.Access, error) {
	f.closes = append(f.closes, c)
	return f.access, f.err
}

func sessionHandler(svc httpadapter.SupportSessionService, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithSupportSessions(svc))
}

func exceptionalFor(t *testing.T, tenantID, authorizationID string) string {
	t.Helper()
	return sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "worker-event-relay", "roles": []string{"PLATFORM_ADMINISTRATOR"}, "exp": time.Now().Add(time.Hour).Unix(),
		"tenantId": tenantID, "access": "exceptional", "authorizationId": authorizationID})
}

func someToken() supportsession.Token {
	return supportsession.Token{AccessToken: "signed.support.token", ExpiresAt: time.Date(2026, 11, 9, 15, 0, 0, 0, time.UTC), ExpiresIn: 3 * time.Hour,
		Scope: []string{"CASH", "RESERVATIONS"}, AuthorizationID: requestID}
}

func closedAccess() supportaccess.Access {
	a, _ := approvedAccess().Close("The incident is solved", time.Date(2026, 11, 9, 11, 30, 0, 0, time.UTC))
	return a
}

func TestC_ThePlatformAdministratorTakesTheTokenAndTheUseCaseGetsTheCallerAndThePath(t *testing.T) {
	svc := &fakeSession{token: someToken()}
	rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, tokenRoute, platformAdminToken(t), "", "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if len(svc.tokens) != 1 || svc.tokens[0] != (supportsession.TokenCommand{ActorID: "worker-event-relay", ID: requestID, CorrelationID: "sup-1"}) {
		t.Fatalf("the use case got %+v", svc.tokens)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	scope, _ := out["scope"].([]any)
	if out["accessToken"] != "signed.support.token" || out["tokenType"] != "Bearer" || out["expiresIn"] != float64(10800) || out["expiresAt"] != "2026-11-09T15:00:00Z" ||
		out["authorizationId"] != requestID || len(scope) != 2 || scope[0] != "CASH" {
		t.Fatalf("answer = %v", out)
	}
}

func TestC_OnlyTheOrdinarySessionOfThePlatformAdministratorTakesTheTokenNotEvenTheTokenOfTheSameAccess(t *testing.T) {
	tokens := map[string]string{
		"tenant administrator":          tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, tenantOfAdmin, ""),
		"customer":                      tokenWith(t, []string{"FINAL_CUSTOMER"}, tenantOfAdmin, ""),
		"restricted platform":           tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", "restricted"),
		"the token of that same access": exceptionalFor(t, tenantOfAdmin, requestID),
		"service with no role":          tokenWith(t, nil, "", ""),
	}
	for name, token := range tokens {
		svc := &fakeSession{token: someToken()}
		if rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, tokenRoute, token, "", "", ""); rec.Code != http.StatusForbidden || len(svc.tokens) != 0 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if rec := supportCall(sessionHandler(&fakeSession{}, io.Discard), http.MethodPost, tokenRoute, "", "", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
}

func TestC_TheTokenIsAnsweredWithTheCodeOfWhatTheUseCaseRefused(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"not found":   {supportsession.ErrNotFound, http.StatusNotFound, "NOT_FOUND"},
		"not allowed": {supportaccess.ErrInvalidTransition, http.StatusUnprocessableEntity, "INVALID_STATUS_TRANSITION"},
		"our fields":  {&supportsession.FieldError{Field: "actorId", Err: errors.New("is not valid")}, http.StatusInternalServerError, "INTERNAL_ERROR"},
		"a failure":   {errors.New("pq: connection refused at db-host-7"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for name, c := range cases {
		var logs strings.Builder
		svc := &fakeSession{err: c.err}
		rec := supportCall(sessionHandler(svc, &logs), http.MethodPost, tokenRoute, platformAdminToken(t), "", "", "")
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.code) || strings.Contains(rec.Body.String(), "db-host-7") || strings.Contains(logs.String(), "db-host-7") {
			t.Errorf("%s: %d %s / %s", name, rec.Code, rec.Body, logs.String())
		}
	}
}

func TestC_TheTokenOfAnAccessNeverAppearsInALog(t *testing.T) {
	var logs strings.Builder
	svc := &fakeSession{token: someToken()}
	supportCall(sessionHandler(svc, &logs), http.MethodPost, tokenRoute, platformAdminToken(t), "", "", "")
	if strings.Contains(logs.String(), "signed.support.token") {
		t.Fatalf("the token was logged: %s", logs.String())
	}
}

func TestC_TheAdministratorClosesWithTheOrdinarySessionOrWithTheTokenOfThatSameAccess(t *testing.T) {
	for name, token := range map[string]string{
		"the ordinary session":     platformAdminToken(t),
		"the token of that access": exceptionalFor(t, tenantOfAdmin, requestID),
	} {
		svc := &fakeSession{access: closedAccess()}
		rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, closeRoute, token, "application/json", `{"reason":"The incident is solved"}`, "")
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if len(svc.closes) != 1 || svc.closes[0] != (supportsession.CloseCommand{ActorID: "worker-event-relay", ID: requestID, Reason: "The incident is solved", CorrelationID: "sup-1"}) {
			t.Fatalf("%s: the use case got %+v", name, svc.closes)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["status"] != "CLOSED" || out["closedReason"] != "The incident is solved" {
			t.Fatalf("%s: answer = %v %v", name, out, err)
		}
	}
}

func TestC_NoOtherTokenClosesAnAccess(t *testing.T) {
	tokens := map[string]string{
		"the token of ANOTHER access": exceptionalFor(t, tenantOfAdmin, "66666666-6666-4666-8666-666666666666"),
		"tenant administrator":        tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, tenantOfAdmin, ""),
		"customer":                    tokenWith(t, []string{"FINAL_CUSTOMER"}, tenantOfAdmin, ""),
		"restricted platform":         tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", "restricted"),
		"service with no role":        tokenWith(t, nil, "", ""),
	}
	for name, token := range tokens {
		svc := &fakeSession{access: closedAccess()}
		if rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, closeRoute, token, "application/json", `{"reason":"done"}`, ""); rec.Code != http.StatusForbidden || len(svc.closes) != 0 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if rec := supportCall(sessionHandler(&fakeSession{}, io.Discard), http.MethodPost, closeRoute, "", "application/json", `{"reason":"done"}`, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
}

func TestC_TheClosingBodyIsReadStrictlyAndItsRefusalsHaveTheirCodes(t *testing.T) {
	for name, c := range map[string]struct {
		ctype, body string
		status      int
	}{
		"not json":      {"text/plain", `{"reason":"x"}`, http.StatusUnsupportedMediaType},
		"broken":        {"application/json", `{"reason":`, http.StatusBadRequest},
		"unknown field": {"application/json", `{"reason":"x","tenantId":"t"}`, http.StatusBadRequest},
		"not a string":  {"application/json", `{"reason":7}`, http.StatusBadRequest},
		"too large":     {"application/json", `{"reason":"` + strings.Repeat("r", 4200) + `"}`, http.StatusRequestEntityTooLarge},
	} {
		svc := &fakeSession{}
		if rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, closeRoute, platformAdminToken(t), c.ctype, c.body, ""); rec.Code != c.status || len(svc.closes) != 0 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	for name, c := range map[string]struct {
		err    error
		status int
	}{
		"reason":      {&supportsession.FieldError{Field: "reason", Err: errors.New("is not valid")}, http.StatusBadRequest},
		"not found":   {supportsession.ErrNotFound, http.StatusNotFound},
		"not allowed": {supportaccess.ErrInvalidTransition, http.StatusUnprocessableEntity},
		"a failure":   {errors.New("boom"), http.StatusInternalServerError},
	} {
		svc := &fakeSession{err: c.err}
		if rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, closeRoute, platformAdminToken(t), "application/json", `{"reason":"done"}`, ""); rec.Code != c.status {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}
