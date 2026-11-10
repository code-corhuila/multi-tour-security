package httpadapter_test

import (
	"io"
	"net/http"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/golang-jwt/jwt/v5"
)

// HU-SEC-007 part B: the token of an emergency access is read like the one of a support access, and its authorization is the only one it may end.

func TestC_TheEmergencyMarkNeedsATenantAndAnAuthorizationLikeTheOtherMark(t *testing.T) {
	v := httpadapter.NewVerifier(&routeKey.PublicKey)
	in := time.Now().Add(time.Hour).Unix()
	const id = "22222222-2222-4222-8222-222222222222"
	if got, err := v.Verify(sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "s", "exp": in, "access": "emergency", "tenantId": "t-1", "authorizationId": id, "scope": []string{"CASH"}})); err != nil || got.AuthorizationID != id {
		t.Errorf("an emergency token: %+v %v", got, err)
	}
	for name, body := range map[string]jwt.MapClaims{
		"no authorization": {"sub": "s", "exp": in, "access": "emergency", "tenantId": "t-1"},
		"no tenant":        {"sub": "s", "exp": in, "access": "emergency", "authorizationId": id},
		"not a uuid":       {"sub": "s", "exp": in, "access": "emergency", "tenantId": "t-1", "authorizationId": "a b"},
	} {
		if _, err := v.Verify(sign(t, jwt.SigningMethodRS256, routeKey, body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func emergencyFor(t *testing.T, tenantID, authorizationID string) string {
	t.Helper()
	return sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "worker-event-relay", "roles": []string{"PLATFORM_ADMINISTRATOR"}, "exp": time.Now().Add(time.Hour).Unix(),
		"tenantId": tenantID, "access": "emergency", "authorizationId": authorizationID})
}

func TestC_TheTokenOfAnEmergencyAccessClosesItsOwnAccessAndNoOtherAndTakesNoToken(t *testing.T) {
	own := emergencyFor(t, tenantOfAdmin, requestID)
	svc := &fakeSession{access: closedAccess()}
	if rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, closeRoute, own, "application/json", `{"reason":"The incident is solved"}`, ""); rec.Code != http.StatusOK || len(svc.closes) != 1 {
		t.Fatalf("closing its own access: %d %s", rec.Code, rec.Body)
	}
	other := emergencyFor(t, tenantOfAdmin, "99999999-9999-4999-8999-999999999999")
	svc = &fakeSession{access: closedAccess()}
	if rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, closeRoute, other, "application/json", `{"reason":"x"}`, ""); rec.Code != http.StatusForbidden || len(svc.closes) != 0 {
		t.Errorf("closing another access: %d", rec.Code)
	}
	svc = &fakeSession{token: someToken()}
	if rec := supportCall(sessionHandler(svc, io.Discard), http.MethodPost, tokenRoute, own, "", "", ""); rec.Code != http.StatusForbidden || len(svc.tokens) != 0 {
		t.Errorf("taking a token with an emergency token: %d", rec.Code)
	}
}
