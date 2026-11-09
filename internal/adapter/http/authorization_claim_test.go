package httpadapter_test

import (
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/golang-jwt/jwt/v5"
)

// The authorization claim of the token of a support access (HU-SEC-007 part A): read as text, absent for any other token, and refused when
// it has another type, like every claim this service reads.
func TestC_AMalformedAuthorizationClaimIsRefusedAndAnAbsentOneIsEmpty(t *testing.T) {
	v := httpadapter.NewVerifier(&routeKey.PublicKey)
	in := time.Now().Add(time.Hour).Unix()
	good := sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "s", "exp": in, "authorizationId": "a-1"})
	if got, err := v.Verify(good); err != nil || got.AuthorizationID != "a-1" {
		t.Fatalf("%+v %v", got, err)
	}
	none := sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "s", "exp": in})
	if got, err := v.Verify(none); err != nil || got.AuthorizationID != "" {
		t.Fatalf("%+v %v", got, err)
	}
	bad := sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "s", "exp": in, "authorizationId": 7})
	if _, err := v.Verify(bad); err == nil {
		t.Fatal("an authorization claim that is not text was accepted")
	}
}
