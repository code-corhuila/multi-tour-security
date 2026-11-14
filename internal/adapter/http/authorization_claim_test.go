package httpadapter_test

import (
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/golang-jwt/jwt/v5"
)

// The authorization claim of the token of a support access (HU-SEC-007 part A): the token of an access needs a tenant and the id of its
// authorization; no other token may carry one; and a claim of another type is refused, like every claim this service reads.
func TestC_TheAuthorizationClaimBelongsToTheTokenOfASupportAccessAndNoOther(t *testing.T) {
	v := httpadapter.NewVerifier(&routeKey.PublicKey)
	in := time.Now().Add(time.Hour).Unix()
	const id = "22222222-2222-4222-8222-222222222222"
	accepted := map[string]jwt.MapClaims{
		"an access":        {"sub": "s", "exp": in, "access": "exceptional", "tenantId": "t-1", "authorizationId": id, "scope": []string{"CASH"}},
		"an ordinary one":  {"sub": "s", "exp": in},
		"a restricted one": {"sub": "s", "exp": in, "access": "restricted", "tenantId": "t-1"},
	}
	for name, body := range accepted {
		got, err := v.Verify(sign(t, jwt.SigningMethodRS256, routeKey, body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if name == "an access" && got.AuthorizationID != id {
			t.Errorf("the authorization was read as %q", got.AuthorizationID)
		}
	}
	refused := map[string]jwt.MapClaims{
		"an access with no authorization":   {"sub": "s", "exp": in, "access": "exceptional", "tenantId": "t-1"},
		"an access with no tenant":          {"sub": "s", "exp": in, "access": "exceptional", "authorizationId": id},
		"an access, authorization not uuid": {"sub": "s", "exp": in, "access": "exceptional", "tenantId": "t-1", "authorizationId": "a b"},
		"an ordinary token with one":        {"sub": "s", "exp": in, "authorizationId": id},
		"a restricted token with one":       {"sub": "s", "exp": in, "access": "restricted", "tenantId": "t-1", "authorizationId": id},
		"not text":                          {"sub": "s", "exp": in, "access": "exceptional", "tenantId": "t-1", "authorizationId": 7},
	}
	for name, body := range refused {
		if _, err := v.Verify(sign(t, jwt.SigningMethodRS256, routeKey, body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
