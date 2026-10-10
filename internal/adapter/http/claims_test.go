package httpadapter_test

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/golang-jwt/jwt/v5"
)

func TestC_TheVerifierReadsTheTenantAndTheAccessMarkAndNothingElseGivesThemPower(t *testing.T) {
	key := newKey(t)
	verifier := httpadapter.NewVerifier(&key.PublicKey)
	exp := time.Now().Add(time.Hour).Unix()
	cases := []struct {
		name   string
		claims jwt.MapClaims
		want   httpadapter.Claims
	}{
		{"ordinary", jwt.MapClaims{"sub": "a", "exp": exp, "tenantId": "t-1"}, httpadapter.Claims{Subject: "a", TenantID: "t-1"}},
		{"password change", jwt.MapClaims{"sub": "a", "exp": exp, "tenantId": "t-1", "access": "password-change"}, httpadapter.Claims{Subject: "a", TenantID: "t-1", Access: "password-change"}},
		{"platform", jwt.MapClaims{"sub": "root", "exp": exp}, httpadapter.Claims{Subject: "root"}},
		{"a service", jwt.MapClaims{"sub": "w", "exp": exp, "roles": []string{"SERVICE"}}, httpadapter.Claims{Subject: "w", Roles: []string{"SERVICE"}}},
		{"null claims are absent ones", jwt.MapClaims{"sub": "a", "exp": exp, "tenantId": nil, "access": nil, "roles": nil}, httpadapter.Claims{Subject: "a"}},
	}
	for _, c := range cases {
		got, err := verifier.Verify(sign(t, jwt.SigningMethodRS256, key, c.claims))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
}

// Fail closed: a claim with the wrong type is not an absent claim. Reading it as absent would let a token that carries a
// tenant or an access mark pass as one that carries none.
func TestC_AClaimWithTheWrongTypeMakesTheTokenUnacceptable(t *testing.T) {
	key := newKey(t)
	verifier := httpadapter.NewVerifier(&key.PublicKey)
	exp := time.Now().Add(time.Hour).Unix()
	for name, extra := range map[string]jwt.MapClaims{
		"tenant that is a number":   {"tenantId": 7},
		"tenant that is a list":     {"tenantId": []string{"t"}},
		"access that is a number":   {"access": 123},
		"access that is a list":     {"access": []string{"password-change"}},
		"roles that is a string":    {"roles": "SERVICE"},
		"roles with a number in it": {"roles": []any{"SERVICE", 5}},
		"roles with a null in it":   {"roles": []any{"SERVICE", nil}},
		"roles that is an object":   {"roles": map[string]any{"SERVICE": true}},
	} {
		claims := jwt.MapClaims{"sub": "w", "exp": exp}
		for k, v := range extra {
			claims[k] = v
		}
		if got, err := verifier.Verify(sign(t, jwt.SigningMethodRS256, key, claims)); err == nil {
			t.Errorf("%s: the token was accepted as %+v", name, got)
		}
	}
}

func TestC_ATokenOfPasswordChangeOnAnUnknownRouteGetsTheAnswerOfAnyOtherToken(t *testing.T) {
	key := newKey(t)
	token := sign(t, jwt.SigningMethodRS256, key, jwt.MapClaims{"sub": "a", "exp": time.Now().Add(time.Hour).Unix(), "access": "password-change"})
	rec := get(newHandler(key), protectedPath, token, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the mark gives no extra reach: %d", rec.Code)
	}
}
