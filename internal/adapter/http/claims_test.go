package httpadapter_test

import (
	"net/http"
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
		{"values that are not strings", jwt.MapClaims{"sub": "a", "exp": exp, "tenantId": 7, "access": []string{"password-change"}}, httpadapter.Claims{Subject: "a"}},
	}
	for _, c := range cases {
		got, err := verifier.Verify(sign(t, jwt.SigningMethodRS256, key, c.claims))
		if err != nil || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.name, got, err, c.want)
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
