package jwtadapter_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	jwtadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/jwt"
	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
	"github.com/golang-jwt/jwt/v5"
)

var now = time.Now().UTC().Truncate(time.Second)

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func claims() token.Claims {
	a := account.Account{ID: "account-1", TenantID: "tenant-1"}
	return token.Access(a, []string{"TENANT_ADMINISTRATOR"}, []string{"CASH"}, false, now)
}

func TestC_ASignedTokenIsAcceptedByTheVerifierThatEveryServiceUses(t *testing.T) {
	k := key(t)
	raw, err := jwtadapter.NewSigner(k).Sign(claims())
	if err != nil {
		t.Fatal(err)
	}
	got, err := httpadapter.NewVerifier(&k.PublicKey).Verify(raw)
	if err != nil || got.Subject != "account-1" {
		t.Fatalf("the verifier refused a token of the signer: %v %+v", err, got)
	}
}

func TestC_TheTokenCarriesEveryClaimOfTheSpec(t *testing.T) {
	k := key(t)
	raw, err := jwtadapter.NewSigner(k).Sign(claims())
	if err != nil {
		t.Fatal(err)
	}
	parsed := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, parsed, func(*jwt.Token) (any, error) { return &k.PublicKey, nil }); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]any{"iss": "multi-tour-security", "aud": []any{"multi-tour"}, "sub": "account-1", "tenantId": "tenant-1"} {
		if got := parsed[name]; !equal(got, want) {
			t.Errorf("claim %s is %v, want %v", name, got, want)
		}
	}
	for _, name := range []string{"iat", "nbf", "exp", "roles", "permissions"} {
		if _, ok := parsed[name]; !ok {
			t.Errorf("claim %s is missing", name)
		}
	}
	if _, ok := parsed["access"]; ok {
		t.Error("an ordinary token must not carry an access mark")
	}
}

func equal(a, b any) bool {
	switch want := b.(type) {
	case []any:
		got, ok := a.([]any)
		return ok && len(got) == len(want) && (len(want) == 0 || got[0] == want[0])
	default:
		return a == b
	}
}

func TestC_APlatformTokenHasNoTenantClaimAndARestrictedOneHasTheAccessMark(t *testing.T) {
	k := key(t)
	signer := jwtadapter.NewSigner(k)
	root := token.Access(account.Account{ID: "root"}, []string{"PLATFORM_ADMINISTRATOR"}, nil, false, now)
	raw, _ := signer.Sign(root)
	parsed := jwt.MapClaims{}
	_, _ = jwt.ParseWithClaims(raw, parsed, func(*jwt.Token) (any, error) { return &k.PublicKey, nil })
	if _, ok := parsed["tenantId"]; ok {
		t.Error("the platform token must not carry a tenantId")
	}
	restricted := token.Access(account.Account{ID: "a", TenantID: "t"}, []string{"TENANT_ADMINISTRATOR"}, nil, true, now)
	raw, _ = signer.Sign(restricted)
	parsed = jwt.MapClaims{}
	_, _ = jwt.ParseWithClaims(raw, parsed, func(*jwt.Token) (any, error) { return &k.PublicKey, nil })
	if parsed["access"] != "restricted" {
		t.Errorf("access = %v", parsed["access"])
	}
}

func TestC_ATokenWithAnotherAlgorithmOrAnotherKeyIsRefusedByTheVerifier(t *testing.T) {
	k := key(t)
	verifier := httpadapter.NewVerifier(&k.PublicKey)
	other := key(t)
	foreign, _ := jwtadapter.NewSigner(other).Sign(claims())
	if _, err := verifier.Verify(foreign); err == nil {
		t.Error("a token signed with another key was accepted")
	}
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "a", "exp": time.Now().Add(time.Hour).Unix()}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := verifier.Verify(none); err == nil {
		t.Error("an unsigned token was accepted")
	}
	hs, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "a", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("secret"))
	if _, err := verifier.Verify(hs); err == nil {
		t.Error("a token signed with HS256 was accepted")
	}
}

func TestC_ASignerWithoutAKeyRefusesToSign(t *testing.T) {
	if _, err := jwtadapter.NewSigner(nil).Sign(claims()); err == nil {
		t.Fatal("a signer with no key signed")
	}
}
