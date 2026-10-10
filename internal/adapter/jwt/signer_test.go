package jwtadapter_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"reflect"
	"strings"
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
	parsed := mustParse(t, mustSign(t, k, claims()), k)
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

func equal(a, b any) bool { return reflect.DeepEqual(a, b) }

func mustParse(t *testing.T, raw string, k *rsa.PrivateKey) jwt.MapClaims {
	t.Helper()
	parsed := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, parsed, func(*jwt.Token) (any, error) { return &k.PublicKey, nil }); err != nil {
		t.Fatalf("the token does not parse: %v", err)
	}
	return parsed
}

func mustSign(t *testing.T, k *rsa.PrivateKey, c token.Claims) string {
	t.Helper()
	raw, err := jwtadapter.NewSigner(k).Sign(c)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	return raw
}

func TestC_APlatformTokenHasNoTenantClaimAndARestrictedOneHasTheAccessMark(t *testing.T) {
	k := key(t)
	root := token.Access(account.Account{ID: "root"}, []string{"PLATFORM_ADMINISTRATOR"}, nil, false, now)
	if _, ok := mustParse(t, mustSign(t, k, root), k)["tenantId"]; ok {
		t.Error("the platform token must not carry a tenantId")
	}
	restricted := token.Access(account.Account{ID: "a", TenantID: "t"}, []string{"TENANT_ADMINISTRATOR"}, nil, true, now)
	if got := mustParse(t, mustSign(t, k, restricted), k)["access"]; got != "restricted" {
		t.Errorf("access = %v", got)
	}
}

func TestC_ThePasswordChangeAndTheServiceTokensGoThroughSignAndVerify(t *testing.T) {
	k := key(t)
	verifier := httpadapter.NewVerifier(&k.PublicKey)
	change := mustParse(t, mustSign(t, k, token.PasswordChange(account.Account{ID: "a", TenantID: "t"}, now)), k)
	if change["access"] != "password-change" || !equal(change["roles"], []any{}) {
		t.Errorf("the token of a temporary credential must have no role: %v", change)
	}
	service, err := token.Service("onboard-tenant", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	raw := mustSign(t, k, service)
	if got, err := verifier.Verify(raw); err != nil || got.Subject != "onboard-tenant" {
		t.Fatalf("the verifier refused a service token: %v", err)
	}
	if _, ok := mustParse(t, raw, k)["tenantId"]; ok {
		t.Error("a service token must not carry a tenant")
	}
}

func TestC_RolesAndPermissionsAreEmptyListsInTheSignedTokenAndNeverNull(t *testing.T) {
	k := key(t)
	raw := mustSign(t, k, token.Access(account.Account{ID: "a", TenantID: "t"}, nil, nil, false, now))
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"roles":[]`) || !strings.Contains(string(payload), `"permissions":[]`) {
		t.Fatalf("an empty claim must be [] and not null: %s", payload)
	}
}

func TestC_TheSignedAccessTokenLastsFifteenMinutesAndAnExpiredOneIsRefused(t *testing.T) {
	k := key(t)
	parsed := mustParse(t, mustSign(t, k, claims()), k)
	iat, _ := parsed.GetIssuedAt()
	exp, _ := parsed.GetExpirationTime()
	if exp.Sub(iat.Time) != 15*time.Minute {
		t.Fatalf("exp - iat = %v", exp.Sub(iat.Time))
	}
	old := token.Access(account.Account{ID: "a", TenantID: "t"}, []string{"ANALYST"}, nil, false, time.Now().Add(-time.Hour))
	if _, err := httpadapter.NewVerifier(&k.PublicKey).Verify(mustSign(t, k, old)); err == nil {
		t.Error("an expired token was accepted")
	}
}

func TestC_ASignerRefusesWhatIsNotAToken(t *testing.T) {
	k := key(t)
	for _, c := range []token.Claims{{}, {Issuer: "multi-tour-security", Subject: "a", IssuedAt: now, ExpiresAt: now}} {
		if _, err := jwtadapter.NewSigner(k).Sign(c); err == nil {
			t.Errorf("claims without a subject or a life were signed: %+v", c)
		}
	}
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwtadapter.NewSigner(short).Sign(claims()); err == nil {
		t.Error("a key of 1024 bits signed")
	}
}

func TestC_ATokenWithAnotherAlgorithmOrAnotherKeyIsRefusedByTheVerifier(t *testing.T) {
	k := key(t)
	verifier := httpadapter.NewVerifier(&k.PublicKey)
	other := key(t)
	foreign := mustSign(t, other, claims())
	if _, err := verifier.Verify(foreign); err == nil {
		t.Error("a token signed with another key was accepted")
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "a", "exp": time.Now().Add(time.Hour).Unix()}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(none); err == nil {
		t.Error("an unsigned token was accepted")
	}
	hs, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "a", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(hs); err == nil {
		t.Error("a token signed with HS256 was accepted")
	}
}

func TestC_ASignerWithoutAKeyRefusesToSign(t *testing.T) {
	if _, err := jwtadapter.NewSigner(nil).Sign(claims()); err == nil {
		t.Fatal("a signer with no key signed")
	}
}
