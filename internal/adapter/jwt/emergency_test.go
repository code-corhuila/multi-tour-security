package jwtadapter_test

import (
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// The token of an emergency access is signed and read back like the one of a support access, with its own mark (HU-SEC-007 part B).
func TestC_TheTokenOfAnEmergencyAccessCarriesItsMarkItsScopeAndIsReadBack(t *testing.T) {
	k := key(t)
	c, err := token.Emergency("11111111-1111-4111-8111-111111111111", "tenant-1", []string{"CASH", "SENSITIVE"}, "22222222-2222-4222-8222-222222222222", now.Add(4*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	raw := mustSign(t, k, c)
	body := mustParse(t, raw, k)
	if body["access"] != "emergency" || body["tenantId"] != "tenant-1" || body["authorizationId"] != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("claims = %v", body)
	}
	if scope, _ := body["scope"].([]any); len(scope) != 2 || scope[1] != "SENSITIVE" {
		t.Fatalf("scope = %v", body["scope"])
	}
	got, err := httpadapter.NewVerifier(&k.PublicKey).Verify(raw)
	if err != nil || got.AuthorizationID != "22222222-2222-4222-8222-222222222222" || got.Access != "emergency" || got.TenantID != "tenant-1" {
		t.Fatalf("read back: %+v %v", got, err)
	}
}
