package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
)

func TestC_AnIdentifierThatIsNotOneIsA404BeforeAnyLookup(t *testing.T) {
	// a path the mux itself cleans (empty, "..") may redirect: what matters is that nothing is looked up or created
	cases := []struct {
		name, segment string
		answers404    bool
	}{
		{"null byte", "%00", true}, {"upper case", "ABC", true}, {"space", "a%20b", true}, {"dots", "a..b", true},
		{"two characters", "ab", true}, {"forty-one characters", strings.Repeat("a", 41), true},
		{"trailing hyphen", "abc-", true}, {"very long", strings.Repeat("a", 5000), true},
		{"parent directory", "..", false}, {"empty", "", false},
	}
	for _, c := range cases {
		svc, tenants := &fakeCreator{reg: registered(), created: true}, &fakeTenantFinder{found: true}
		rec := postAccount(accountsHandler(svc, tenants, io.Discard), "/api/v1/security/public/tenants/"+c.segment+"/accounts", "application/json", customerBody, accountsKey)
		var env envelope
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if len(tenants.asked) != 0 || len(svc.commands) != 0 || rec.Code == http.StatusCreated || (c.answers404 && (rec.Code != http.StatusNotFound || env.Error != "NOT_FOUND")) {
			t.Errorf("%s: %d %s, looked up %q", c.name, rec.Code, rec.Body, tenants.asked)
		}
	}
	for _, edge := range []string{"abc", strings.Repeat("a", 40), "a-b-c"} {
		tenants := &fakeTenantFinder{found: true}
		postAccount(accountsHandler(&fakeCreator{}, tenants, io.Discard), "/api/v1/security/public/tenants/"+edge+"/accounts", "application/json", customerBody, accountsKey)
		if len(tenants.asked) != 1 {
			t.Errorf("%q is a valid identifier and must be looked up", edge)
		}
	}
}

func TestC_ARepeatWithAMalformedBodyIs400AndWithAValidDifferentBodyIs200(t *testing.T) {
	svc := &fakeCreator{reg: registered()}
	h := accountsHandler(svc, &fakeTenantFinder{found: true}, io.Discard)
	if rec := postAccount(h, accountsRoute, "application/json", `{"firstName":`, accountsKey); rec.Code != http.StatusBadRequest || len(svc.commands) != 0 {
		t.Fatalf("a malformed body is refused before the key is looked at: %d", rec.Code)
	}
	other := strings.Replace(customerBody, "Laura", "Otra", 1)
	if rec := postAccount(h, accountsRoute, "application/json", other, accountsKey); rec.Code != http.StatusOK {
		t.Fatalf("a valid body that differs gets the first account: %d", rec.Code)
	}
}

func TestC_AnUnexpectedFailureLogsNoEmailAndAnUnknownStatusIsA500(t *testing.T) {
	var logs bytes.Buffer
	driver := errors.New(`ERROR: duplicate key value violates unique constraint "uq" (Key (email)=(laura.perez@example.com))`)
	rec := postAccount(accountsHandler(&fakeCreator{err: driver}, &fakeTenantFinder{found: true}, &logs), accountsRoute, "application/json", customerBody, accountsKey)
	if rec.Code != http.StatusInternalServerError || strings.Contains(logs.String(), "laura.perez") || !strings.Contains(logs.String(), "creating an account failed") {
		t.Fatalf("%d, log: %s", rec.Code, logs.String())
	}
	odd := registered()
	odd.Account.Status = account.Status(99)
	rec = postAccount(accountsHandler(&fakeCreator{reg: odd, created: true}, &fakeTenantFinder{found: true}, io.Discard), accountsRoute, "application/json", customerBody, accountsKey)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a status the adapter does not know fails loudly: %d %s", rec.Code, rec.Body)
	}
}
