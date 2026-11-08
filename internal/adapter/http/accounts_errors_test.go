package httpadapter_test

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// What a refusal of the registration must never carry, compared in lower case: text of the database driver, a fragment of
// SQL or a path of the source. The answer is the common envelope and the detail goes only to the log (Annex C, norm 5.3).
var internals = []string{"pq:", "pgx", "sqlstate", "select ", "insert ", "security.identity", "/internal/", ".go:", "panic"}

// Issue code-corhuila/multi-tour-docs#586, second criterion: a malformed JSON, an e-mail of 10,000 characters and an e-mail
// with a quote get the common error envelope with no database message, SQL fragment or file path. It checks that nothing
// leaks in the answer; whether a quote can inject SQL is a question for the tests of the store against the real database.
func TestC_ARefusalOfTheRegistrationIsTheCommonEnvelopeAndNeverShowsAnInternalDetail(t *testing.T) {
	const quotedEmail = `laura"perez@example.com`
	quoted := strings.Replace(customerBody, `"email":"Laura.Perez@Example.com"`, `"email":"laura\"perez@example.com"`, 1)
	driver := errors.New(`pq: syntax error at or near "perez" (SQLSTATE 42601) in INSERT INTO security.identity at /app/internal/adapter/postgres/registry.go:88`)
	cases := []struct {
		name, body  string
		failure     error
		status      int
		code        string
		reachesCase bool
	}{
		{"malformed JSON, refused before the use case", `{"email":"laura@example.com","password":`, nil, 400, "VALIDATION_ERROR", false},
		{"an e-mail of 10,000 characters, stopped by the 4 KB limit of the body", strings.Replace(customerBody, "Laura.Perez@Example.com", strings.Repeat("a", 10_000)+"@example.com", 1), nil, 413, "PAYLOAD_TOO_LARGE", false},
		{"an e-mail with a quote that reaches the store and the store fails", quoted, driver, 500, "INTERNAL_ERROR", true},
	}
	for _, c := range cases {
		svc := &fakeCreator{err: c.failure}
		rec := postAccount(accountsHandler(svc, &fakeTenantFinder{found: true}, io.Discard), accountsRoute, "application/json", c.body, accountsKey)
		var env envelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Errorf("%s: %d, the answer is not the envelope: %s", c.name, rec.Code, rec.Body)
			continue
		}
		if rec.Code != c.status || env.Error != c.code || env.Message == "" || env.TraceID != "acc-1" {
			t.Errorf("%s: %d %+v", c.name, rec.Code, env)
		}
		if reached := len(svc.commands) == 1; reached != c.reachesCase {
			t.Errorf("%s: the use case was reached %v, want %v", c.name, reached, c.reachesCase)
		}
		if c.reachesCase && (len(svc.commands) != 1 || !strings.Contains(svc.commands[0].Email, quotedEmail)) {
			t.Errorf("%s: the e-mail with the quote did not reach the store: %+v", c.name, svc.commands)
		}
		body := strings.ToLower(rec.Body.String())
		for _, leak := range internals {
			if strings.Contains(body, leak) {
				t.Errorf("%s: the answer shows %q: %s", c.name, leak, rec.Body)
			}
		}
	}
}
