package httpadapter_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestC_AQueryThatCannotBeReadOrIsWrittenLooselyIsA400(t *testing.T) {
	for _, q := range []string{"?x=%zz", "?page=1;limit=2", "?page=007", "?limit=0020", "?page=+1", "?page=1.0", "?page=%31"} {
		svc := &fakeOutbox{}
		rec := call(outboxHandler(svc, io.Discard), http.MethodGet, outboxRoute+q, serviceBearer(t), "", "", "t-1")
		if q == "?page=%31" {
			// an encoded digit is still the number 1: the query is read, then judged
			if rec.Code != http.StatusOK {
				t.Errorf("%s: %d", q, rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusBadRequest || svc.listed != 0 {
			t.Errorf("%s: %d %s", q, rec.Code, rec.Body)
		}
	}
}

// Every way of not having a valid token is the same 401 on the internal routes, whatever is wrong with the token.
func TestC_EveryKindOfBadTokenIsTheSame401OnTheInternalRoutes(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	other := newKey(t)
	bad := map[string]string{
		"none":                              sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, jwt.MapClaims{"sub": "w", "roles": []string{"SERVICE"}, "exp": exp}),
		"hs256":                             sign(t, jwt.SigningMethodHS256, []byte("shared"), jwt.MapClaims{"sub": "w", "roles": []string{"SERVICE"}, "exp": exp}),
		"expired":                           sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "w", "roles": []string{"SERVICE"}, "exp": time.Now().Add(-time.Hour).Unix()}),
		"foreign key":                       sign(t, jwt.SigningMethodRS256, other, jwt.MapClaims{"sub": "w", "roles": []string{"SERVICE"}, "exp": exp}),
		"no subject":                        sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"roles": []string{"SERVICE"}, "exp": exp}),
		"roles of a number":                 sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "w", "roles": []any{"SERVICE", 5}, "exp": exp}),
		"service with a tenant of a number": sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "w", "roles": []string{"SERVICE"}, "tenantId": 7, "exp": exp}),
		"service with a mark of a list":     sign(t, jwt.SigningMethodRS256, routeKey, jwt.MapClaims{"sub": "w", "roles": []string{"SERVICE"}, "access": []string{"restricted"}, "exp": exp}),
	}
	for _, c := range internalCalls {
		want := ""
		for name, token := range bad {
			svc := &fakeOutbox{event: sampleEvent()}
			rec := call(outboxHandler(svc, io.Discard), c.method, c.path, token, "application/json", c.body, "same")
			var env envelope
			_ = json.Unmarshal(rec.Body.Bytes(), &env)
			if rec.Code != http.StatusUnauthorized || env.Error != "UNAUTHORIZED" || svc.listed+svc.published+svc.attempted != 0 {
				t.Errorf("%s / %s: %d %s", c.name, name, rec.Code, rec.Body)
			}
			if want == "" {
				want = rec.Body.String()
			} else if rec.Body.String() != want {
				t.Errorf("%s / %s answered another body", c.name, name)
			}
		}
	}
}
