package httpadapter_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
)

const protectedPath = "/api/v1/security/accounts"

type envelope struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	TraceID string `json:"traceId"`
}

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newHandler(key *rsa.PrivateKey) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&key.PublicKey), slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

func sign(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func get(h http.Handler, path, token, correlationID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if correlationID != "" {
		req.Header.Set("X-Correlation-Id", correlationID)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var body envelope
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("the body is not the common envelope: %v", err)
	}
	return body
}

func TestC_HealthAnswersWithoutToken(t *testing.T) {
	rec := get(newHandler(newKey(t)), "/health", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestC_ProtectedRouteWithoutTokenAnswers401(t *testing.T) {
	rec := get(newHandler(newKey(t)), protectedPath, "", "")
	body := decode(t, rec)
	if rec.Code != http.StatusUnauthorized || body.Error != "UNAUTHORIZED" {
		t.Fatalf("got %d %q, want 401 UNAUTHORIZED", rec.Code, body.Error)
	}
	if body.TraceID == "" || body.TraceID != rec.Header().Get("X-Correlation-Id") {
		t.Fatalf("traceId %q must be the correlation id %q", body.TraceID, rec.Header().Get("X-Correlation-Id"))
	}
}

func TestC_UnknownRouteWithValidTokenAnswersTheEnvelope(t *testing.T) {
	key := newKey(t)
	token := sign(t, jwt.SigningMethodRS256, key, jwt.MapClaims{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()})
	rec := get(newHandler(key), protectedPath, token, "")
	if body := decode(t, rec); rec.Code != http.StatusNotFound || body.Error != "NOT_FOUND" {
		t.Fatalf("got %d %q, want 404 NOT_FOUND", rec.Code, body.Error)
	}
}

func TestC_CorrelationIdIsReusedOrGenerated(t *testing.T) {
	h := newHandler(newKey(t))
	if got := get(h, "/health", "", "abc-123").Header().Get("X-Correlation-Id"); got != "abc-123" {
		t.Fatalf("a valid id must be reused, got %q", got)
	}
	if got := get(h, "/health", "", "").Header().Get("X-Correlation-Id"); got == "" {
		t.Fatal("a missing id must be generated")
	}
}

func TestC_InvalidTokensAreRejected(t *testing.T) {
	key := newKey(t)
	future := time.Now().Add(time.Hour).Unix()
	cases := map[string]string{
		"alg_none":    sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, jwt.MapClaims{"sub": "u1", "exp": future}),
		"alg_hs256":   sign(t, jwt.SigningMethodHS256, []byte("shared-secret"), jwt.MapClaims{"sub": "u1", "exp": future}),
		"without_sub": sign(t, jwt.SigningMethodRS256, key, jwt.MapClaims{"exp": future}),
		"without_exp": sign(t, jwt.SigningMethodRS256, key, jwt.MapClaims{"sub": "u1"}),
		"expired":     sign(t, jwt.SigningMethodRS256, key, jwt.MapClaims{"sub": "u1", "exp": time.Now().Add(-time.Hour).Unix()}),
		"foreign_key": sign(t, jwt.SigningMethodRS256, newKey(t), jwt.MapClaims{"sub": "u1", "exp": future}),
		"not_a_token": "not-a-jwt",
	}
	h := newHandler(key)
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			rec := get(h, protectedPath, token, "")
			if body := decode(t, rec); rec.Code != http.StatusUnauthorized || body.Error != "UNAUTHORIZED" {
				t.Fatalf("got %d %q, want 401 UNAUTHORIZED", rec.Code, body.Error)
			}
		})
	}
}
