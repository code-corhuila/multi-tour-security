// Package httpadapter is the inbound HTTP adapter: routes, the common error envelope, correlation
// and the token check of the protected routes. The core never imports it.
package httpadapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
)

const correlationHeader = "X-Correlation-Id"

// A correlation id is reused only when it is short and made of safe characters, so a caller
// cannot inject anything into the logs.
var validCorrelationID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type contextKey struct{}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	TraceID string `json:"traceId"`
}

// TokenVerifier is what the adapter needs from the token check, so a test can replace it.
type TokenVerifier interface {
	Verify(raw string) (Claims, error)
}

// New builds the handler of the service. Every route except /health requires a valid token; a new
// route is registered here and wrapped with protect.
func New(verifier TokenVerifier, logger *slog.Logger) http.Handler {
	s := &server{verifier: verifier, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.Handle("/", s.protect(http.HandlerFunc(s.notFound)))
	return s.correlate(mux)
}

type server struct {
	verifier TokenVerifier
	logger   *slog.Logger
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *server) notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the resource does not exist")
}

// protect answers 401 unless the request carries a valid RS256 token.
func (s *server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found {
			writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "authentication is required")
			return
		}
		if _, err := s.verifier.Verify(raw); err != nil {
			// the reason goes to the log with the trace id, never to the caller
			s.logger.WarnContext(r.Context(), "token rejected", "traceId", traceID(r.Context()), "reason", err.Error())
			writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "authentication is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// correlate reuses or generates X-Correlation-Id, returns it, and logs each request with it.
func (s *server) correlate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(correlationHeader)
		if !validCorrelationID.MatchString(id) {
			id = newCorrelationID()
		}
		w.Header().Set(correlationHeader, id)
		ctx := context.WithValue(r.Context(), contextKey{}, id)
		s.logger.InfoContext(ctx, "request", "traceId", id, "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newCorrelationID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails on the supported platforms
	return hex.EncodeToString(b)
}

func traceID(ctx context.Context) string {
	id, _ := ctx.Value(contextKey{}).(string)
	return id
}

// writeError is the only place where an error becomes an HTTP answer.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: code, Message: message, TraceID: traceID(r.Context())})
}
