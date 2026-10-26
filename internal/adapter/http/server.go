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

// claimsKey carries the claims of the verified token to the handler of a protected route.
type claimsKey struct{}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	TraceID string `json:"traceId"`
	// Details names the invalid fields of a 400, never their values.
	Details []fieldDetail `json:"details,omitempty"`
}

type fieldDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// TokenVerifier is what the adapter needs from the token check, so a test can replace it.
type TokenVerifier interface {
	Verify(raw string) (Claims, error)
}

// New builds the handler of the service. Every route except /health and the public routes of an option requires a
// valid token; a new route is registered here and wrapped with protect.
func New(verifier TokenVerifier, logger *slog.Logger, options ...Option) http.Handler {
	s := &server{verifier: verifier, logger: logger}
	for _, option := range options {
		option(s)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	if s.outbox != nil {
		internal := func(h http.HandlerFunc) http.Handler { return s.protect(s.requireService(h)) }
		mux.Handle("GET /api/v1/security/internal/outbox", internal(s.listOutbox))
		mux.Handle("POST /api/v1/security/internal/outbox/{eventId}/published", internal(s.markPublished))
		mux.Handle("POST /api/v1/security/internal/outbox/{eventId}/attempts", internal(s.recordAttempt))
	}
	if s.tenantEvents != nil {
		mux.Handle("POST /api/v1/security/internal/tenants/{tenantId}/events", s.protect(s.requireService(http.HandlerFunc(s.receiveTenantEvent))))
	}
	if s.change != nil {
		mux.Handle("PUT /api/v1/security/sessions/password", s.protect(http.HandlerFunc(s.changePassword)))
	}
	if s.refresh != nil {
		mux.HandleFunc("POST /api/v1/security/public/sessions/refresh", s.renew)
	}
	if s.signIn != nil {
		// public by design: a person who signs in has no token yet
		mux.HandleFunc("POST /api/v1/security/public/tenants/{identifier}/sessions", s.signInTenant)
		mux.HandleFunc("POST /api/v1/security/public/platform/sessions", s.signInPlatform)
	}
	if s.accounts != nil && s.accountTenants != nil {
		// public by design: a person who has no account has no token
		mux.HandleFunc("POST /api/v1/security/public/tenants/{identifier}/accounts", s.createCustomerAccount)
	}
	if s.linkRequester != nil && s.background != nil {
		// public by design: a person who is waiting for a link has no token
		mux.HandleFunc("POST /api/v1/security/public/tenants/{identifier}/email-verifications", s.askForLink)
	}
	if s.firstAdmins != nil {
		mux.Handle("POST /api/v1/security/internal/tenants/{tenantId}/administrators", s.protect(s.requireService(http.HandlerFunc(s.createFirstAdministrator))))
	}
	mux.Handle("/", s.protect(http.HandlerFunc(s.notFound)))
	return s.correlate(mux)
}

type server struct {
	verifier TokenVerifier
	logger   *slog.Logger
	signIn   SignInService
	refresh  RefreshService
	change   ChangePasswordService
	outbox   OutboxService

	tenantEvents   TenantEventService
	accounts       AccountCreator
	accountTenants TenantFinder
	firstAdmins    AccountCreator

	linkRequester LinkRequester
	background    *Background
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
		claims, err := s.verifier.Verify(raw)
		if err != nil {
			// the reason goes to the log with the trace id, never to the caller
			s.logger.WarnContext(r.Context(), "token rejected", "traceId", traceID(r.Context()), "reason", err.Error())
			writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "authentication is required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
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
	writeEnvelope(w, r, status, errorBody{Error: code, Message: message})
}

func writeEnvelope(w http.ResponseWriter, r *http.Request, status int, body errorBody) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	body.TraceID = traceID(r.Context())
	_ = json.NewEncoder(w).Encode(body)
}
