package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportsession"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// SupportSessionService is what the routes of the token of a support access need from the use case, so a test can replace it.
type SupportSessionService interface {
	Token(ctx context.Context, c supportsession.TokenCommand) (supportsession.Token, error)
	Close(ctx context.Context, c supportsession.CloseCommand) (supportaccess.Access, error)
}

// WithSupportSessions registers the routes where the Platform Administrator takes the token of an approved support access and closes it
// (HU-SEC-007 part A).
func WithSupportSessions(service SupportSessionService) Option {
	return func(s *server) { s.supportSessions = service }
}

// requirePlatformAdministratorOrItsAccess lets in what requirePlatformAdministrator lets in and also the token of the very access that is being
// closed: it carries the role, a tenant, the mark `exceptional` or `emergency` and the id of its authorization, and that id must be the one of the path, so
// a token ends its own access and no other (the contract of closeSupportAccess).
func (s *server) requirePlatformAdministratorOrItsAccess(next http.Handler) http.Handler {
	ordinary := s.requirePlatformAdministrator(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		if slices.Contains(claims.Roles, account.RolePlatformAdministrator) && claims.TenantID != "" &&
			token.IsSupportAccess(claims.Access) && claims.AuthorizationID == r.PathValue("supportAccessId") {
			next.ServeHTTP(w, r)
			return
		}
		ordinary.ServeHTTP(w, r)
	})
}

// supportTokenBody is the SupportAccessToken of the contract.
type supportTokenBody struct {
	AccessToken     string   `json:"accessToken"`
	TokenType       string   `json:"tokenType"`
	ExpiresIn       int      `json:"expiresIn"`
	ExpiresAt       string   `json:"expiresAt"`
	Scope           []string `json:"scope"`
	AuthorizationID string   `json:"authorizationId"`
}

// refuseSession answers what the use case refused. The actor and the correlation id come from the credential and the request, so a fault in
// them is ours; only the reason is the caller's.
func (s *server) refuseSession(w http.ResponseWriter, r *http.Request, what string, err error) {
	var invalid *supportsession.FieldError
	switch {
	case errors.As(err, &invalid) && invalid.Field == "reason":
		refuseField(w, r, invalid)
	case errors.Is(err, supportsession.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the support access does not exist")
	case errors.Is(err, supportaccess.ErrInvalidTransition):
		refuseTransition(w, r, "the support access does not allow it now")
	default:
		s.fail(w, r, what, err)
	}
}

// takeSupportAccessToken gives the token of an approved access. The caller and the access come from the credential and the path.
func (s *server) takeSupportAccessToken(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	given, err := s.supportSessions.Token(r.Context(), supportsession.TokenCommand{
		ActorID: claims.Subject, ID: r.PathValue("supportAccessId"), CorrelationID: traceID(r.Context()),
	})
	if err != nil {
		s.refuseSession(w, r, "taking the token of a support access", err)
		return
	}
	writeJSON(w, http.StatusOK, supportTokenBody{
		AccessToken: given.AccessToken, TokenType: "Bearer", ExpiresIn: int(given.ExpiresIn.Seconds()), ExpiresAt: instant(given.ExpiresAt),
		Scope: given.Scope, AuthorizationID: given.AuthorizationID,
	})
}

// closeSupportAccess ends an access before its time; the body is the reason and nothing else.
func (s *server) closeSupportAccess(w http.ResponseWriter, r *http.Request) {
	var body supportRejectionBody
	if !readJSON(w, r, &body) {
		return
	}
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	closed, err := s.supportSessions.Close(r.Context(), supportsession.CloseCommand{
		ActorID: claims.Subject, ID: r.PathValue("supportAccessId"), Reason: body.Reason, CorrelationID: traceID(r.Context()),
	})
	if err != nil {
		s.refuseSession(w, r, "closing a support access", err)
		return
	}
	writeJSON(w, http.StatusOK, toSupportAccessBody(closed))
}
