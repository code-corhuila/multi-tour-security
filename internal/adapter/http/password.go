package httpadapter

import (
	"context"
	"errors"
	"net/http"

	"github.com/code-corhuila/multi-tour-security/internal/core/changepassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// ChangePasswordService is what the route needs from its use case, so a test can replace it.
type ChangePasswordService interface {
	Change(ctx context.Context, r changepassword.Request) error
}

// WithChangePassword registers the route where a temporary credential chooses its password. Unlike the public routes it
// asks for a token, and for one kind only.
func WithChangePassword(service ChangePasswordService) Option {
	return func(s *server) { s.change = service }
}

type changePasswordBody struct {
	NewPassword *string `json:"newPassword"`
}

// changePassword accepts only the token a temporary credential gets (access: password-change): any other token, an
// ordinary or a restricted one, is told what a missing token is told.
func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	if claims.Access != token.PasswordChangeAccess {
		writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "authentication is required")
		return
	}
	var body changePasswordBody
	if !readJSON(w, r, &body) {
		return
	}
	if body.NewPassword == nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with a newPassword")
		return
	}
	err := s.change.Change(r.Context(), changepassword.Request{
		AccountID: claims.Subject, TenantID: claims.TenantID, NewPassword: *body.NewPassword, CorrelationID: traceID(r.Context()),
	})
	switch {
	case err == nil:
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, signin.ErrRefused):
		writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "authentication failed")
	case errors.Is(err, changepassword.ErrWeakPassword):
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the password does not meet the policy")
	default:
		s.logger.ErrorContext(r.Context(), "change of password failed", "traceId", traceID(r.Context()), "reason", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
	}
}
