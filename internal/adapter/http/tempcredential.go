package httpadapter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/code-corhuila/multi-tour-security/internal/core/issuetemp"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// CredentialIssuer is what the route that issues a temporary credential needs from the use case, so a test can replace it.
type CredentialIssuer interface {
	Issue(ctx context.Context, r issuetemp.Request) (port.Registered, error)
}

// WithIssueTemporaryCredential registers the route where an administrator gives a user a new temporary credential (HU-SEC-005).
func WithIssueTemporaryCredential(service CredentialIssuer) Option {
	return func(s *server) { s.credentialIssuer = service }
}

const platformAdministratorRole = "PLATFORM_ADMINISTRATOR"

// issuerRole tells which administrator the credential is: a Tenant Administrator of a tenant, or the Platform Administrator, who has
// none. A temporary or restricted credential is neither, and the use case decides who may issue to whom.
func issuerRole(claims Claims) (string, bool) {
	switch {
	case claims.Access != "":
		return "", false
	case slices.Contains(claims.Roles, tenantAdministratorRole) && claims.TenantID != "":
		return tenantAdministratorRole, true
	case slices.Contains(claims.Roles, platformAdministratorRole) && claims.TenantID == "":
		return platformAdministratorRole, true
	}
	return "", false
}

func (s *server) requireIssuer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		if _, ok := issuerRole(claims); !ok {
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "access denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// credentialBody is the IssueTemporaryCredentialRequest of the contract: the password and its confirmation, and nothing that could
// change the issuer, the tenant or the user.
type credentialBody struct {
	Password             string `json:"password"`
	PasswordConfirmation string `json:"passwordConfirmation"`
}

// issueTemporaryCredential takes the issuer, their role and their tenant from the credential and the user from the path. Who may
// issue to whom is the use case's: the refusal of authority is a business rule (422), not a 403.
func (s *server) issueTemporaryCredential(w http.ResponseWriter, r *http.Request) {
	var body credentialBody
	if !readJSON(w, r, &body) {
		return
	}
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	role, _ := issuerRole(claims)
	reg, err := s.credentialIssuer.Issue(r.Context(), issuetemp.Request{ActorID: claims.Subject, ActorRole: role, ActorTenantID: claims.TenantID,
		AccountID: r.PathValue("accountId"), Password: body.Password, Confirmation: body.PasswordConfirmation, CorrelationID: traceID(r.Context())})
	var invalid *issuetemp.FieldError
	var out accountBody
	if err == nil {
		out, err = toAccountBody(reg)
	}
	switch {
	case errors.As(err, &invalid) && invalid.Field != "actorId":
		writeEnvelope(w, r, http.StatusBadRequest, errorBody{Error: "VALIDATION_ERROR", Message: "the request is not valid",
			Details: []fieldDetail{{Field: invalid.Field, Message: invalid.Err.Error()}}})
	case errors.Is(err, port.ErrUserNotFound):
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the user does not exist")
	case errors.Is(err, issuetemp.ErrNotAuthorized):
		writeError(w, r, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION", "the issuer cannot issue a credential to that user")
	case errors.Is(err, port.ErrNotTemporary):
		writeError(w, r, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION", "the user has no temporary credential to replace: they chose their own password")
	case err != nil:
		// the actor comes from the credential: an id that is not one is our failure. Only the type is logged: a driver error can quote a row
		s.logger.ErrorContext(r.Context(), "issuing a temporary credential failed", "traceId", traceID(r.Context()), "errorType", fmt.Sprintf("%T", err))
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
	default:
		writeJSON(w, http.StatusOK, out)
	}
}
