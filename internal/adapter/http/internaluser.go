package httpadapter

import (
	"net/http"
	"slices"

	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
)

// WithCreateInternalUser registers the route where a Tenant Administrator registers a user of their own tenant
// (HU-SEC-005). The service is the same use case that makes the other accounts, asked for the kind InternalUser.
func WithCreateInternalUser(service AccountCreator) Option {
	return func(s *server) { s.internalUsers = service }
}

const tenantAdministratorRole = "TENANT_ADMINISTRATOR"

// requireTenantAdministrator lets in the credential of an Administrator of a tenant and nothing else: the role in the
// token, a tenant, and no access mark, which a temporary or a restricted credential carries (spec 003, RN-SEC-003-01).
// The role is read from the token, not from the database: the token already proves it for its 15 minutes.
func (s *server) requireTenantAdministrator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		if !slices.Contains(claims.Roles, tenantAdministratorRole) || claims.TenantID == "" || claims.Access != "" {
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "access denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// internalUserBody is the CreateInternalUserRequest of the contract. It has no field for a tenant, an actor or a list of
// roles, and the reader refuses any field it does not name, so nothing in the body can change who is asking or where.
type internalUserBody struct {
	FullName             string `json:"fullName"`
	Email                string `json:"email"`
	Role                 string `json:"role"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"passwordConfirmation"`
}

// createInternalUser takes the tenant and the actor from the credential. A missing field arrives empty and the use case
// refuses it by name, so the rules of the fields live in one place.
func (s *server) createInternalUser(w http.ResponseWriter, r *http.Request) {
	var body internalUserBody
	if !readJSON(w, r, &body) {
		return
	}
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	reg, created, err := s.internalUsers.Create(r.Context(), createaccount.Command{
		Kind: createaccount.InternalUser, TenantID: claims.TenantID, FullName: body.FullName, Email: body.Email, Role: body.Role,
		Password: body.Password, Confirmation: body.PasswordConfirmation, Actor: claims.Subject,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	s.answerAccount(w, r, reg, created, err)
}

// takenMessage says whose a taken e-mail is, in words that never include the e-mail itself.
func takenMessage(reason createaccount.TakenReason) string {
	switch reason {
	case createaccount.TakenByInactiveInternalUser:
		return "belongs to an inactive internal user, who can be reactivated"
	case createaccount.TakenByCustomer:
		return "belongs to a customer account of this tenant"
	case createaccount.TakenByInternalUser:
		return "already in use by an internal user of this tenant"
	default:
		return "already in use in this tenant"
	}
}
