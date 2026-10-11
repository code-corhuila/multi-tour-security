package httpadapter

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// WithCreateFirstAdministrator registers the internal route where the saga onboard-tenant creates the first
// Administrator of a tenant, for a service and nobody else.
func WithCreateFirstAdministrator(service AccountCreator) Option {
	return func(s *server) { s.firstAdmins = service }
}

// uuidPattern is the shape of the tenant id in the path; the store casts it, so nothing else may reach it.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type firstAdministratorBody struct {
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// createFirstAdministrator takes the tenant from the path and never consults its copy: the saga is the authority that
// the tenant exists (the event of job 7 may not have arrived yet). The service that asks is recorded as the actor.
func (s *server) createFirstAdministrator(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenantId")
	if !uuidPattern.MatchString(tenantID) {
		s.answerAccount(w, r, port.Registered{}, false, &createaccount.FieldError{Field: "tenantId", Err: errors.New("is not valid")})
		return
	}
	var body firstAdministratorBody
	if !readJSON(w, r, &body) {
		return
	}
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	reg, created, err := s.firstAdmins.Create(r.Context(), createaccount.Command{
		Kind: createaccount.FirstAdministrator, TenantID: strings.ToLower(tenantID), FullName: body.FullName, Email: body.Email,
		Password: body.Password, Actor: claims.Subject, IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	s.answerAccount(w, r, reg, created, err)
}
