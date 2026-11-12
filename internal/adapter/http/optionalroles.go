package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/optionalrole"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// OptionalRoleManager is what the routes of the optional roles need from the use case, so a test can replace it.
type OptionalRoleManager interface {
	List(ctx context.Context, q optionalrole.Query) ([]port.OptionalRoleState, error)
	Enable(ctx context.Context, r optionalrole.Request) (port.OptionalRoleState, error)
	Disable(ctx context.Context, r optionalrole.Request) (port.OptionalRoleState, error)
}

// WithOptionalRoles registers the routes where a Tenant Administrator sees, enables and disables the optional roles of their own tenant
// (HU-SEC-006).
func WithOptionalRoles(service OptionalRoleManager) Option {
	return func(s *server) { s.optionalRoles = service }
}

// optionalRoleBody is the OptionalRoleState of the contract. A role that never changed shows no change.
type optionalRoleBody struct {
	Role      string     `json:"role"`
	Enabled   bool       `json:"enabled"`
	ChangedAt *time.Time `json:"changedAt,omitempty"`
	ChangedBy string     `json:"changedBy,omitempty"`
}

func toOptionalRoleBody(st port.OptionalRoleState) optionalRoleBody {
	body := optionalRoleBody{Role: st.Role, Enabled: st.Enabled, ChangedBy: st.ChangedBy}
	if !st.ChangedAt.IsZero() {
		at := st.ChangedAt.UTC()
		body.ChangedAt = &at
	}
	return body
}

// listOptionalRoles answers the three roles of the tenant of the credential. It takes no parameter: the tenant is the token's.
func (s *server) listOptionalRoles(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	states, err := s.optionalRoles.List(r.Context(), optionalrole.Query{TenantID: claims.TenantID})
	if err != nil {
		s.failOptionalRole(w, r, "listing the optional roles", err)
		return
	}
	data := make([]optionalRoleBody, 0, len(states))
	for _, st := range states {
		data = append(data, toOptionalRoleBody(st))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

// changeOptionalRole takes the tenant and the actor from the credential and the role from the path; it reads no body, so nothing in the
// request can name another tenant, another actor or a role that the path does not.
func (s *server) changeOptionalRole(change func(context.Context, optionalrole.Request) (port.OptionalRoleState, error), what string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		st, err := change(r.Context(), optionalrole.Request{TenantID: claims.TenantID, ActorID: claims.Subject, Role: r.PathValue("role"),
			CorrelationID: traceID(r.Context())})
		if err != nil {
			s.failOptionalRole(w, r, what, err)
			return
		}
		writeJSON(w, http.StatusOK, toOptionalRoleBody(st))
	}
}

// failOptionalRole answers each refusal of the use case or of its store with its own status.
func (s *server) failOptionalRole(w http.ResponseWriter, r *http.Request, what string, err error) {
	var invalid *optionalrole.FieldError
	switch {
	case errors.As(err, &invalid) && callerField(invalid):
		refuseField(w, r, invalid)
	case errors.Is(err, port.ErrStatusTransition):
		refuseTransition(w, r, "the optional role is already in that state")
	case errors.Is(err, port.ErrRoleInUse):
		refuseRule(w, r, "an active user of the tenant holds the role")
	default:
		s.fail(w, r, what, err)
	}
}
