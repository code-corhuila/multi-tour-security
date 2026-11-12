package httpadapter

import (
	"context"
	"errors"
	"net/http"

	"github.com/code-corhuila/multi-tour-security/internal/core/changestatus"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// UserStatusChanger is what the routes that inactivate and reactivate need from the use case, so a test can replace it.
type UserStatusChanger interface {
	Inactivate(ctx context.Context, r changestatus.Request) (port.Registered, error)
	Reactivate(ctx context.Context, r changestatus.Request) (port.Registered, error)
}

// WithChangeUserStatus registers the routes where a Tenant Administrator inactivates and reactivates a user of their own tenant
// (HU-SEC-005).
func WithChangeUserStatus(service UserStatusChanger) Option {
	return func(s *server) { s.userStatus = service }
}

// statusBody is the StatusChangeRequest of the contract: the reason and nothing else, so nothing in the body can change the
// tenant, the actor or the status that the route decides.
type statusBody struct {
	Reason string `json:"reason"`
}

// changeStatus takes the tenant and the actor from the credential and the user from the path.
func (s *server) changeStatus(change func(context.Context, changestatus.Request) (port.Registered, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body statusBody
		if !readJSON(w, r, &body) {
			return
		}
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		reg, err := change(r.Context(), changestatus.Request{TenantID: claims.TenantID, AccountID: r.PathValue("accountId"), ActorID: claims.Subject,
			Reason: body.Reason, CorrelationID: traceID(r.Context())})
		var invalid *changestatus.FieldError
		var out accountBody
		if err == nil {
			out, err = toAccountBody(reg)
		}
		switch {
		case errors.As(err, &invalid) && callerField(invalid):
			refuseField(w, r, invalid)
		case errors.Is(err, port.ErrUserNotFound):
			refuseNoUser(w, r)
		case errors.Is(err, port.ErrLastAdministrator):
			refuseRule(w, r, "the last active administrator of the tenant cannot be inactivated")
		case errors.Is(err, port.ErrStatusTransition):
			writeError(w, r, http.StatusUnprocessableEntity, "INVALID_STATUS_TRANSITION", "the user cannot go to that status from the one it has")
		case err != nil:
			s.fail(w, r, "changing the status of a user", err)
		default:
			writeJSON(w, http.StatusOK, out)
		}
	}
}
