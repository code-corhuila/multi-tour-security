package httpadapter

import (
	"context"
	"errors"
	"fmt"
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
		case errors.As(err, &invalid) && (invalid.Field == "reason" || invalid.Field == "accountId"):
			writeEnvelope(w, r, http.StatusBadRequest, errorBody{Error: "VALIDATION_ERROR", Message: "the request is not valid",
				Details: []fieldDetail{{Field: invalid.Field, Message: "is not valid"}}})
		case errors.Is(err, port.ErrUserNotFound):
			writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the user does not exist")
		case errors.Is(err, port.ErrStatusTransition):
			writeError(w, r, http.StatusUnprocessableEntity, "INVALID_STATUS_TRANSITION", "the user cannot go to that status from the one it has")
		case err != nil:
			// the tenant and the actor come from the credential: an id that is not one is our failure, not a 400. Only the type is logged
			s.logger.ErrorContext(r.Context(), "changing the status of a user failed", "traceId", traceID(r.Context()), "errorType", fmt.Sprintf("%T", err))
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
		default:
			writeJSON(w, http.StatusOK, out)
		}
	}
}
