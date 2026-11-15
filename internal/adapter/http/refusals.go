package httpadapter

import (
	"fmt"
	"net/http"

	"github.com/code-corhuila/multi-tour-security/internal/core/validate"
)

// The answers that more than one route gives to a refusal of its use case, written once: the field that the caller can correct,
// the user that is not there and the failure of ours.

// callerField tells whether the field of a refusal is one that the caller can correct. The tenant and the actor come from the
// credential, never from the request, so a refusal that names them is our failure and not a 400.
func callerField(f *validate.FieldError) bool { return f.Field != "tenantId" && f.Field != "actorId" }

// refuseField answers a 400 that names the field and says what is wrong with it, never its value.
func refuseField(w http.ResponseWriter, r *http.Request, f *validate.FieldError) {
	writeEnvelope(w, r, http.StatusBadRequest, errorBody{Error: "VALIDATION_ERROR", Message: "the request is not valid",
		Details: []fieldDetail{{Field: f.Field, Message: f.Reason()}}})
}

// refuseNoUser answers the 404 of a user that is not in the tenant of the credential, or not there at all.
func refuseNoUser(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the user does not exist")
}

// refuseRule answers a 422 that breaks a business rule.
func refuseRule(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION", message)
}

// refuseTransition answers the 422 of a change that the state of the thing does not allow, which the clients tell from a business rule.
func refuseTransition(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusUnprocessableEntity, "INVALID_STATUS_TRANSITION", message)
}

// fail answers the 500 of a failure of ours. The log gets the trace id and, of the cause, only its type: the text of a driver
// error can quote the row that failed, and nothing of it reaches the caller.
func (s *server) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.logger.ErrorContext(r.Context(), what+" failed", "traceId", traceID(r.Context()), "errorType", fmt.Sprintf("%T", err))
	writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
}
