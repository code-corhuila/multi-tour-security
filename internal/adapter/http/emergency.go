package httpadapter

import (
	"context"
	"errors"
	"net/http"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportemergency"
)

// EmergencyOpener is what the route of the emergency access needs from the use case, so a test can replace it.
type EmergencyOpener interface {
	Open(ctx context.Context, c supportemergency.Command) (supportaccess.Access, bool, error)
}

// WithEmergencyAccess registers the route where the Platform Administrator opens an emergency access to a tenant (HU-SEC-007 part B).
func WithEmergencyAccess(service EmergencyOpener) Option {
	return func(s *server) { s.emergencyAccess = service }
}

// emergencyAccessRequestBody is the CreateEmergencyAccessRequest of the contract. It has no field for the actor, and the reader refuses any
// field it does not name, so nothing in the body can change who is opening it.
type emergencyAccessRequestBody struct {
	TenantID        string   `json:"tenantId"`
	Reason          string   `json:"reason"`
	Statement       string   `json:"statement"`
	Areas           []string `json:"areas"`
	Hours           int      `json:"hours"`
	Sensitive       bool     `json:"sensitive"`
	SensitiveReason string   `json:"sensitiveReason"`
}

// refuseEmergency answers what the use case refused. The tenant comes in the body, so its fault is the caller's too; only the actor, who
// comes from the credential, is not.
func (s *server) refuseEmergency(w http.ResponseWriter, r *http.Request, err error) {
	var invalid *supportemergency.FieldError
	switch {
	case errors.As(err, &invalid) && invalid.Field != "actorId":
		refuseField(w, r, invalid)
	case errors.Is(err, supportemergency.ErrTenantNotFound):
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the tenant does not exist")
	case errors.Is(err, supportaccess.ErrOpenAccessExists):
		refuseRule(w, r, "an access to that tenant is already open")
	default:
		s.fail(w, r, "opening an emergency access", err)
	}
}

// openEmergencyAccess takes the actor and the correlation id from the credential and the request. A missing field arrives empty and the use
// case refuses it by name.
func (s *server) openEmergencyAccess(w http.ResponseWriter, r *http.Request) {
	var body emergencyAccessRequestBody
	if !readJSON(w, r, &body) {
		return
	}
	claims, _ := r.Context().Value(claimsKey{}).(Claims)
	access, created, err := s.emergencyAccess.Open(r.Context(), supportemergency.Command{
		ActorID: claims.Subject, TenantID: body.TenantID, Reason: body.Reason, Statement: body.Statement, Areas: body.Areas, Hours: body.Hours,
		Sensitive: body.Sensitive, SensitiveReason: body.SensitiveReason, IdempotencyKey: r.Header.Get("Idempotency-Key"), CorrelationID: traceID(r.Context()),
	})
	if err != nil {
		s.refuseEmergency(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, toSupportAccessBody(access))
}
