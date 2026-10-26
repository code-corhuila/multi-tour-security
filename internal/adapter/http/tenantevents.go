package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/tenantevent"
)

// maxEventBody holds the full state of a tenant with room to spare.
const maxEventBody = 16 * 1024

// TenantEventService is what the route needs from its use case, so a test can replace it.
type TenantEventService interface {
	Receive(ctx context.Context, e tenantevent.Event) (applied bool, err error)
}

// WithTenantEvents registers the route where job 7 tells the service about the tenants, for job 7 and nobody else.
func WithTenantEvents(service TenantEventService) Option {
	return func(s *server) { s.tenantEvents = service }
}

type tenantEventBody struct {
	EventID      string `json:"eventId"`
	EventType    string `json:"eventType"`
	EventVersion int    `json:"eventVersion"`
	TenantID     string `json:"tenantId"`
	AggregateID  string `json:"aggregateId"`
	OccurredAt   string `json:"occurredAt"`
	Payload      struct {
		TenantID       string `json:"tenantId"`
		Identifier     string `json:"identifier"`
		CommercialName string `json:"commercialName"`
		TenantStatus   string `json:"tenantStatus"`
	} `json:"payload"`
}

// receiveTenantEvent reads the envelope of ADR-004 D4, which tolerates fields it does not name, and answers 201 when
// the copy of the tenant changed and 200 when it did not (an older event, or one received before).
func (s *server) receiveTenantEvent(w http.ResponseWriter, r *http.Request) {
	var body tenantEventBody
	if !readJSONWith(w, r, &body, maxEventBody, false) {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	at, err := time.Parse(time.RFC3339Nano, body.OccurredAt)
	if len(key) < 8 || len(key) > 128 || key != body.EventID || err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the Idempotency-Key is the id of the event and the envelope is the one of the contract")
		return
	}
	applied, err := s.tenantEvents.Receive(r.Context(), tenantevent.Event{
		PathTenantID: r.PathValue("tenantId"), EventID: body.EventID, Type: body.EventType, Version: body.EventVersion,
		TenantID: body.TenantID, AggregateID: body.AggregateID, PayloadTenantID: body.Payload.TenantID,
		Identifier: body.Payload.Identifier, CommercialName: body.Payload.CommercialName, Status: body.Payload.TenantStatus, OccurredAt: at,
	})
	switch {
	case errors.Is(err, tenantevent.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the envelope breaks the contract")
	case errors.Is(err, tenantevent.ErrRetryLater):
		// an operator can see an event that stays held back; the identifier and the detail of the driver stay out
		s.logger.WarnContext(r.Context(), "tenant event held back by an identifier of another tenant", "traceId", traceID(r.Context()),
			"eventId", body.EventID, "tenantId", body.TenantID)
		w.Header().Set("Retry-After", "5")
		writeError(w, r, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "deliver the event again later")
	case err != nil:
		s.logger.ErrorContext(r.Context(), "receiving a tenant event failed", "traceId", traceID(r.Context()), "reason", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
	default:
		w.Header().Set("Cache-Control", "no-store")
		if applied {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}
}
