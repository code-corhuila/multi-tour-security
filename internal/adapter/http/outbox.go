package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
)

// OutboxService is what the internal routes need from the outbox, so a test can replace it.
type OutboxService interface {
	ListDue(ctx context.Context, page, limit int) (outbox.Page, error)
	MarkPublished(ctx context.Context, id string) (outbox.Event, error)
	RecordFailedAttempt(ctx context.Context, id, text string) (outbox.Event, error)
}

// WithOutbox registers the three internal routes of the outbox, for job 7 and nobody else.
func WithOutbox(service OutboxService) Option {
	return func(s *server) { s.outbox = service }
}

const serviceRole = "SERVICE"

// requireService lets in the token of a service and nothing else: the role SERVICE alone, no tenant and no access mark.
// Any other valid token, a person's included, is FORBIDDEN, and the gateway does not route these paths at all.
func (s *server) requireService(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		if !slices.Equal(claims.Roles, []string{serviceRole}) || claims.TenantID != "" || claims.Access != "" {
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "access denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type eventBody struct {
	EventID       string          `json:"eventId"`
	EventType     string          `json:"eventType"`
	EventVersion  int             `json:"eventVersion"`
	TenantID      string          `json:"tenantId,omitempty"`
	AggregateID   string          `json:"aggregateId"`
	Payload       json.RawMessage `json:"payload"`
	CorrelationID string          `json:"correlationId"`
	OccurredAt    string          `json:"occurredAt"`
	PublishedAt   string          `json:"publishedAt,omitempty"`
	Status        string          `json:"status"`
	Attempts      int             `json:"attempts"`
	LastError     string          `json:"lastError,omitempty"`
	NextAttemptAt string          `json:"nextAttemptAt"`
}

func eventOf(e outbox.Event) eventBody {
	body := eventBody{
		EventID: e.ID, EventType: e.Type, EventVersion: e.Version, TenantID: e.TenantID, AggregateID: e.AggregateID, Payload: e.Payload,
		CorrelationID: e.CorrelationID, OccurredAt: e.OccurredAt.UTC().Format(time.RFC3339Nano), Status: string(e.Status),
		Attempts: e.Attempts, LastError: e.LastError, NextAttemptAt: e.NextAttemptAt.UTC().Format(time.RFC3339Nano),
	}
	if !e.PublishedAt.IsZero() {
		body.PublishedAt = e.PublishedAt.UTC().Format(time.RFC3339Nano)
	}
	return body
}

// a plain whole number: no sign, no spaces and no leading zeros
var digits = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)

// number reads a query parameter that is a plain whole number, once, or the default when it is absent.
func number(values map[string][]string, name string, fallback int) (int, bool) {
	raw, present := values[name]
	if !present {
		return fallback, true
	}
	if len(raw) != 1 || !digits.MatchString(raw[0]) {
		return 0, false
	}
	n, _ := strconv.Atoi(raw[0])
	return n, true
}

func (s *server) listOutbox(w http.ResponseWriter, r *http.Request) {
	// ParseQuery reports a pair it cannot read, where URL.Query() would drop it and let an undeclared filter slip through
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the query cannot be read")
		return
	}
	page, okPage := number(query, "page", 1)
	limit, okLimit := number(query, "limit", 20)
	status, hasStatus := query["status"]
	validStatus := !hasStatus || (len(status) == 1 && status[0] == "PENDING")
	for name := range query {
		if name != "page" && name != "limit" && name != "status" {
			validStatus = false // a filter that is not declared is a 400, not ignored
		}
	}
	if !okPage || !okLimit || !validStatus || page < 1 || limit < 1 || limit > 100 {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "page, limit and status are the only parameters, and they must be valid")
		return
	}
	result, err := s.outbox.ListDue(r.Context(), page, limit)
	if err != nil {
		s.failOutbox(w, r, err, "listing the outbox")
		return
	}
	data := make([]eventBody, 0, len(result.Data))
	for _, e := range result.Data {
		data = append(data, eventOf(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": data,
		"meta": map[string]int{"page": result.Page, "limit": result.Limit, "total": result.Total, "totalPages": result.TotalPages},
	})
}

func (s *server) markPublished(w http.ResponseWriter, r *http.Request) {
	event, err := s.outbox.MarkPublished(r.Context(), r.PathValue("eventId"))
	if err != nil {
		s.failOutbox(w, r, err, "marking an event published")
		return
	}
	writeJSON(w, http.StatusOK, eventOf(event))
}

type attemptBody struct {
	Error *string `json:"error"`
}

func (s *server) recordAttempt(w http.ResponseWriter, r *http.Request) {
	var body attemptBody
	if !readJSON(w, r, &body) {
		return
	}
	if body.Error == nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with an error")
		return
	}
	event, err := s.outbox.RecordFailedAttempt(r.Context(), r.PathValue("eventId"), *body.Error)
	if err != nil {
		s.failOutbox(w, r, err, "recording a failed delivery")
		return
	}
	writeJSON(w, http.StatusOK, eventOf(event))
}

// failOutbox is the only place where an error of the outbox becomes an HTTP answer; the cause of a 500 goes to the log
// with the trace id and never to the caller.
func (s *server) failOutbox(w http.ResponseWriter, r *http.Request, err error, what string) {
	switch {
	case errors.Is(err, outbox.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the request is not valid")
	case errors.Is(err, outbox.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the event does not exist")
	default:
		s.logger.ErrorContext(r.Context(), what+" failed", "traceId", traceID(r.Context()), "reason", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
