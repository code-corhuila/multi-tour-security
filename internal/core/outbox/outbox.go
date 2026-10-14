// Package outbox is what the core knows of the events this service leaves for the rest of the platform in the same
// transaction as the change that causes them (ADR-004 D4), and of how job 7 reads, delivers and reports them. It
// imports only the standard library.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Status of an event: it is pending until job 7 publishes it or its attempts run out.
type Status string

const (
	Pending   Status = "PENDING"
	Published Status = "PUBLISHED"
	Failed    Status = "FAILED"
)

// Event is an event of the outbox as job 7 reads it. The owner is the only one that changes it.
type Event struct {
	ID            string
	Type          string
	Version       int
	TenantID      string // empty for the Platform Administrator
	AggregateID   string
	ActorID       string
	Reason        string
	Payload       json.RawMessage
	CorrelationID string
	OccurredAt    time.Time
	PublishedAt   time.Time // zero until it is published
	Status        Status
	Attempts      int
	LastError     string
	NextAttemptAt time.Time
}

// Policy is how long a failed delivery waits (it doubles up to a cap) and how many attempts it gets (ADR-004 D10).
type Policy struct {
	Base        time.Duration
	Cap         time.Duration
	MaxAttempts int
}

// DefaultPolicy: 5 seconds doubling to 15 minutes, and the 20th attempt gives the event up.
var DefaultPolicy = Policy{Base: 5 * time.Second, Cap: 15 * time.Minute, MaxAttempts: 20}

// WaitAfter is the wait after the n-th failed attempt: the base, twice the base, four times... never above the cap.
func (p Policy) WaitAfter(attempts int) time.Duration {
	wait := p.Base
	for doubled := 1; doubled < attempts && wait < p.Cap; doubled++ {
		wait *= 2
	}
	return min(wait, p.Cap)
}

// Published is the event delivered, whatever it was: a delivery that did succeed is true even if the event had been
// given up. Publishing twice keeps the first instant.
func (e Event) Published(at time.Time) Event {
	if e.Status == Published {
		return e
	}
	e.Status = Published
	e.PublishedAt = at.Truncate(time.Microsecond) // what is answered is what the database keeps
	return e
}

// WithFailedAttempt is one more failed delivery: it counts, keeps the error and waits longer, and the last one gives
// the event up. An event that is no longer pending is not touched by a report that came late.
func (e Event) WithFailedAttempt(text string, at time.Time, p Policy) Event {
	if e.Status != Pending {
		return e
	}
	at = at.Truncate(time.Microsecond)
	e.Attempts++
	e.LastError = text
	if e.Attempts >= p.MaxAttempts {
		e.Status, e.NextAttemptAt = Failed, at
		return e
	}
	e.NextAttemptAt = at.Add(p.WaitAfter(e.Attempts))
	return e
}

// Store keeps the events. Modify changes one under the lock of its row, so that two reports at once are both counted.
type Store interface {
	ListDue(ctx context.Context, now time.Time, page, limit int) (events []Event, total int, err error)
	Modify(ctx context.Context, id string, change func(Event) Event) (Event, bool, error)
}

var (
	// ErrInvalid is a page, a limit or an error text that cannot be used.
	ErrInvalid = errors.New("the request is not valid")
	// ErrNotFound is an event that does not exist, or an id that cannot be one.
	ErrNotFound = errors.New("the event does not exist")
)

const (
	maxLimit     = 100
	maxErrorText = 1000
)

var eventID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Page is one page of the events that are due.
type Page struct {
	Data       []Event
	Page       int
	Limit      int
	Total      int
	TotalPages int
}

// Service is what job 7 asks of the outbox; the composition root fills every piece, and a missing one stops it.
type Service struct {
	Store  Store
	Clock  func() time.Time
	Policy Policy
}

func (s *Service) ready() error {
	if s.Store == nil || s.Clock == nil || s.Policy.MaxAttempts < 1 || s.Policy.Base <= 0 {
		return errors.New("the outbox is not wired: every piece is needed")
	}
	return nil
}

// ListDue gives the pending events that are due, the one due for longest first.
func (s *Service) ListDue(ctx context.Context, page, limit int) (Page, error) {
	if err := s.ready(); err != nil {
		return Page{}, err
	}
	if page < 1 || limit < 1 || limit > maxLimit {
		return Page{}, ErrInvalid
	}
	events, total, err := s.Store.ListDue(ctx, s.Clock(), page, limit)
	if err != nil {
		return Page{}, err
	}
	if events == nil {
		events = []Event{}
	}
	return Page{Data: events, Page: page, Limit: limit, Total: total, TotalPages: (total + limit - 1) / limit}, nil
}

// MarkPublished records that every consumer took the event.
func (s *Service) MarkPublished(ctx context.Context, id string) (Event, error) {
	if err := s.ready(); err != nil {
		return Event{}, err
	}
	if !eventID.MatchString(id) {
		return Event{}, ErrNotFound
	}
	now := s.Clock()
	return s.modify(ctx, id, func(e Event) Event { return e.Published(now) })
}

// RecordFailedAttempt records that a consumer did not take the event.
func (s *Service) RecordFailedAttempt(ctx context.Context, id, text string) (Event, error) {
	if err := s.ready(); err != nil {
		return Event{}, err
	}
	text, ok := clean(text)
	if !ok {
		return Event{}, ErrInvalid
	}
	if !eventID.MatchString(id) {
		return Event{}, ErrNotFound
	}
	now, policy := s.Clock(), s.Policy
	return s.modify(ctx, id, func(e Event) Event { return e.WithFailedAttempt(text, now, policy) })
}

func (s *Service) modify(ctx context.Context, id string, change func(Event) Event) (Event, error) {
	event, found, err := s.Store.Modify(ctx, id, change)
	if err != nil {
		return Event{}, err
	}
	if !found {
		return Event{}, ErrNotFound
	}
	return event, nil
}

// clean trims the error and refuses what could disguise a line of a log or a screen: control, format (bidirectional,
// zero-width) and separator characters, an unassigned or private-use point, invalid UTF-8. The plain space is fine.
func clean(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if text == "" || utf8.RuneCountInString(text) > maxErrorText {
		return "", false
	}
	for _, r := range text {
		if r != ' ' && (r == utf8.RuneError || !unicode.IsGraphic(r) || unicode.Is(unicode.Zs, r)) {
			return "", false
		}
	}
	return text, true
}
