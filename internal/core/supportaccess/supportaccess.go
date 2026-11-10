// Package supportaccess is the support access of the Platform Administrator to one tenant, authorized by a Tenant Administrator
// (HU-SEC-007 part A, PDR section 9): a request that waits for a decision, an approval that lasts the hours asked and ends by itself,
// and the early closing. It imports only the standard library (plan D-02); persistence, tokens and routes are the adapters' business.
package supportaccess

import (
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Area is a part of the tenant that a support access may read. The sensitive data (medical, emergency, consent) are not an area: they are
// reached only by the emergency access (part B), never by an authorized one (RN-SEC-009-02).
type Area string

const (
	Reservations Area = "RESERVATIONS"
	Catalog      Area = "CATALOG"
	Operations   Area = "OPERATIONS"
	Cash         Area = "CASH"
	Customers    Area = "CUSTOMERS"
)

var areas = []Area{Reservations, Catalog, Operations, Cash, Customers}

// Status of a support access. A request that nobody decided in time and an approval whose hours are over are both Expired.
type Status string

const (
	Pending  Status = "PENDING"
	Approved Status = "APPROVED"
	Rejected Status = "REJECTED"
	Expired  Status = "EXPIRED"
	Closed   Status = "CLOSED"
)

// Basis says why the access exists: the authorization of a Tenant Administrator, or the emergency of the Platform Administrator
// (HU-SEC-007 part B). An access built before the basis existed has none, which reads as the authorization.
type Basis string

const (
	TenantAuthorization Basis = "TENANT_AUTHORIZATION"
	Emergency           Basis = "EMERGENCY"
)

// SensitiveScope is the word the scope of the token carries when the access reaches the sensitive data (RN-SEC-010-05).
const SensitiveScope = "SENSITIVE"

const (
	// MaxHours is the longest an access lasts (PDR section 9).
	MaxHours = 24
	// DecisionWindow is how long a request waits for a Tenant Administrator before it expires (RN-SEC-009-04).
	DecisionWindow = 72 * time.Hour
	// MaxText is the longest reason, in characters.
	MaxText = 500
)

var (
	ErrInvalidAreas      = errors.New("the areas must be one or more different ones of the closed list")
	ErrInvalidReason     = errors.New("the reason must be between 1 and 500 characters")
	ErrInvalidHours      = errors.New("the hours must be between 1 and 24")
	ErrInvalidTransition = errors.New("the support access is not in a status that allows it")

	ErrInvalidStatement           = errors.New("the statement must be between 1 and 500 characters")
	ErrInvalidSensitiveReason     = errors.New("the sensitive data need their own justification of 1 to 500 characters, different from the general reason")
	ErrSensitiveReasonWithoutFlag = errors.New("a justification for the sensitive data needs the sensitive flag")
	ErrOpenAccessExists           = errors.New("the Platform Administrator already has an open access to that tenant")
)

// AreaNames lists the areas of the closed list, as a copy that the caller may change.
func AreaNames() []string {
	names := make([]string, len(areas))
	for i, a := range areas {
		names[i] = string(a)
	}
	return names
}

// ParseAreas turns names into areas: at least one, each of the list and none repeated. The order given is kept.
func ParseAreas(names []string) ([]Area, error) {
	if len(names) == 0 || len(names) > len(areas) {
		return nil, ErrInvalidAreas
	}
	out := make([]Area, 0, len(names))
	for _, n := range names {
		a := Area(n)
		if !slices.Contains(areas, a) || slices.Contains(out, a) {
			return nil, ErrInvalidAreas
		}
		out = append(out, a)
	}
	return out, nil
}

// Access is one request and what became of it. The zero time means "not yet".
type Access struct {
	ID             string
	TenantID       string
	RequestedBy    string
	Reason         string
	Areas          []Area
	Hours          int
	Status         Status
	RequestedAt    time.Time
	DecidedBy      string
	DecidedAt      time.Time
	DecisionReason string
	ExpiresAt      time.Time
	OpenedAt       time.Time
	ClosedAt       time.Time
	ClosedReason   string
	// Part B, the emergency access. Basis is empty or TenantAuthorization for the rest.
	Basis           Basis
	Statement       string
	Sensitive       bool
	SensitiveReason string
}

// IsEmergency tells whether the access was opened by the Platform Administrator alone.
func (a Access) IsEmergency() bool { return a.Basis == Emergency }

// New is a request of the Platform Administrator: pending, with the reason trimmed.
func New(tenantID, requestedBy, reason string, areaNames []string, hours int, now time.Time) (Access, error) {
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > MaxText {
		return Access{}, ErrInvalidReason
	}
	if hours < 1 || hours > MaxHours {
		return Access{}, ErrInvalidHours
	}
	parsed, err := ParseAreas(areaNames)
	if err != nil {
		return Access{}, err
	}
	return Access{TenantID: tenantID, RequestedBy: requestedBy, Reason: reason, Areas: parsed, Hours: hours, Status: Pending, RequestedAt: now}, nil
}

// NewEmergency is the emergency access of the Platform Administrator: it needs no approval, so it is approved from the start, opens and runs
// from now for the hours asked (RN-SEC-010-02). The sensitive data are reached only with the flag and their own justification (RN-SEC-010-03).
func NewEmergency(tenantID, openedBy, reason, statement string, areaNames []string, hours int, sensitive bool, sensitiveReason string, now time.Time) (Access, error) {
	reason, statement, sensitiveReason = strings.TrimSpace(reason), strings.TrimSpace(statement), strings.TrimSpace(sensitiveReason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > MaxText {
		return Access{}, ErrInvalidReason
	}
	if n := utf8.RuneCountInString(statement); n < 1 || n > MaxText {
		return Access{}, ErrInvalidStatement
	}
	if hours < 1 || hours > MaxHours {
		return Access{}, ErrInvalidHours
	}
	parsed, err := ParseAreas(areaNames)
	if err != nil {
		return Access{}, err
	}
	switch n := utf8.RuneCountInString(sensitiveReason); {
	case sensitive && (n < 1 || n > MaxText || sensitiveReason == reason):
		return Access{}, ErrInvalidSensitiveReason
	case !sensitive && n > 0:
		return Access{}, ErrSensitiveReasonWithoutFlag
	}
	return Access{
		TenantID: tenantID, RequestedBy: openedBy, Reason: reason, Areas: parsed, Hours: hours, Status: Approved, RequestedAt: now,
		DecidedAt: now, ExpiresAt: now.Add(time.Duration(hours) * time.Hour), OpenedAt: now,
		Basis: Emergency, Statement: statement, Sensitive: sensitive, SensitiveReason: sensitiveReason,
	}, nil
}

// At is the access as it stands at that instant: a request that waited 72 hours, and an approval whose hours are over, are Expired even if
// nothing has written it yet (the token ends by its own expiry; the store writes the fact later, plan D-05).
func (a Access) At(now time.Time) Access {
	switch {
	case a.Status == Pending && !now.Before(a.RequestedAt.Add(DecisionWindow)):
		a.Status = Expired
	case a.Status == Approved && !now.Before(a.ExpiresAt):
		a.Status = Expired
	}
	return a
}

// Approve is the decision of a Tenant Administrator: the hours asked run from now, never more than 24.
func (a Access) Approve(decidedBy string, now time.Time) (Access, error) {
	// an access built outside New is not trusted for the hours it carries (RN-SEC-009-04: never more than 24)
	if a.Hours < 1 || a.Hours > MaxHours {
		return Access{}, ErrInvalidHours
	}
	if a.At(now).Status != Pending {
		return Access{}, ErrInvalidTransition
	}
	a.Status, a.DecidedBy, a.DecidedAt, a.ExpiresAt = Approved, decidedBy, now, now.Add(time.Duration(a.Hours)*time.Hour)
	return a, nil
}

// Reject is the refusal of a Tenant Administrator, with a reason.
func (a Access) Reject(decidedBy, reason string, now time.Time) (Access, error) {
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > MaxText {
		return Access{}, ErrInvalidReason
	}
	if a.At(now).Status != Pending {
		return Access{}, ErrInvalidTransition
	}
	a.Status, a.DecidedBy, a.DecidedAt, a.DecisionReason = Rejected, decidedBy, now, reason
	return a, nil
}

// CanTakeToken tells whether the Platform Administrator may take the token now: only while the access is approved and not over.
func (a Access) CanTakeToken(now time.Time) error {
	if a.At(now).Status != Approved {
		return ErrInvalidTransition
	}
	return nil
}

// Close ends an approved access before its time, with a reason.
func (a Access) Close(reason string, now time.Time) (Access, error) {
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > MaxText {
		return Access{}, ErrInvalidReason
	}
	if a.At(now).Status != Approved {
		return Access{}, ErrInvalidTransition
	}
	a.Status, a.ClosedAt, a.ClosedReason = Closed, now, reason
	return a, nil
}

// Scope is the claim of the token: the approved areas, as a copy that the caller may change.
func (a Access) Scope() []string {
	scope := make([]string, len(a.Areas))
	for i, area := range a.Areas {
		scope[i] = string(area)
	}
	if a.Sensitive {
		scope = append(scope, SensitiveScope)
	}
	return scope
}
