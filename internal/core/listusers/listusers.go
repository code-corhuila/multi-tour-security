// Package listusers is the use case that lists the internal users of a tenant (HU-SEC-005, RN-SEC-003-07).
package listusers

import (
	"context"
	"errors"
	"math"
	"regexp"
	"slices"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// ErrInvalid is any part of the request that is not valid; FieldError says which.
var ErrInvalid = errors.New("the request is not valid")

// FieldError names the field that was refused, never its value.
type FieldError struct{ Field string }

func (e *FieldError) Error() string        { return e.Field + ": is not valid" }
func (e *FieldError) Is(target error) bool { return target == ErrInvalid }

const maxLimit = 100

// internalRoles are the only roles the list ever shows: a customer or a platform role is never listed, whatever is asked.
var internalRoles = []string{"TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "MANAGER", "ACCOUNTANT", "ANALYST"}

var (
	statuses = []string{"ACTIVE", "INACTIVE", "PENDING"}
	uuid     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Query is one request. Role and Status are empty for any. The tenant is the one of the credential.
type Query struct {
	TenantID string
	Role     string
	Status   string
	Page     int
	Limit    int
}

// Page is one page of users and the numbers that tell where it is.
type Page struct {
	Data       []port.Registered
	Page       int
	Limit      int
	Total      int
	TotalPages int
}

// Service reads the users through the store the composition root gives it.
type Service struct {
	Directory port.UserDirectory
}

// List validates the query before the store sees it, so that nothing that is not a tenant reaches it.
func (s *Service) List(ctx context.Context, q Query) (Page, error) {
	if s.Directory == nil {
		return Page{}, errors.New("the user list is not wired: the store is needed")
	}
	roles := slices.Clone(internalRoles)
	switch {
	case !uuid.MatchString(q.TenantID):
		return Page{}, &FieldError{Field: "tenantId"}
	case q.Role != "" && !slices.Contains(internalRoles, q.Role):
		return Page{}, &FieldError{Field: "role"}
	case q.Status != "" && !slices.Contains(statuses, q.Status):
		return Page{}, &FieldError{Field: "status"}
	case q.Limit < 1 || q.Limit > maxLimit:
		return Page{}, &FieldError{Field: "limit"}
	// the offset (Page-1)*Limit must fit an int: a page past it is a 400, not a negative OFFSET that fails in the engine
	case q.Page < 1 || q.Page > math.MaxInt/q.Limit:
		return Page{}, &FieldError{Field: "page"}
	}
	if q.Role != "" {
		roles = []string{q.Role}
	}
	users, total, err := s.Directory.List(ctx, q.TenantID, port.UserFilter{Roles: roles, Status: q.Status}, q.Limit, (q.Page-1)*q.Limit)
	if err != nil {
		return Page{}, err
	}
	if users == nil {
		users = []port.Registered{}
	}
	return Page{Data: users, Page: q.Page, Limit: q.Limit, Total: total, TotalPages: (total + q.Limit - 1) / q.Limit}, nil
}
