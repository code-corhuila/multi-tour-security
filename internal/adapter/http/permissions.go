package httpadapter

import (
	"context"
	"errors"
	"net/http"

	"github.com/code-corhuila/multi-tour-security/internal/core/changepermission"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// PermissionChanger is what the routes that assign and remove a special permission need from the use case, so a test can replace it.
type PermissionChanger interface {
	Grant(ctx context.Context, r changepermission.Request) (port.Registered, error)
	Remove(ctx context.Context, r changepermission.Request) (port.Registered, error)
}

// WithChangePermission registers the routes where a Tenant Administrator assigns and removes a special permission of a user of their
// own tenant (HU-SEC-006).
func WithChangePermission(service PermissionChanger) Option {
	return func(s *server) { s.permissions = service }
}

// permissionBody is the PermissionChangeRequest of the contract: the permission and nothing else, so nothing in the body can change the
// tenant, the actor or the role of the user.
type permissionBody struct {
	Permission string `json:"permission"`
}

// changePermission takes the tenant and the actor from the credential, the user from the path and the permission from the body. A
// permission outside the four is refused by the use case, which names the field and never the value.
func (s *server) changePermission(change func(context.Context, changepermission.Request) (port.Registered, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body permissionBody
		if !readJSON(w, r, &body) {
			return
		}
		claims, _ := r.Context().Value(claimsKey{}).(Claims)
		reg, err := change(r.Context(), changepermission.Request{TenantID: claims.TenantID, AccountID: r.PathValue("accountId"), ActorID: claims.Subject,
			Permission: body.Permission, CorrelationID: traceID(r.Context())})
		var invalid *changepermission.FieldError
		var out accountBody
		if err == nil {
			out, err = toAccountBody(reg)
		}
		switch {
		case errors.As(err, &invalid) && callerField(invalid):
			refuseField(w, r, invalid)
		case errors.Is(err, port.ErrUserNotFound):
			refuseNoUser(w, r)
		case errors.Is(err, changepermission.ErrProfilePermission):
			refuseRule(w, r, "the permission is held by profile and is neither assigned nor removed")
		case errors.Is(err, changepermission.ErrNotAssignable):
			refuseRule(w, r, "the role of the user cannot hold that permission")
		case err != nil:
			s.fail(w, r, "changing the permissions of a user", err)
		default:
			writeJSON(w, http.StatusOK, out)
		}
	}
}
