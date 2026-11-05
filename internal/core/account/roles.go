package account

import "slices"

// The two administrator roles, which the rules of the service name.
const (
	RoleTenantAdministrator   = "TENANT_ADMINISTRATOR"
	RolePlatformAdministrator = "PLATFORM_ADMINISTRATOR"
	// RoleOperationalCollaborator is the role that may receive any of the four special permissions
	RoleOperationalCollaborator = "OPERATIONAL_COLLABORATOR"
)

// the roles a tenant may enable, which a tenant starts without (HU-SEC-006, RN-SEC-005-12); they hold no special permission
var optionalRoles = []string{"MANAGER", "ACCOUNTANT", "ANALYST"}

// the roles of the staff of a tenant, which a Tenant Administrator may give (HU-SEC-005, RN-SEC-003-02); a customer role and the
// platform role are not among them
var internalRoles = append([]string{RoleTenantAdministrator, RoleOperationalCollaborator}, optionalRoles...)

// By is the text that the store keeps as the author of a change made by an administrator: the role in kebab case and the id.
// Any role but the platform one is recorded as a tenant administrator, so only callers that already checked the role may use it.
func By(actorRole, actorID string) string {
	if actorRole == RolePlatformAdministrator {
		return "platform-administrator/" + actorID
	}
	return "tenant-administrator/" + actorID
}

// InternalRoles lists the five roles of a tenant's staff, as a copy that the caller may change.
func InternalRoles() []string { return slices.Clone(internalRoles) }

// IsInternalRole tells whether role is one of the five.
func IsInternalRole(role string) bool { return slices.Contains(internalRoles, role) }

// OptionalRoles lists the three, in a fixed order, as a copy that the caller may change.
func OptionalRoles() []string { return slices.Clone(optionalRoles) }

// IsOptionalRole tells whether role is one of the three.
func IsOptionalRole(role string) bool { return slices.Contains(optionalRoles, role) }
