package account

import "slices"

// The two administrator roles, which the rules of the service name.
const (
	RoleTenantAdministrator   = "TENANT_ADMINISTRATOR"
	RolePlatformAdministrator = "PLATFORM_ADMINISTRATOR"
	// RoleOperationalCollaborator is the role that may receive any of the four special permissions
	RoleOperationalCollaborator = "OPERATIONAL_COLLABORATOR"
)

// the roles of the staff of a tenant, which a Tenant Administrator may give (HU-SEC-005, RN-SEC-003-02); a customer role and the
// platform role are not among them
var internalRoles = []string{RoleTenantAdministrator, RoleOperationalCollaborator, "MANAGER", "ACCOUNTANT", "ANALYST"}

// InternalRoles lists the five roles of a tenant's staff, as a copy that the caller may change.
func InternalRoles() []string { return slices.Clone(internalRoles) }

// IsInternalRole tells whether role is one of the five.
func IsInternalRole(role string) bool { return slices.Contains(internalRoles, role) }

// the roles a tenant may enable, which a tenant starts without (HU-SEC-006, RN-SEC-005-12); they hold no special permission
var optionalRoles = []string{"MANAGER", "ACCOUNTANT", "ANALYST"}

// OptionalRoles lists the three, in a fixed order, as a copy that the caller may change.
func OptionalRoles() []string { return slices.Clone(optionalRoles) }

// IsOptionalRole tells whether role is one of the three.
func IsOptionalRole(role string) bool { return slices.Contains(optionalRoles, role) }
