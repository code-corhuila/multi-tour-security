package account

import "slices"

// The two administrator roles, which the rules of the service name.
const (
	RoleTenantAdministrator   = "TENANT_ADMINISTRATOR"
	RolePlatformAdministrator = "PLATFORM_ADMINISTRATOR"
)

// the roles of the staff of a tenant, which a Tenant Administrator may give (HU-SEC-005, RN-SEC-003-02); a customer role and the
// platform role are not among them
var internalRoles = []string{RoleTenantAdministrator, "OPERATIONAL_COLLABORATOR", "MANAGER", "ACCOUNTANT", "ANALYST"}

// InternalRoles lists the five roles of a tenant's staff, as a copy that the caller may change.
func InternalRoles() []string { return slices.Clone(internalRoles) }

// IsInternalRole tells whether role is one of the five.
func IsInternalRole(role string) bool { return slices.Contains(internalRoles, role) }
