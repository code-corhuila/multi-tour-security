package account

import (
	"slices"
)

// The four special permissions of Phase 1 (PDR section 9), as the claim `permissions` of the credential names them. The commercial
// service already compares the first and the last; the cash service takes the value of the second from its configuration.
const (
	PermissionValidateProofs           = "VALIDATE_PAYMENT_PROOFS"
	PermissionManageCash               = "MANAGE_CASH"
	PermissionManageDepartureExecution = "MANAGE_DEPARTURE_EXECUTION"
	PermissionConsultSensitiveData     = "CONSULT_SENSITIVE_DATA"
)

var specialPermissions = []string{PermissionValidateProofs, PermissionManageCash, PermissionManageDepartureExecution, PermissionConsultSensitiveData}

// SpecialPermissions lists the four, as a copy that the caller may change. No other exists and none can be created.
func SpecialPermissions() []string { return slices.Clone(specialPermissions) }

// IsSpecialPermission tells whether p is one of the four.
func IsSpecialPermission(p string) bool { return slices.Contains(specialPermissions, p) }

// ProfilePermissions are the permissions a role holds by profile and that nobody assigns or removes: the Tenant Administrator's three.
func ProfilePermissions(roles []string) []string {
	if !slices.Contains(roles, RoleTenantAdministrator) {
		return []string{}
	}
	return []string{PermissionManageCash, PermissionManageDepartureExecution, PermissionValidateProofs}
}

// Assignable tells whether an Administrator may assign the permission to a person with that role. The Administrator holds three by
// profile, so only sensitive data is assigned to them; the Operational Collaborator may receive any of the four; the optional roles,
// a customer and the platform none (plan D-02).
func Assignable(role, permission string) bool {
	switch role {
	case RoleTenantAdministrator:
		return permission == PermissionConsultSensitiveData
	case RoleOperationalCollaborator:
		return IsSpecialPermission(permission)
	}
	return false
}

// PermissionsFor is the whole set a person holds: the permissions of their profile plus each assigned one that one of their roles may
// hold, sorted and without repeats, and never nil so that the claim is an empty list and not null. An assigned permission that no role
// of the person may hold is ignored, whatever wrote it. The input is not changed.
func PermissionsFor(roles, assigned []string) []string {
	set := ProfilePermissions(roles)
	for _, p := range assigned {
		if slices.ContainsFunc(roles, func(role string) bool { return Assignable(role, p) }) {
			set = append(set, p)
		}
	}
	slices.Sort(set)
	return slices.Compact(set)
}
