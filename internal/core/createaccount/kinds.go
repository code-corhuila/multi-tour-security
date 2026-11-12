package createaccount

// rule is one row of the table of plan D-02: what differs between the kinds of account. Everything else is shared.
type rule struct {
	scope string // prefix of the idempotency scope, so that one key means one intent per kind and tenant
	// role is the one given; empty when the command asks for it
	role string
	// selfService is a person who registers themselves: first and last name, a phone and a confirmed ordinary password
	selfService bool
	// temporary makes the password a credential of 72 hours that only allows choosing another
	temporary bool
	// activeTenant asks the copy of the tenant; the saga that makes the first Administrator is the authority instead
	activeTenant bool
	// pending makes the account wait for its e-mail to be verified: it gets a link and sends it
	pending bool
	// createdBy is recorded with the account, followed by "/" and the actor when the kind has one
	createdBy string
	hasActor  bool
}

// rules is the table as a function with a switch, so that nothing can change it at run time.
func rules(k Kind) (rule, bool) {
	switch k {
	case Customer:
		return rule{scope: "customer", role: "FINAL_CUSTOMER", selfService: true, activeTenant: true, pending: true, createdBy: "customer"}, true
	case InternalUser:
		return rule{scope: "user", temporary: true, activeTenant: true, createdBy: "tenant-administrator", hasActor: true}, true
	case FirstAdministrator:
		return rule{scope: "first-admin", role: "TENANT_ADMINISTRATOR", temporary: true, createdBy: "service", hasActor: true}, true
	}
	return rule{}, false
}

// tenantRole tells whether a role is one that a person of a tenant can give another; a platform or customer role never is.
func tenantRole(role string) bool {
	switch role {
	case "TENANT_ADMINISTRATOR", "OPERATIONAL_COLLABORATOR", "MANAGER", "ACCOUNTANT", "ANALYST":
		return true
	}
	return false
}
