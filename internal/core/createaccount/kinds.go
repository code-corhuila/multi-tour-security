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
	// createdBy is recorded with the account, followed by "/" and the actor when the kind has one
	createdBy string
	hasActor  bool
}

var rules = map[Kind]rule{
	Customer:           {scope: "customer", role: "FINAL_CUSTOMER", selfService: true, activeTenant: true, createdBy: "customer"},
	InternalUser:       {scope: "user", temporary: true, activeTenant: true, createdBy: "tenant-administrator", hasActor: true},
	FirstAdministrator: {scope: "first-admin", role: "TENANT_ADMINISTRATOR", temporary: true, createdBy: "service", hasActor: true},
}
