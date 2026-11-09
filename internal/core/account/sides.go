package account

import "slices"

// The side a person works from when the account holds both (HU-SEC-008): as a customer or as a member of the team.
const (
	ContextCustomer = "CUSTOMER"
	ContextTeam     = "TEAM"
)

// RoleFinalCustomer is the role of the customer side; every other role but the platform one is the team side.
const RoleFinalCustomer = "FINAL_CUSTOMER"

// ForContext narrows the roles of an account to the side that asked. An account with one side carries it whatever was asked and
// has no context (""). An account with both carries the team roles when the team was asked and the customer role otherwise, the
// side with fewer permissions, and says which. The input is not changed.
func ForContext(roles []string, asked string) (string, []string) {
	customer := slices.Contains(roles, RoleFinalCustomer)
	team := slices.DeleteFunc(slices.Clone(roles), func(r string) bool { return r == RoleFinalCustomer })
	switch {
	case !customer || len(team) == 0:
		return "", slices.Clone(roles)
	case asked == ContextTeam:
		return ContextTeam, team
	}
	return ContextCustomer, []string{RoleFinalCustomer}
}
