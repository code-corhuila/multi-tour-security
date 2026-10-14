package httpadapter

import "regexp"

// identifierPattern is the shape the contract gives the identifier of a tenant in a link.
var identifierPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// validIdentifier tells whether a path value can be the identifier of a tenant (3 to 40 characters of the pattern of
// the contract). A route checks it before asking any store, so that a value such as a null byte never reaches one.
func validIdentifier(s string) bool {
	return len(s) >= 3 && len(s) <= 40 && identifierPattern.MatchString(s)
}
