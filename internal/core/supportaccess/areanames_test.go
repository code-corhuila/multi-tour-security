package supportaccess_test

import (
	"slices"
	"testing"
)

// The list of areas is not the scope of the token: persistence and the response keep only the closed list, so a sensitive emergency can be stored
// and read back (review of spec 010, finding F1).
func TestD_TheAreasOfASensitiveAccessAreTheClosedListWithoutTheSensitiveWord(t *testing.T) {
	a := emergency(t, true, "The incident is about a medical record")
	if got := a.AreaNames(); !slices.Equal(got, []string{"CASH"}) {
		t.Errorf("areas = %v", got)
	}
	if got := a.Scope(); !slices.Equal(got, []string{"CASH", "SENSITIVE"}) {
		t.Errorf("scope = %v", got)
	}
	got := a.AreaNames()
	got[0] = "CUSTOMERS"
	if a.AreaNames()[0] != "CASH" {
		t.Error("the caller changed the areas of the access")
	}
}
