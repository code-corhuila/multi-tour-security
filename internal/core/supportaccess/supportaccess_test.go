package supportaccess_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

// The rules of the support access of the Platform Administrator (HU-SEC-007 part A, security spec 009: RN-SEC-009-01, -02, -04, -05, -06).

const (
	tenantID = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	platform = "11111111-1111-4111-8111-111111111111"
	admin    = "22222222-2222-4222-8222-222222222222"
)

var now = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

func request(t *testing.T) supportaccess.Access {
	t.Helper()
	a, err := supportaccess.New(tenantID, platform, "The cash closing does not show the transfers", []string{"CASH", "RESERVATIONS"}, 4, now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestD_TheAreasAreAClosedListWithoutSensitiveData(t *testing.T) {
	for _, ok := range [][]string{{"RESERVATIONS"}, {"CATALOG", "OPERATIONS", "CASH", "CUSTOMERS", "RESERVATIONS"}} {
		if _, err := supportaccess.ParseAreas(ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for name, bad := range map[string][]string{
		"none":      {},
		"nil":       nil,
		"medical":   {"MEDICAL"},
		"sensitive": {"CASH", "SENSITIVE_DATA"},
		"lowercase": {"cash"},
		"repeated":  {"CASH", "CASH"},
		"blank":     {""},
	} {
		if _, err := supportaccess.ParseAreas(bad); !errors.Is(err, supportaccess.ErrInvalidAreas) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestD_ARequestIsValidOnlyWithAReasonAnAreaAndOneToTwentyFourHours(t *testing.T) {
	cases := map[string]struct {
		reason string
		areas  []string
		hours  int
	}{
		"no reason":        {"", []string{"CASH"}, 4},
		"blank reason":     {"   ", []string{"CASH"}, 4},
		"long reason":      {strings.Repeat("x", 501), []string{"CASH"}, 4},
		"no area":          {"why", nil, 4},
		"no hours":         {"why", []string{"CASH"}, 0},
		"too many hours":   {"why", []string{"CASH"}, 25},
		"negative hours":   {"why", []string{"CASH"}, -1},
		"sensitive wanted": {"why", []string{"MEDICAL"}, 4},
	}
	for name, c := range cases {
		if _, err := supportaccess.New(tenantID, platform, c.reason, c.areas, c.hours, now); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, hours := range []int{1, 24} {
		if _, err := supportaccess.New(tenantID, platform, strings.Repeat("x", 500), []string{"CASH"}, hours, now); err != nil {
			t.Errorf("%d hours with a reason of 500 characters: %v", hours, err)
		}
	}
	a := request(t)
	if a.Status != supportaccess.Pending || a.Hours != 4 || a.RequestedAt != now || a.TenantID != tenantID || a.RequestedBy != platform {
		t.Errorf("request = %+v", a)
	}
}

func TestD_ARequestExpiresAfter72Hours(t *testing.T) {
	a := request(t)
	if got := a.At(now.Add(72*time.Hour - time.Second)).Status; got != supportaccess.Pending {
		t.Errorf("just before: %s", got)
	}
	if got := a.At(now.Add(72 * time.Hour)).Status; got != supportaccess.Expired {
		t.Errorf("at 72 hours: %s", got)
	}
	if _, err := a.Approve(admin, now.Add(73*time.Hour)); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("approving an expired request: %v", err)
	}
}

func TestD_AnApprovedAccessEndsWhenItsHoursAreOver(t *testing.T) {
	approvedAt := now.Add(time.Hour)
	a, err := request(t).Approve(admin, approvedAt)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != supportaccess.Approved || a.DecidedBy != admin || !a.DecidedAt.Equal(approvedAt) || !a.ExpiresAt.Equal(approvedAt.Add(4*time.Hour)) {
		t.Fatalf("approved = %+v", a)
	}
	if got := a.At(a.ExpiresAt.Add(-time.Second)).Status; got != supportaccess.Approved {
		t.Errorf("just before the end: %s", got)
	}
	if got := a.At(a.ExpiresAt).Status; got != supportaccess.Expired {
		t.Errorf("at the end: %s", got)
	}
}

func TestD_NoApprovedAccessLastsMoreThan24HoursFromTheApproval(t *testing.T) {
	long, err := supportaccess.New(tenantID, platform, "why", []string{"CASH"}, 24, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := long.Approve(admin, now.Add(70*time.Hour))
	if err != nil || !a.ExpiresAt.Equal(now.Add(94*time.Hour)) {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestD_OnlyAPendingRequestIsDecided(t *testing.T) {
	approved, _ := request(t).Approve(admin, now)
	rejected, err := request(t).Reject(admin, "Nobody asked for this", now)
	if err != nil || rejected.Status != supportaccess.Rejected || rejected.DecisionReason != "Nobody asked for this" {
		t.Fatalf("rejected = %+v %v", rejected, err)
	}
	for name, a := range map[string]supportaccess.Access{"approved": approved, "rejected": rejected} {
		if _, err := a.Approve(admin, now); !errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("approving %s: %v", name, err)
		}
		if _, err := a.Reject(admin, "again", now); !errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("rejecting %s: %v", name, err)
		}
	}
	if _, err := request(t).Reject(admin, "  ", now); err == nil {
		t.Error("a rejection with no reason was accepted")
	}
}

func TestD_TheTokenIsTakenOnlyWhileTheAccessIsApprovedAndNotOver(t *testing.T) {
	pending := request(t)
	approved, _ := pending.Approve(admin, now)
	rejected, _ := request(t).Reject(admin, "no", now)
	closed, _ := approved.Close("Solved", now.Add(time.Hour))
	cases := map[string]struct {
		a  supportaccess.Access
		at time.Time
		ok bool
	}{
		"pending":         {pending, now, false},
		"rejected":        {rejected, now, false},
		"approved":        {approved, now.Add(time.Hour), true},
		"at the very end": {approved, approved.ExpiresAt, false},
		"after the end":   {approved, approved.ExpiresAt.Add(time.Minute), false},
		"closed":          {closed, now.Add(2 * time.Hour), false},
		"at the approval": {approved, now, true},
	}
	for name, c := range cases {
		err := c.a.CanTakeToken(c.at)
		if c.ok && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !c.ok && !errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestD_OnlyAnApprovedAccessIsClosedAndItKeepsWhyAndWhen(t *testing.T) {
	approved, _ := request(t).Approve(admin, now)
	closed, err := approved.Close("The incident is solved", now.Add(time.Hour))
	if err != nil || closed.Status != supportaccess.Closed || closed.ClosedReason != "The incident is solved" || !closed.ClosedAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("closed = %+v %v", closed, err)
	}
	if _, err := request(t).Close("why", now); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("closing a pending request: %v", err)
	}
	if _, err := closed.Close("again", now); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("closing twice: %v", err)
	}
	if _, err := approved.Close("late", approved.ExpiresAt); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("closing an access that ran out: %v", err)
	}
	if _, err := approved.Close(" ", now); err == nil {
		t.Error("closing with no reason was accepted")
	}
}

func TestD_TheScopeOfTheTokenIsTheApprovedAreasAndNothingElse(t *testing.T) {
	a := request(t)
	if got := a.Scope(); !slices.Equal(got, []string{"CASH", "RESERVATIONS"}) {
		t.Errorf("scope = %v", got)
	}
	got := a.Scope()
	got[0] = "CUSTOMERS"
	if a.Scope()[0] != "CASH" {
		t.Error("the caller changed the areas of the access")
	}
}

// The reason is counted in characters, not in bytes: 500 of two bytes are accepted and 501 are not, in the three places that take one.
func TestD_TheReasonIsCountedInCharactersNotInBytes(t *testing.T) {
	ok, long := strings.Repeat("ñ", 500), strings.Repeat("ñ", 501)
	if _, err := supportaccess.New(tenantID, platform, ok, []string{"CASH"}, 1, now); err != nil {
		t.Errorf("500 characters in New: %v", err)
	}
	if _, err := supportaccess.New(tenantID, platform, long, []string{"CASH"}, 1, now); !errors.Is(err, supportaccess.ErrInvalidReason) {
		t.Errorf("501 characters in New: %v", err)
	}
	if _, err := request(t).Reject(admin, ok, now); err != nil {
		t.Errorf("500 characters in Reject: %v", err)
	}
	if _, err := request(t).Reject(admin, long, now); !errors.Is(err, supportaccess.ErrInvalidReason) {
		t.Errorf("501 characters in Reject: %v", err)
	}
	approved, _ := request(t).Approve(admin, now)
	if _, err := approved.Close(ok, now); err != nil {
		t.Errorf("500 characters in Close: %v", err)
	}
	if _, err := approved.Close(long, now); !errors.Is(err, supportaccess.ErrInvalidReason) {
		t.Errorf("501 characters in Close: %v", err)
	}
}

// The window to decide ends at the instant, not after it.
func TestD_ADecisionAtExactly72HoursIsTooLate(t *testing.T) {
	if _, err := request(t).Approve(admin, now.Add(72*time.Hour-time.Second)); err != nil {
		t.Errorf("one second before: %v", err)
	}
	if _, err := request(t).Approve(admin, now.Add(72*time.Hour)); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("at 72 hours: %v", err)
	}
	if _, err := request(t).Reject(admin, "no", now.Add(72*time.Hour)); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("rejecting at 72 hours: %v", err)
	}
}

// An access built outside New, with hours the rules do not allow, is never approved for them (a corrupt row, a careless adapter).
func TestD_AnAccessWithHoursOutOfRangeIsNeverApproved(t *testing.T) {
	for _, hours := range []int{0, -3, 25, 1000} {
		a := request(t)
		a.Hours = hours
		if _, err := a.Approve(admin, now); !errors.Is(err, supportaccess.ErrInvalidHours) {
			t.Errorf("%d hours: %v", hours, err)
		}
	}
}
