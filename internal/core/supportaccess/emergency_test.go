package supportaccess_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
)

// The rules of the emergency access of the Platform Administrator (HU-SEC-007 part B, security spec 010: RN-SEC-010-01, -02, -03, -04, -05).

func emergency(t *testing.T, sensitive bool, sensitiveReason string) supportaccess.Access {
	t.Helper()
	a, err := supportaccess.NewEmergency(tenantID, platform, "Every cash of today shows a negative balance", "No Administrator can sign in and none answers",
		[]string{"CASH"}, 4, sensitive, sensitiveReason, now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestD_AnEmergencyAccessRunsFromItsOpeningAndEndsWithItsHours(t *testing.T) {
	a := emergency(t, false, "")
	if a.Basis != supportaccess.Emergency || a.Status != supportaccess.Approved || a.DecidedBy != "" {
		t.Fatalf("an emergency starts approved by nobody: %+v", a)
	}
	if !a.OpenedAt.Equal(now) || !a.DecidedAt.Equal(now) || !a.ExpiresAt.Equal(now.Add(4*time.Hour)) {
		t.Errorf("it opens and runs from the opening: opened %v, expires %v", a.OpenedAt, a.ExpiresAt)
	}
	if err := a.CanTakeToken(now.Add(4*time.Hour - time.Second)); err != nil {
		t.Errorf("the token is available while it lasts: %v", err)
	}
	if got := a.At(now.Add(4 * time.Hour)).Status; got != supportaccess.Expired {
		t.Errorf("at the end it is %s", got)
	}
}

func TestD_AnEmergencyIsValidOnlyWithAJustificationAStatementAnAreaAndOneToTwentyFourHours(t *testing.T) {
	new := func(reason, statement string, areas []string, hours int) error {
		_, err := supportaccess.NewEmergency(tenantID, platform, reason, statement, areas, hours, false, "", now)
		return err
	}
	cases := map[string]struct {
		err  error
		want error
	}{
		"ok":             {new("why", "because", []string{"CASH"}, 24), nil},
		"no reason":      {new("  ", "because", []string{"CASH"}, 4), supportaccess.ErrInvalidReason},
		"long reason":    {new(strings.Repeat("a", 501), "because", []string{"CASH"}, 4), supportaccess.ErrInvalidReason},
		"no statement":   {new("why", " ", []string{"CASH"}, 4), supportaccess.ErrInvalidStatement},
		"long statement": {new("why", strings.Repeat("a", 501), []string{"CASH"}, 4), supportaccess.ErrInvalidStatement},
		"no area":        {new("why", "because", nil, 4), supportaccess.ErrInvalidAreas},
		"unknown area":   {new("why", "because", []string{"MEDICAL"}, 4), supportaccess.ErrInvalidAreas},
		"zero hours":     {new("why", "because", []string{"CASH"}, 0), supportaccess.ErrInvalidHours},
		"25 hours":       {new("why", "because", []string{"CASH"}, 25), supportaccess.ErrInvalidHours},
	}
	for name, c := range cases {
		if !errors.Is(c.err, c.want) && !(c.want == nil && c.err == nil) {
			t.Errorf("%s: err = %v, want %v", name, c.err, c.want)
		}
	}
}

func TestD_SensitiveDataNeedTheFlagAndTheirOwnJustification(t *testing.T) {
	open := func(sensitive bool, sensitiveReason string) (supportaccess.Access, error) {
		return supportaccess.NewEmergency(tenantID, platform, "The general reason", "because", []string{"CASH"}, 4, sensitive, sensitiveReason, now)
	}
	if a, err := open(true, "The incident is about a passenger's medical record"); err != nil || !a.Sensitive || a.SensitiveReason == "" {
		t.Errorf("sensitive with its reason: %+v, %v", a, err)
	}
	if a, err := open(false, ""); err != nil || a.Sensitive {
		t.Errorf("not sensitive by default: %+v, %v", a, err)
	}
	for name, c := range map[string]struct {
		sensitive bool
		reason    string
		want      error
	}{
		"flag without reason": {true, "  ", supportaccess.ErrInvalidSensitiveReason},
		"flag, long reason":   {true, strings.Repeat("a", 501), supportaccess.ErrInvalidSensitiveReason},
		"flag, same reason":   {true, "The general reason", supportaccess.ErrInvalidSensitiveReason},
		"reason without flag": {false, "a reason alone", supportaccess.ErrSensitiveReasonWithoutFlag},
	} {
		if _, err := open(c.sensitive, c.reason); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
}

func TestD_SensitiveIsInTheScopeOnlyWhenAsked(t *testing.T) {
	if got := emergency(t, false, "").Scope(); !slices.Equal(got, []string{"CASH"}) {
		t.Errorf("scope without sensitive = %v", got)
	}
	got := emergency(t, true, "The incident is about a medical record").Scope()
	if !slices.Equal(got, []string{"CASH", "SENSITIVE"}) {
		t.Errorf("scope with sensitive = %v", got)
	}
	if strings.Contains(strings.Join(request(t).Scope(), ","), "SENSITIVE") {
		t.Error("an authorized access never carries the sensitive data")
	}
}
