package supportsession_test

import (
	"slices"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportsession"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// The token of an emergency access (HU-SEC-007 part B, security spec 010: RN-SEC-010-04, -05, -06).

func asEmergency(sensitive bool) func(*supportaccess.Access) {
	return func(a *supportaccess.Access) {
		reason := ""
		if sensitive {
			reason = "The incident is about a passenger's medical record"
		}
		e, err := supportaccess.NewEmergency(tenantID, platform, "Every cash of today shows a negative balance", "No Administrator can sign in", []string{"CASH"}, 4, sensitive, reason, now.Add(-time.Hour))
		if err != nil {
			panic(err)
		}
		e.ID = accessID
		*a = e
	}
}

func TestA_TheEmergencyTokenEndsWithTheAccessAndIsMarkedEmergency(t *testing.T) {
	w := newWorld(t, asEmergency(false))
	given, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c-1"})
	if err != nil {
		t.Fatal(err)
	}
	c := w.signer.claims[0]
	if c.Access != token.EmergencyAccess || c.AuthorizationID != accessID || c.TenantID != tenantID || !c.ExpiresAt.Equal(now.Add(3*time.Hour)) || !given.ExpiresAt.Equal(c.ExpiresAt) {
		t.Fatalf("claims = %+v, token = %+v", c, given)
	}
}

func TestA_SensitiveIsInTheScopeOfTheTokenOnlyWhenTheEmergencyAsksForIt(t *testing.T) {
	plain := newWorld(t, asEmergency(false))
	given, err := plain.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c-2"})
	if err != nil || !slices.Equal(given.Scope, []string{"CASH"}) || !slices.Equal(plain.signer.claims[0].Scope, []string{"CASH"}) {
		t.Fatalf("without sensitive: %+v %v", given, err)
	}
	sensitive := newWorld(t, asEmergency(true))
	given, err = sensitive.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c-3"})
	if err != nil || !slices.Equal(given.Scope, []string{"CASH", "SENSITIVE"}) || !slices.Equal(sensitive.signer.claims[0].Scope, []string{"CASH", "SENSITIVE"}) {
		t.Fatalf("with sensitive: %+v %v", given, err)
	}
	// an authorized access keeps the mark of part A
	authorized := newWorld(t, nil)
	if _, err := authorized.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c-4"}); err != nil || authorized.signer.claims[0].Access != token.ExceptionalAccess {
		t.Fatalf("authorized: %+v %v", authorized.signer.claims, err)
	}
}

func TestA_AnEmergencyIsClosedLikeAnyOtherAccessAndKeepsItsBasis(t *testing.T) {
	w := newWorld(t, asEmergency(true))
	closed, err := w.service.Close(ctx, supportsession.CloseCommand{ActorID: platform, ID: accessID, Reason: "The incident is solved", CorrelationID: "c-5"})
	if err != nil || closed.Status != supportaccess.Closed || closed.Basis != supportaccess.Emergency || len(w.store.closes) != 1 {
		t.Fatalf("closed = %+v %v", closed, err)
	}
}
