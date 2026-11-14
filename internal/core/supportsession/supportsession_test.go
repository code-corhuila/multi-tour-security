package supportsession_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportsession"
	"github.com/code-corhuila/multi-tour-security/internal/core/token"
)

// Taking the token of an approved support access and closing it before its time (HU-SEC-007 part A, security spec 009: RN-SEC-009-05, -06).

const (
	tenantID = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
	platform = "44444444-4444-4444-8444-444444444444"
	other    = "99999999-9999-4999-8999-999999999999"
	admin    = "22222222-2222-4222-8222-222222222222"
	accessID = "55555555-5555-4555-8555-555555555555"
)

var now = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

type fakeStore struct {
	items       map[string]supportaccess.Access
	opens       []string
	closes      []supportaccess.Access
	expiredFor  []string
	refuseOpen  bool
	refuseClose bool
	afterOpen   func(*supportaccess.Access) // changes what Open answers, as a closing between the opening and the re-read would
	err         error
}

func (f *fakeStore) FindOwn(_ context.Context, requestedBy, id string) (supportaccess.Access, bool, error) {
	a, ok := f.items[id]
	if !ok || a.RequestedBy != requestedBy {
		return supportaccess.Access{}, false, f.err
	}
	return a, true, f.err
}

func (f *fakeStore) Open(_ context.Context, requestedBy, id string, at time.Time, correlationID string) (supportaccess.Access, bool, error) {
	f.opens = append(f.opens, requestedBy+"|"+id+"|"+at.Format(time.RFC3339)+"|"+correlationID)
	if f.err != nil || f.refuseOpen {
		return supportaccess.Access{}, false, f.err
	}
	a := f.items[id]
	if a.OpenedAt.IsZero() {
		a.OpenedAt = at
	}
	f.items[id] = a
	if f.afterOpen != nil {
		f.afterOpen(&a)
	}
	return a, true, nil
}

func (f *fakeStore) Close(_ context.Context, a supportaccess.Access, correlationID string) (bool, error) {
	if f.err != nil || f.refuseClose {
		return false, f.err
	}
	f.closes = append(f.closes, a)
	return true, nil
}

func (f *fakeStore) ExpireApproved(_ context.Context, requestedBy, _ string, _ time.Time) error {
	f.expiredFor = append(f.expiredFor, requestedBy)
	return f.err
}

type fakeSigner struct {
	claims []token.Claims
	err    error
}

func (f *fakeSigner) Sign(c token.Claims) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.claims = append(f.claims, c)
	return "signed.support.token", nil
}

func approved(t *testing.T) supportaccess.Access {
	t.Helper()
	a, err := supportaccess.New(tenantID, platform, "The cash closing does not show the transfers", []string{"CASH", "RESERVATIONS"}, 4, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	a.ID = accessID
	a, err = a.Approve(admin, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type world struct {
	service *supportsession.Service
	store   *fakeStore
	signer  *fakeSigner
}

func newWorld(t *testing.T, edit func(*supportaccess.Access)) *world {
	a := approved(t)
	if edit != nil {
		edit(&a)
	}
	w := &world{store: &fakeStore{items: map[string]supportaccess.Access{accessID: a}}, signer: &fakeSigner{}}
	w.service = &supportsession.Service{Store: w.store, Signer: w.signer, Clock: func() time.Time { return now }}
	return w
}

var ctx = context.Background()

func fieldOf(err error) string {
	var fe *supportsession.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func TestA_TheTokenEndsWithTheAccessAndCarriesTheTenantTheScopeAndTheAuthorization(t *testing.T) {
	w := newWorld(t, nil)
	got, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "corr-1"})
	if err != nil {
		t.Fatal(err)
	}
	ends := now.Add(3 * time.Hour) // approved an hour ago for four hours
	if got.AccessToken != "signed.support.token" || !got.ExpiresAt.Equal(ends) || got.ExpiresIn != 3*time.Hour || got.AuthorizationID != accessID ||
		strings.Join(got.Scope, ",") != "CASH,RESERVATIONS" {
		t.Fatalf("token = %+v", got)
	}
	if len(w.signer.claims) != 1 {
		t.Fatalf("%d tokens signed", len(w.signer.claims))
	}
	c := w.signer.claims[0]
	if c.Subject != platform || c.TenantID != tenantID || c.Access != "exceptional" || c.AuthorizationID != accessID || !c.ExpiresAt.Equal(ends) ||
		strings.Join(c.Scope, ",") != "CASH,RESERVATIONS" || strings.Join(c.Roles, ",") != "PLATFORM_ADMINISTRATOR" {
		t.Fatalf("claims = %+v", c)
	}
	if len(w.store.opens) != 1 || w.store.opens[0] != platform+"|"+accessID+"|"+now.Format(time.RFC3339)+"|corr-1" {
		t.Fatalf("opens = %v", w.store.opens)
	}
	if len(w.store.expiredFor) != 1 || w.store.expiredFor[0] != platform {
		t.Fatalf("expired for %v", w.store.expiredFor)
	}
}

func TestA_NoTokenIsGivenBeforeTheApprovalOrAfterTheEndOrToAnotherAdministrator(t *testing.T) {
	for name, edit := range map[string]func(*supportaccess.Access){
		"pending":  func(a *supportaccess.Access) { a.Status, a.ExpiresAt = supportaccess.Pending, time.Time{} },
		"rejected": func(a *supportaccess.Access) { a.Status = supportaccess.Rejected },
		"closed":   func(a *supportaccess.Access) { a.Status = supportaccess.Closed },
		"ran out":  func(a *supportaccess.Access) { a.ExpiresAt = now },
	} {
		w := newWorld(t, edit)
		if _, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c"}); !errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(w.signer.claims) != 0 || len(w.store.opens) != 0 {
			t.Errorf("%s: a token was signed or an access opened", name)
		}
	}
	w := newWorld(t, nil)
	if _, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: other, ID: accessID, CorrelationID: "c"}); !errors.Is(err, supportsession.ErrNotFound) {
		t.Errorf("another administrator: %v", err)
	}
	if _, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: "../x", CorrelationID: "c"}); !errors.Is(err, supportsession.ErrNotFound) {
		t.Errorf("an id that is not one: %v", err)
	}
	if len(w.signer.claims) != 0 {
		t.Error("a token was signed")
	}
}

func TestA_AnAccessThatStoppedBeingApprovedBetweenTheReadAndTheOpeningGivesNoToken(t *testing.T) {
	w := newWorld(t, nil)
	w.store.refuseOpen = true
	if _, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c"}); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Fatalf("err = %v", err)
	}
	if len(w.signer.claims) != 0 {
		t.Fatal("a token was signed")
	}
}

func TestA_TheTokenAsksForTheFieldsOfTheCaller(t *testing.T) {
	for name, c := range map[string]supportsession.TokenCommand{
		"actor":       {ActorID: "x", ID: accessID, CorrelationID: "c"},
		"correlation": {ActorID: platform, ID: accessID, CorrelationID: ""},
	} {
		w := newWorld(t, nil)
		if _, err := w.service.Token(ctx, c); fieldOf(err) == "" {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(w.store.opens) != 0 {
			t.Errorf("%s: an access was opened", name)
		}
	}
}

func TestA_AFailureOfTheStoreOrTheSignerIsNotAnAnswerOfTheRules(t *testing.T) {
	w := newWorld(t, nil)
	w.store.err = errors.New("db down")
	if _, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c"}); err == nil || fieldOf(err) != "" ||
		errors.Is(err, supportsession.ErrNotFound) || errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("store: %v", err)
	}
	w = newWorld(t, nil)
	w.signer.err = errors.New("no key")
	if _, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c"}); err == nil || fieldOf(err) != "" ||
		errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("signer: %v", err)
	}
}

func TestA_ClosingCutsTheSessionsAndWritesTheFactInOneStoreCallWithTheReasonAndTheInstant(t *testing.T) {
	w := newWorld(t, nil)
	got, err := w.service.Close(ctx, supportsession.CloseCommand{ActorID: platform, ID: accessID, Reason: "The incident is solved", CorrelationID: "corr-2"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != supportaccess.Closed || got.ClosedReason != "The incident is solved" || !got.ClosedAt.Equal(now) {
		t.Fatalf("closed = %+v", got)
	}
	if len(w.store.closes) != 1 || w.store.closes[0].ID != accessID {
		t.Fatalf("closes = %+v", w.store.closes)
	}
}

func TestA_OnlyAnApprovedAccessOfTheCallerIsClosedWithAReason(t *testing.T) {
	for name, edit := range map[string]func(*supportaccess.Access){
		"pending": func(a *supportaccess.Access) { a.Status, a.ExpiresAt = supportaccess.Pending, time.Time{} },
		"closed":  func(a *supportaccess.Access) { a.Status = supportaccess.Closed },
		"ran out": func(a *supportaccess.Access) { a.ExpiresAt = now },
	} {
		w := newWorld(t, edit)
		if _, err := w.service.Close(ctx, supportsession.CloseCommand{ActorID: platform, ID: accessID, Reason: "done", CorrelationID: "c"}); !errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(w.store.closes) != 0 {
			t.Errorf("%s: a close was stored", name)
		}
	}
	w := newWorld(t, nil)
	if _, err := w.service.Close(ctx, supportsession.CloseCommand{ActorID: other, ID: accessID, Reason: "done", CorrelationID: "c"}); !errors.Is(err, supportsession.ErrNotFound) {
		t.Errorf("another administrator: %v", err)
	}
	for _, bad := range []string{"", "  ", strings.Repeat("x", 501)} {
		if _, err := w.service.Close(ctx, supportsession.CloseCommand{ActorID: platform, ID: accessID, Reason: bad, CorrelationID: "c"}); fieldOf(err) != "reason" {
			t.Errorf("reason %q: %v", bad, err)
		}
	}
	w.store.refuseClose = true
	if _, err := w.service.Close(ctx, supportsession.CloseCommand{ActorID: platform, ID: accessID, Reason: "done", CorrelationID: "c"}); !errors.Is(err, supportaccess.ErrInvalidTransition) {
		t.Errorf("a close that lost: %v", err)
	}
}

func TestA_NothingRunsWithoutItsPieces(t *testing.T) {
	if _, err := (&supportsession.Service{}).Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c"}); err == nil || fieldOf(err) != "" {
		t.Errorf("err = %v", err)
	}
	if _, err := (&supportsession.Service{}).Close(ctx, supportsession.CloseCommand{ActorID: platform, ID: accessID, Reason: "r", CorrelationID: "c"}); err == nil || fieldOf(err) != "" {
		t.Errorf("err = %v", err)
	}
}

// Between the opening and the re-read the access may be closed or run out: no token is signed for it.
func TestA_AnAccessThatEndedBetweenTheOpeningAndTheReadGivesNoToken(t *testing.T) {
	for name, edit := range map[string]func(*supportaccess.Access){
		"closed":  func(a *supportaccess.Access) { a.Status = supportaccess.Closed },
		"expired": func(a *supportaccess.Access) { a.Status = supportaccess.Expired },
		"over":    func(a *supportaccess.Access) { a.ExpiresAt = now },
	} {
		w := newWorld(t, nil)
		w.store.afterOpen = edit
		if _, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c"}); !errors.Is(err, supportaccess.ErrInvalidTransition) {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(w.signer.claims) != 0 {
			t.Errorf("%s: a token was signed", name)
		}
	}
}

// A failure to sign leaves the access open; the retry opens it again (the store writes no second fact) and gives the token.
func TestA_ARetryAfterAFailureToSignGivesTheTokenAndOpensAgain(t *testing.T) {
	w := newWorld(t, nil)
	w.signer.err = errors.New("no key")
	if _, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c"}); err == nil {
		t.Fatal("expected the failure")
	}
	w.signer.err = nil
	got, err := w.service.Token(ctx, supportsession.TokenCommand{ActorID: platform, ID: accessID, CorrelationID: "c"})
	if err != nil || got.AccessToken == "" || len(w.store.opens) != 2 || len(w.signer.claims) != 1 {
		t.Fatalf("err=%v opens=%d signed=%d", err, len(w.store.opens), len(w.signer.claims))
	}
}
