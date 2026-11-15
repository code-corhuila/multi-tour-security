package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportdecision"
)

// HU-SEC-007 part A, security spec 009: the routes where a Tenant Administrator lists the support requests of their tenant and decides them
// (RN-SEC-009-03, -07). The Administrator of an inactive tenant does the same with the restricted access (AC2).

const (
	decisionsRoute = "/api/v1/security/support-accesses"
	requestID      = "55555555-5555-4555-8555-555555555555"
	tenantOfAdmin  = "3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f"
)

type fakeDecider struct {
	decisions []supportdecision.Decision
	rejected  []supportdecision.Decision
	queries   []supportdecision.Query
	access    supportaccess.Access
	page      supportdecision.Page
	err       error
}

func (f *fakeDecider) Approve(_ context.Context, d supportdecision.Decision) (supportaccess.Access, error) {
	f.decisions = append(f.decisions, d)
	return f.access, f.err
}

func (f *fakeDecider) Reject(_ context.Context, d supportdecision.Decision) (supportaccess.Access, error) {
	f.rejected = append(f.rejected, d)
	return f.access, f.err
}

func (f *fakeDecider) List(_ context.Context, q supportdecision.Query) (supportdecision.Page, error) {
	f.queries = append(f.queries, q)
	return f.page, f.err
}

func decisionHandler(svc httpadapter.SupportDecider, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithSupportDecisions(svc))
}

func adminOfTenant(t *testing.T) string {
	return tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, tenantOfAdmin, "")
}

func restrictedAdmin(t *testing.T) string {
	return tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, tenantOfAdmin, "restricted")
}

func approvedAccess() supportaccess.Access {
	a := askedAccess()
	a, _ = a.Approve("worker-event-relay", time.Date(2026, 11, 9, 11, 0, 0, 0, time.UTC))
	return a
}

func TestC_AnAdministratorApprovesAndTheUseCaseGetsTheTenantAndTheActorOfTheCredential(t *testing.T) {
	svc := &fakeDecider{access: approvedAccess()}
	rec := supportCall(decisionHandler(svc, io.Discard), http.MethodPost, decisionsRoute+"/"+requestID+"/approval", adminOfTenant(t), "", "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if len(svc.decisions) != 1 || svc.decisions[0] != (supportdecision.Decision{TenantID: tenantOfAdmin, ActorID: "worker-event-relay", ID: requestID}) {
		t.Fatalf("decisions = %+v", svc.decisions)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["status"] != "APPROVED" || out["expiresAt"] != "2026-11-09T15:00:00Z" {
		t.Fatalf("answer = %v %v", out, err)
	}
}

func TestC_AnAdministratorRejectsWithAReasonAndTheTenantIsNeverTakenFromThePath(t *testing.T) {
	a := askedAccess()
	a, _ = a.Reject("worker-event-relay", "Nobody asked for this", time.Date(2026, 11, 9, 11, 0, 0, 0, time.UTC))
	svc := &fakeDecider{access: a}
	rec := supportCall(decisionHandler(svc, io.Discard), http.MethodPost, decisionsRoute+"/"+requestID+"/rejection", adminOfTenant(t), "application/json", `{"reason":"Nobody asked for this"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(svc.rejected) != 1 || svc.rejected[0] != (supportdecision.Decision{TenantID: tenantOfAdmin, ActorID: "worker-event-relay", ID: requestID, Reason: "Nobody asked for this"}) {
		t.Fatalf("rejected = %+v", svc.rejected)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["status"] != "REJECTED" || out["decisionReason"] != "Nobody asked for this" {
		t.Fatalf("answer = %v %v", out, err)
	}
}

func TestC_TheAdministratorOfAnInactiveTenantDecidesWithTheRestrictedAccess(t *testing.T) {
	svc := &fakeDecider{access: approvedAccess(), page: supportdecision.Page{Data: []supportaccess.Access{askedAccess()}, Page: 1, Limit: 20, Total: 1, TotalPages: 1}}
	h := decisionHandler(svc, io.Discard)
	token := restrictedAdmin(t)
	if rec := supportCall(h, http.MethodGet, decisionsRoute, token, "", "", ""); rec.Code != http.StatusOK {
		t.Errorf("listing: %d %s", rec.Code, rec.Body)
	}
	if rec := supportCall(h, http.MethodPost, decisionsRoute+"/"+requestID+"/approval", token, "", "", ""); rec.Code != http.StatusOK {
		t.Errorf("approving: %d %s", rec.Code, rec.Body)
	}
	if rec := supportCall(h, http.MethodPost, decisionsRoute+"/"+requestID+"/rejection", token, "application/json", `{"reason":"no"}`, ""); rec.Code != http.StatusOK {
		t.Errorf("rejecting: %d %s", rec.Code, rec.Body)
	}
}

func TestC_OnlyAnAdministratorOfATenantWithAnOrdinaryOrRestrictedAccessGetsIn(t *testing.T) {
	tokens := map[string]string{
		"platform administrator":   tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""),
		"the token of an access":   tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, tenantOfAdmin, "exceptional"),
		"password change":          tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, tenantOfAdmin, "password-change"),
		"collaborator":             tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, tenantOfAdmin, ""),
		"customer":                 tokenWith(t, []string{"FINAL_CUSTOMER"}, tenantOfAdmin, ""),
		"administrator, no tenant": tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, "", ""),
		"service with no role":     tokenWith(t, nil, "", ""),
	}
	for name, token := range tokens {
		svc := &fakeDecider{access: approvedAccess()}
		h := decisionHandler(svc, io.Discard)
		for _, call := range []struct{ method, path, ctype, body string }{
			{http.MethodGet, decisionsRoute, "", ""},
			{http.MethodPost, decisionsRoute + "/" + requestID + "/approval", "", ""},
			{http.MethodPost, decisionsRoute + "/" + requestID + "/rejection", "application/json", `{"reason":"no"}`},
		} {
			if rec := supportCall(h, call.method, call.path, token, call.ctype, call.body, ""); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s: %d", name, call.method, call.path, rec.Code)
			}
		}
		if len(svc.decisions)+len(svc.rejected)+len(svc.queries) != 0 {
			t.Errorf("%s reached the use case", name)
		}
	}
	h := decisionHandler(&fakeDecider{}, io.Discard)
	for _, path := range []string{decisionsRoute, decisionsRoute + "/" + requestID + "/approval"} {
		method := http.MethodGet
		if strings.HasSuffix(path, "approval") {
			method = http.MethodPost
		}
		if rec := supportCall(h, method, path, "", "", "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("no token %s: %d", path, rec.Code)
		}
	}
}

func TestC_TheDecisionIsAnsweredWithTheCodeOfWhatTheUseCaseRefused(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"not found":     {supportdecision.ErrNotFound, http.StatusNotFound, "NOT_FOUND"},
		"not pending":   {supportaccess.ErrInvalidTransition, http.StatusUnprocessableEntity, "INVALID_STATUS_TRANSITION"},
		"reason":        {&supportdecision.FieldError{Field: "reason", Err: errors.New("is not valid")}, http.StatusBadRequest, "VALIDATION_ERROR"},
		"store failure": {errors.New("pq: connection refused at db-host-7"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for name, c := range cases {
		var logs strings.Builder
		svc := &fakeDecider{err: c.err}
		rec := supportCall(decisionHandler(svc, &logs), http.MethodPost, decisionsRoute+"/"+requestID+"/rejection", adminOfTenant(t), "application/json", `{"reason":"no"}`, "")
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.code) || strings.Contains(rec.Body.String(), "db-host-7") || strings.Contains(logs.String(), "db-host-7") {
			t.Errorf("%s: %d %s / %s", name, rec.Code, rec.Body, logs.String())
		}
	}
	// the tenant and the actor come from the credential, so a fault in them is ours and never the caller's
	svc := &fakeDecider{err: &supportdecision.FieldError{Field: "actorId", Err: errors.New("is not valid")}}
	if rec := supportCall(decisionHandler(svc, io.Discard), http.MethodPost, decisionsRoute+"/"+requestID+"/approval", adminOfTenant(t), "", "", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("actorId: %d", rec.Code)
	}
}

func TestC_ARejectionBodyIsReadStrictly(t *testing.T) {
	cases := map[string]struct {
		ctype, body string
		status      int
	}{
		"not json":      {"text/plain", `{"reason":"no"}`, http.StatusUnsupportedMediaType},
		"broken":        {"application/json", `{"reason":`, http.StatusBadRequest},
		"unknown field": {"application/json", `{"reason":"no","tenantId":"x"}`, http.StatusBadRequest},
		"not a string":  {"application/json", `{"reason":7}`, http.StatusBadRequest},
		"too large":     {"application/json", `{"reason":"` + strings.Repeat("r", 4200) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for name, c := range cases {
		svc := &fakeDecider{}
		rec := supportCall(decisionHandler(svc, io.Discard), http.MethodPost, decisionsRoute+"/"+requestID+"/rejection", adminOfTenant(t), c.ctype, c.body, "")
		if rec.Code != c.status || len(svc.rejected) != 0 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestC_TheListIsOfTheTenantOfTheCredentialAndItsParametersAreTheDeclaredOnes(t *testing.T) {
	svc := &fakeDecider{page: supportdecision.Page{Data: []supportaccess.Access{askedAccess()}, Page: 2, Limit: 10, Total: 11, TotalPages: 2}}
	h := decisionHandler(svc, io.Discard)
	rec := supportCall(h, http.MethodGet, decisionsRoute+"?page=2&limit=10&status=PENDING", adminOfTenant(t), "", "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if len(svc.queries) != 1 || svc.queries[0] != (supportdecision.Query{TenantID: tenantOfAdmin, Status: "PENDING", Page: 2, Limit: 10}) {
		t.Fatalf("query = %+v", svc.queries)
	}
	var out struct {
		Data []map[string]any
		Meta map[string]int
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Data) != 1 || out.Meta["total"] != 11 || out.Meta["totalPages"] != 2 {
		t.Fatalf("answer = %s %v", rec.Body, err)
	}
	for _, bad := range []string{"?tenantId=x", "?status=", "?status=A&status=B", "?page=x", "?limit=-1"} {
		before := len(svc.queries)
		if rec := supportCall(h, http.MethodGet, decisionsRoute+bad, adminOfTenant(t), "", "", ""); rec.Code != http.StatusBadRequest || len(svc.queries) != before {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
}

// The exception is narrow: the restricted access reaches these three routes and no other route of the Administrator keeps it out any less.
func TestC_TheRestrictedAccessStillGetsNoOtherRouteOfTheAdministrator(t *testing.T) {
	svc := &fakeLister{page: onePage()}
	if rec := getUsers(listHandler(svc, io.Discard), restrictedAdmin(t), ""); rec.Code != http.StatusForbidden || len(svc.queries) != 0 {
		t.Fatalf("the list of users: %d", rec.Code)
	}
}
