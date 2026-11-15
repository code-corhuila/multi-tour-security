package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	httpadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/http"
	"github.com/code-corhuila/multi-tour-security/internal/core/listusers"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

// HU-SEC-005, RN-SEC-003-07: the route that lists the internal users of the tenant of the credential.

type fakeLister struct {
	queries []listusers.Query
	page    listusers.Page
	err     error
}

func (f *fakeLister) List(_ context.Context, q listusers.Query) (listusers.Page, error) {
	f.queries = append(f.queries, q)
	return f.page, f.err
}

func listHandler(svc httpadapter.UserLister, logs io.Writer) http.Handler {
	return httpadapter.New(httpadapter.NewVerifier(&routeKey.PublicKey), slog.New(slog.NewJSONHandler(logs, nil)), httpadapter.WithListInternalUsers(svc))
}

func getUsers(h http.Handler, token, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, usersRoute+query, nil)
	req.Header.Set("X-Correlation-Id", "list-1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func onePage() listusers.Page {
	return listusers.Page{Data: []port.Registered{registeredUser()}, Page: 1, Limit: 20, Total: 1, TotalPages: 1}
}

func TestC_TheListAsksForTheTenantOfTheTokenWithTheDefaultsAndAnswersTheEnvelope(t *testing.T) {
	svc := &fakeLister{page: onePage()}
	rec := getUsers(listHandler(svc, io.Discard), administrator(t), "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if want := (listusers.Query{TenantID: accountTenant, Page: 1, Limit: 20}); len(svc.queries) != 1 || svc.queries[0] != want {
		t.Fatalf("the use case was asked %+v", svc.queries)
	}
	var out struct {
		Data []map[string]any
		Meta map[string]int
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Data) != 1 || out.Data[0]["email"] != "carlos.gomez@example.com" || out.Meta["page"] != 1 || out.Meta["limit"] != 20 || out.Meta["total"] != 1 || out.Meta["totalPages"] != 1 {
		t.Fatalf("the answer is %s", rec.Body)
	}
	for _, secret := range []string{"must-never-show", "Hash", "password"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the list shows %q: %s", secret, rec.Body)
		}
	}
}

func TestC_TheFiltersPageAndLimitReachTheUseCase(t *testing.T) {
	svc := &fakeLister{page: onePage()}
	rec := getUsers(listHandler(svc, io.Discard), administrator(t), "?page=3&limit=50&role=MANAGER&status=INACTIVE")
	want := listusers.Query{TenantID: accountTenant, Role: "MANAGER", Status: "INACTIVE", Page: 3, Limit: 50}
	if rec.Code != http.StatusOK || len(svc.queries) != 1 || svc.queries[0] != want {
		t.Fatalf("%d %+v", rec.Code, svc.queries)
	}
}

func TestC_AnEmptyListIsAnEmptyArrayAndNeverNull(t *testing.T) {
	rec := getUsers(listHandler(&fakeLister{page: listusers.Page{Data: []port.Registered{}, Page: 1, Limit: 20}}, io.Discard), administrator(t), "")
	if !strings.Contains(rec.Body.String(), `"data":[]`) {
		t.Fatalf("%s", rec.Body)
	}
}

func TestC_AFilterThatIsNotDeclaredOrAValueThatCannotBeReadIsA400AndTheUseCaseIsNotAsked(t *testing.T) {
	for _, query := range []string{"?tenantId=" + otherTenantID, "?sort=email", "?page=-1", "?page=abc", "?limit=20&limit=30",
		"?role=MANAGER&role=ANALYST", "?role=", "?status=", "?role", "?page=", "?limit=", "?page=99999999999999999999", "?%zz"} {
		svc := &fakeLister{page: onePage()}
		rec := getUsers(listHandler(svc, io.Discard), administrator(t), query)
		if rec.Code != http.StatusBadRequest || len(svc.queries) != 0 {
			t.Errorf("%s: %d, asked %d times: %s", query, rec.Code, len(svc.queries), rec.Body)
		}
	}
}

func TestC_ARefusalOfTheUseCaseIs400NamingTheField(t *testing.T) {
	rec := getUsers(listHandler(&fakeLister{err: &listusers.FieldError{Field: "role"}}, io.Discard), administrator(t), "?role=FINAL_CUSTOMER")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"role"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestC_APageOrALimitOutOfRangeIsA400NamingItAndATenantThatIsNotAnIdIsNeverTheCallersFault(t *testing.T) {
	for _, field := range []string{"page", "limit"} {
		rec := getUsers(listHandler(&fakeLister{err: &listusers.FieldError{Field: field}}, io.Discard), administrator(t), "?"+field+"=0")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"`+field+`"`) {
			t.Errorf("%s: %d %s", field, rec.Code, rec.Body)
		}
	}
	if rec := getUsers(listHandler(&fakeLister{err: &listusers.FieldError{Field: "tenantId"}}, io.Discard), administrator(t), ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("a credential whose tenant is not an id is a failure of ours, not a 400: %d %s", rec.Code, rec.Body)
	}
}

func TestC_OnlyATenantAdministratorWithAnOrdinaryCredentialSeesTheList(t *testing.T) {
	for who, token := range map[string]string{
		"a collaborator":              tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""),
		"a customer":                  tokenWith(t, []string{"FINAL_CUSTOMER"}, accountTenant, ""),
		"the Platform Administrator":  tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""),
		"an Administrator, no tenant": tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, "", ""),
		"a temporary credential":      tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "password-change"),
	} {
		svc := &fakeLister{page: onePage()}
		if rec := getUsers(listHandler(svc, io.Discard), token, ""); rec.Code != http.StatusForbidden || len(svc.queries) != 0 {
			t.Errorf("%s: %d, asked %d times", who, rec.Code, len(svc.queries))
		}
	}
	if rec := getUsers(listHandler(&fakeLister{}, io.Discard), "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
}

func TestC_AFailureOfTheListNeverLeaksItsCause(t *testing.T) {
	var logs strings.Builder
	rec := getUsers(listHandler(&fakeLister{err: errors.New("pq: password=hunter2")}, &logs), administrator(t), "")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(logs.String(), "hunter2") {
		t.Fatalf("%d %s | %s", rec.Code, rec.Body, logs.String())
	}
}

// HU-SEC-006, RN-SEC-005-08: every answer that carries a user shows the whole set of permissions that its credential carries.

func permissionsOf(t *testing.T, body []byte) [][]string {
	t.Helper()
	var out struct {
		Data []struct {
			Permissions []string `json:"permissions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	var all [][]string
	for _, u := range out.Data {
		all = append(all, u.Permissions)
	}
	return all
}

func TestC_TheListShowsThePermissionsOfEachUserAsTheCredentialCarriesThem(t *testing.T) {
	admin, colab, manager := registeredUser(), registeredUser(), registeredUser()
	admin.Role = "TENANT_ADMINISTRATOR"
	colab.Role, colab.Permissions = "OPERATIONAL_COLLABORATOR", []string{"MANAGE_CASH", "CONSULT_SENSITIVE_DATA"}
	manager.Role, manager.Permissions = "MANAGER", []string{"MANAGE_CASH"} // a stray row that no role may hold
	page := listusers.Page{Data: []port.Registered{admin, colab, manager}, Page: 1, Limit: 20, Total: 3, TotalPages: 1}
	rec := getUsers(listHandler(&fakeLister{page: page}, io.Discard), administrator(t), "")
	got := permissionsOf(t, rec.Body.Bytes())
	want := [][]string{
		{"MANAGE_CASH", "MANAGE_DEPARTURE_EXECUTION", "VALIDATE_PAYMENT_PROOFS"}, // the Administrator's three by profile, nothing assigned
		{"CONSULT_SENSITIVE_DATA", "MANAGE_CASH"},                                // what was assigned, sorted
		{}, // a manager holds none, whatever was written
	}
	if len(got) != 3 {
		t.Fatalf("%s", rec.Body)
	}
	for i := range want {
		if got[i] == nil || !slices.Equal(got[i], want[i]) {
			t.Errorf("user %d shows %v, want %v", i, got[i], want[i])
		}
	}
	if !strings.Contains(rec.Body.String(), `"permissions":[]`) {
		t.Errorf("a user with none must show an empty list and not null: %s", rec.Body)
	}
}

func TestC_TheAnswerThatRegistersAUserShowsItsPermissionsToo(t *testing.T) {
	svc := &fakeCreator{reg: registeredUser(), created: true}
	rec := postUser(usersHandler(svc, io.Discard), administrator(t), "application/json", userBody, usersKey)
	if !strings.Contains(rec.Body.String(), `"permissions":[]`) {
		t.Fatalf("a new collaborator holds none: %s", rec.Body)
	}
}
