package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// End to end against PostgreSQL, through HTTP: a Tenant Administrator lists the internal users of their tenant
// (HU-SEC-005, RN-SEC-003-07). Every answer is validated against the tested contract.

type usersPage struct {
	Data []struct {
		Email         string   `json:"email"`
		Roles         []string `json:"roles"`
		AccountStatus string   `json:"accountStatus"`
	} `json:"data"`
	Meta struct{ Page, Limit, Total, TotalPages int }
}

func (s *stack) listUsers(t *testing.T, token, query string) (*httptest.ResponseRecorder, usersPage) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, usersURL+query, nil)
	req.Header.Set("X-Correlation-Id", "e2e-list")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	validateAgainstContract(t, req, rec)
	var page usersPage
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
	}
	return rec, page
}

func TestC_TheListShowsOnlyTheInternalUsersOfTheTenantOfTheCredentialAndFiltersAndPages(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	s.administrator(t, tenantB, "admin@example.com")
	s.account(t, tenantA, "manager@example.com", pgtest.Options{}, "MANAGER")
	s.account(t, tenantA, "gone@example.com", pgtest.Options{Inactive: true}, "MANAGER")
	s.account(t, tenantA, "customer@example.com", pgtest.Options{}, "FINAL_CUSTOMER")
	s.account(t, tenantB, "other@example.com", pgtest.Options{}, "ANALYST")

	rec, all := s.listUsers(t, admin, "")
	if rec.Code != http.StatusOK || all.Meta.Total != 3 || len(all.Data) != 3 || all.Meta.Page != 1 || all.Meta.Limit != 20 || all.Meta.TotalPages != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for _, u := range all.Data {
		if u.Email == "customer@example.com" || u.Email == "other@example.com" || len(u.Roles) != 1 {
			t.Fatalf("a user that is not of the tenant or not internal is listed: %s", rec.Body)
		}
	}
	if _, managers := s.listUsers(t, admin, "?role=MANAGER"); managers.Meta.Total != 2 {
		t.Fatalf("managers = %d", managers.Meta.Total)
	}
	if _, gone := s.listUsers(t, admin, "?status=INACTIVE"); gone.Meta.Total != 1 || gone.Data[0].Email != "gone@example.com" {
		t.Fatalf("inactive = %+v", gone)
	}
	if _, second := s.listUsers(t, admin, "?limit=2&page=2"); len(second.Data) != 1 || second.Meta.TotalPages != 2 || second.Meta.Total != 3 {
		t.Fatalf("second page = %+v", second)
	}
}

func TestC_TheListRefusesWhoIsNotAnAdministratorAndWhatIsNotValid(t *testing.T) {
	s := newStack(t)
	admin := s.administrator(t, tenantA, "admin@example.com")
	for query, want := range map[string]int{"?role=FINAL_CUSTOMER": 400, "?role=PLATFORM_ADMINISTRATOR": 400, "?status=DELETED": 400, "?page=0": 400,
		"?limit=0": 400, "?limit=101": 400, "?page=99999999999999999999": 400, "?tenantId=" + tenantB: 400} {
		if rec, _ := s.listUsers(t, admin, query); rec.Code != want {
			t.Errorf("%s: %d %s", query, rec.Code, rec.Body)
		}
	}
	if rec, _ := s.listUsers(t, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	s.account(t, tenantA, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	colab, _ := s.claims(t, s.signIn(tenantURL, "colab@example.com", password))
	if rec, _ := s.listUsers(t, colab.AccessToken, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a collaborator: %d %s", rec.Code, rec.Body)
	}
}
