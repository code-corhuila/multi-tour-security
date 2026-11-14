package httpadapter_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"

	"github.com/code-corhuila/multi-tour-security/internal/core/changepassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/changepermission"
	"github.com/code-corhuila/multi-tour-security/internal/core/changestatus"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/issuetemp"
	"github.com/code-corhuila/multi-tour-security/internal/core/listusers"
	"github.com/code-corhuila/multi-tour-security/internal/core/optionalrole"
	"github.com/code-corhuila/multi-tour-security/internal/core/outbox"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/recoverpassword"
	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportaccess"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportdecision"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportemergency"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportrequest"
	"github.com/code-corhuila/multi-tour-security/internal/core/supportsession"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenantevent"
	"github.com/code-corhuila/multi-tour-security/internal/core/verifyemail"
)

// Every answer is validated against the published contract, each scenario says the status it must give, and the last
// check fails when a response declared by an operation of the contract was never produced: that is the gate toward
// qa (ADR-004 D7).
func TestC_EveryResponseOfEveryContractOperationIsProducedAndValid(t *testing.T) {
	ctx := context.Background()
	doc, err := openapi3.NewLoader().LoadFromFile("../../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(ctx); err != nil {
		t.Fatalf("the contract is not valid: %v", err)
	}
	router, err := legacy.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}

	big := `{"email":"ana@example.com","password":"` + strings.Repeat("p", 4096) + `"}`
	type scenario struct {
		method, path, contentType, body string
		svc                             *fakeSignIn
		refresh                         *fakeRefresh
		change                          *fakeChange
		token                           string
		want                            int
	}
	scenarios := []scenario{{method: http.MethodGet, path: "/health", want: http.StatusOK}}
	for _, route := range []string{tenantRoute, platformRoute} {
		scenarios = append(scenarios,
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{tokens: okTokens()}, nil, nil, "", http.StatusOK},
			scenario{http.MethodPost, route, "application/json", goodBodyWithSide, &fakeSignIn{tokens: okTokens()}, nil, nil, "", http.StatusOK},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: signin.ErrRefused}, nil, nil, "", http.StatusUnauthorized},
			scenario{http.MethodPost, route, "application/json", `{"email":`, &fakeSignIn{}, nil, nil, "", http.StatusBadRequest},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: signin.ErrInvalidRequest}, nil, nil, "", http.StatusBadRequest},
			scenario{http.MethodPost, route, "text/plain", goodBody, &fakeSignIn{}, nil, nil, "", http.StatusUnsupportedMediaType},
			scenario{http.MethodPost, route, "application/json", big, &fakeSignIn{}, nil, nil, "", http.StatusRequestEntityTooLarge},
			scenario{http.MethodPost, route, "application/json", goodBody, &fakeSignIn{err: errors.New("boom")}, nil, nil, "", http.StatusInternalServerError},
		)
	}

	// a pending account that gives its right password is told to verify its e-mail
	scenarios = append(scenarios, scenario{http.MethodPost, tenantRoute, "application/json", goodBody, &fakeSignIn{err: signin.ErrEmailNotVerified}, nil, nil, "", http.StatusForbidden})

	bigRefresh := `{"refreshToken":"` + strings.Repeat("r", 4200) + `"}`
	for _, r := range []struct {
		contentType, body string
		svc               *fakeRefresh
		want              int
	}{
		{"application/json", refreshBody, &fakeRefresh{tokens: okTokens()}, http.StatusOK},
		{"application/json", refreshBody, &fakeRefresh{err: signin.ErrRefused}, http.StatusUnauthorized},
		{"application/json", `{"refreshToken":`, &fakeRefresh{}, http.StatusBadRequest},
		{"text/plain", refreshBody, &fakeRefresh{}, http.StatusUnsupportedMediaType},
		{"application/json", bigRefresh, &fakeRefresh{}, http.StatusRequestEntityTooLarge},
		{"application/json", refreshBody, &fakeRefresh{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		scenarios = append(scenarios, scenario{method: http.MethodPost, path: refreshRoute, contentType: r.contentType, body: r.body, refresh: r.svc, want: r.want})
	}

	bigPassword := `{"newPassword":"` + strings.Repeat("p", 4200) + `"}`
	pc := bearer(t, "password-change")
	for _, c := range []struct {
		token, contentType, body string
		svc                      *fakeChange
		want                     int
	}{
		{pc, "application/json", passwordBody, &fakeChange{}, http.StatusNoContent},
		{"", "application/json", passwordBody, &fakeChange{}, http.StatusUnauthorized},
		{pc, "application/json", passwordBody, &fakeChange{err: signin.ErrRefused}, http.StatusUnauthorized},
		{pc, "application/json", `{"newPassword":`, &fakeChange{}, http.StatusBadRequest},
		{pc, "application/json", passwordBody, &fakeChange{err: changepassword.ErrWeakPassword}, http.StatusBadRequest},
		{pc, "text/plain", passwordBody, &fakeChange{}, http.StatusUnsupportedMediaType},
		{pc, "application/json", bigPassword, &fakeChange{}, http.StatusRequestEntityTooLarge},
		{pc, "application/json", passwordBody, &fakeChange{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		scenarios = append(scenarios, scenario{method: http.MethodPut, path: passwordRoute, contentType: c.contentType, body: c.body, change: c.svc, token: c.token, want: c.want})
	}

	key := newKey(t)
	exercised := map[string]bool{}
	run := func(handler http.Handler, method, path, contentType, body, token string, want int) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("X-Correlation-Id", "gate-1")
		if strings.HasSuffix(path, "/events") || strings.HasSuffix(path, "/accounts") || strings.HasSuffix(path, "/administrators") || strings.HasSuffix(path, "/users") || strings.HasSuffix(path, "/platform-support-accesses") || strings.HasSuffix(path, "/platform-emergency-accesses") {
			req.Header.Set("Idempotency-Key", eventKey)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s %s: status %d, want %d (%s)", method, path, rec.Code, want, rec.Body)
			return
		}

		route, params, err := router.FindRoute(req)
		if err != nil {
			t.Fatalf("%s %s is not in the contract: %v", method, path, err)
		}
		response := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route},
			Status:                 rec.Code,
			Header:                 rec.Header(),
			Options:                &openapi3filter.Options{IncludeResponseStatus: true},
		}
		response.SetBodyBytes(rec.Body.Bytes())
		if err := openapi3filter.ValidateResponse(ctx, response); err != nil {
			t.Errorf("%s %s answered %d against the contract: %v", method, path, rec.Code, err)
		}
		exercised[method+" "+route.Path+" "+strconv.Itoa(rec.Code)] = true
	}
	for _, s := range scenarios {
		handler := newHandler(key)
		if s.svc != nil {
			handler = signInHandler(s.svc, io.Discard)
		}
		if s.refresh != nil {
			handler = refreshHandler(s.refresh, io.Discard)
		}
		if s.change != nil {
			handler = changeHandler(s.change, io.Discard)
		}
		run(handler, s.method, s.path, s.contentType, s.body, s.token, s.want)
	}

	// the internal routes: only the token of a service, and the answers of the use case as they come
	svcToken := serviceBearer(t)
	page := outbox.Page{Data: []outbox.Event{sampleEvent()}, Page: 1, Limit: 20, Total: 1, TotalPages: 1}
	bigAttempt := `{"error":"` + strings.Repeat("e", 4200) + `"}`
	for _, c := range []struct {
		method, path, contentType, body, token string
		svc                                    *fakeOutbox
		want                                   int
	}{
		{http.MethodGet, outboxRoute, "", "", svcToken, &fakeOutbox{page: page}, http.StatusOK},
		{http.MethodGet, outboxRoute + "?limit=500", "", "", svcToken, &fakeOutbox{}, http.StatusBadRequest},
		{http.MethodGet, outboxRoute, "", "", "", &fakeOutbox{}, http.StatusUnauthorized},
		{http.MethodGet, outboxRoute, "", "", tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", ""), &fakeOutbox{}, http.StatusForbidden},
		{http.MethodGet, outboxRoute, "", "", svcToken, &fakeOutbox{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodPost, publishedPath, "", "", svcToken, &fakeOutbox{event: sampleEvent()}, http.StatusOK},
		{http.MethodPost, publishedPath, "", "", "", &fakeOutbox{}, http.StatusUnauthorized},
		{http.MethodPost, publishedPath, "", "", tokenWith(t, nil, "", ""), &fakeOutbox{}, http.StatusForbidden},
		{http.MethodPost, publishedPath, "", "", svcToken, &fakeOutbox{err: outbox.ErrNotFound}, http.StatusNotFound},
		{http.MethodPost, publishedPath, "", "", svcToken, &fakeOutbox{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, svcToken, &fakeOutbox{event: sampleEvent()}, http.StatusOK},
		{http.MethodPost, attemptsPath, "application/json", `{"error":`, svcToken, &fakeOutbox{}, http.StatusBadRequest},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, "", &fakeOutbox{}, http.StatusUnauthorized},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, tokenWith(t, []string{"ANALYST"}, "t-1", ""), &fakeOutbox{}, http.StatusForbidden},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, svcToken, &fakeOutbox{err: outbox.ErrNotFound}, http.StatusNotFound},
		{http.MethodPost, attemptsPath, "text/plain", `{"error":"503"}`, svcToken, &fakeOutbox{}, http.StatusUnsupportedMediaType},
		{http.MethodPost, attemptsPath, "application/json", bigAttempt, svcToken, &fakeOutbox{}, http.StatusRequestEntityTooLarge},
		{http.MethodPost, attemptsPath, "application/json", `{"error":"503"}`, svcToken, &fakeOutbox{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(outboxHandler(c.svc, io.Discard), c.method, c.path, c.contentType, c.body, c.token, c.want)
	}

	// the receiver of the events of a tenant, with the id of the event as its idempotency key
	bigEvent := strings.Replace(envelopeJSON("TenantCreated", "ACTIVE"), `"country":"CO"`, `"notes":"`+strings.Repeat("n", 17000)+`"`, 1)
	for _, c := range []struct {
		contentType, body, token string
		svc                      *fakeTenantEvents
		want                     int
	}{
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{applied: true}, http.StatusCreated},
		{"application/json", envelopeJSON("TenantInactivated", "INACTIVE"), svcToken, &fakeTenantEvents{applied: false}, http.StatusOK},
		{"application/json", `{"eventId":`, svcToken, &fakeTenantEvents{}, http.StatusBadRequest},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{err: tenantevent.ErrInvalid}, http.StatusBadRequest},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), "", &fakeTenantEvents{}, http.StatusUnauthorized},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, eventTenant, ""), &fakeTenantEvents{}, http.StatusForbidden},
		{"text/plain", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{}, http.StatusUnsupportedMediaType},
		{"application/json", bigEvent, svcToken, &fakeTenantEvents{}, http.StatusRequestEntityTooLarge},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{err: errors.New("boom")}, http.StatusInternalServerError},
		{"application/json", envelopeJSON("TenantCreated", "ACTIVE"), svcToken, &fakeTenantEvents{err: tenantevent.ErrRetryLater}, http.StatusServiceUnavailable},
	} {
		run(eventsHandler(c.svc, io.Discard), http.MethodPost, eventsPath, c.contentType, c.body, c.token, c.want)
	}

	// the account of a Final Customer: created, repeated, and every refusal the use case can give
	bigAccount := `{"firstName":"` + strings.Repeat("a", 4200) + `"}`
	known, unknown := &fakeTenantFinder{found: true}, &fakeTenantFinder{}
	for _, c := range []struct {
		contentType, body string
		svc               *fakeCreator
		tenants           *fakeTenantFinder
		want              int
	}{
		{"application/json", customerBody, &fakeCreator{reg: registered(), created: true}, known, http.StatusCreated},
		{"application/json", customerBody, &fakeCreator{reg: registered()}, known, http.StatusOK},
		{"application/json", customerBody, &fakeCreator{reg: pendingRegistered(), created: true}, known, http.StatusCreated},
		{"application/json", `{"firstName":`, &fakeCreator{}, known, http.StatusBadRequest},
		{"application/json", customerBody, &fakeCreator{err: &createaccount.FieldError{Field: "password", Err: errors.New("weak")}}, known, http.StatusBadRequest},
		{"application/json", customerBody, &fakeCreator{}, unknown, http.StatusNotFound},
		{"application/json", customerBody, &fakeCreator{err: createaccount.ErrTenantNotFound}, known, http.StatusNotFound},
		{"text/plain", customerBody, &fakeCreator{}, known, http.StatusUnsupportedMediaType},
		{"application/json", bigAccount, &fakeCreator{}, known, http.StatusRequestEntityTooLarge},
		{"application/json", customerBody, &fakeCreator{err: port.ErrEmailTaken}, known, http.StatusUnprocessableEntity},
		{"application/json", customerBody, &fakeCreator{err: errors.New("boom")}, known, http.StatusInternalServerError},
	} {
		run(accountsHandler(c.svc, c.tenants, io.Discard), http.MethodPost, accountsRoute, c.contentType, c.body, "", c.want)
	}

	// asking for a new link is always 202 when the body is well formed
	bigAsk := `{"email":"` + strings.Repeat("a", 4200) + `"}`
	for _, c := range []struct {
		path, contentType, body string
		err                     error
		want                    int
	}{
		{requestRoute, "application/json", askBody, nil, http.StatusAccepted},
		{requestRoute, "application/json", askBody, errors.New("boom"), http.StatusAccepted},
		{requestRoute, "application/json", `{"email":`, nil, http.StatusBadRequest},
		{requestRoute, "application/json", `{"email":"no-at-sign"}`, nil, http.StatusBadRequest},
		{requestRoute, "text/plain", askBody, nil, http.StatusUnsupportedMediaType},
		{requestRoute, "application/json", bigAsk, nil, http.StatusRequestEntityTooLarge},
	} {
		handler := askHandler(&fakeRequester{err: c.err}, background(time.Second), io.Discard)
		run(handler, http.MethodPost, c.path, c.contentType, c.body, "", c.want)
	}

	// confirming the e-mail has its own answers
	bigConfirm := `{"token":"` + linkToken + `","password":"` + strings.Repeat("p", 4200) + `"}`
	for _, c := range []struct {
		contentType, body string
		err               error
		want              int
	}{
		{"application/json", confirmBody, nil, http.StatusNoContent},
		{"application/json", `{"token":`, nil, http.StatusBadRequest},
		{"application/json", confirmBody, verifyemail.ErrInvalidRequest, http.StatusBadRequest},
		{"application/json", confirmBody, verifyemail.ErrWrongPassword, http.StatusUnauthorized},
		{"application/json", confirmBody, verifyemail.ErrTenantNotFound, http.StatusNotFound},
		{"application/json", bigConfirm, nil, http.StatusRequestEntityTooLarge},
		{"text/plain", confirmBody, nil, http.StatusUnsupportedMediaType},
		{"application/json", confirmBody, verifyemail.ErrBadLink, http.StatusUnprocessableEntity},
		{"application/json", confirmBody, errors.New("boom"), http.StatusInternalServerError},
	} {
		handler := verificationHandler(&fakeRequester{}, &fakeConfirmer{err: c.err}, background(time.Second), io.Discard)
		run(handler, http.MethodPost, confirmRoute, c.contentType, c.body, "", c.want)
	}

	// the password recovery (HU-SEC-004): asking is always 202 when the body is well formed, and a reset has its own answers,
	// for a tenant and for the platform
	bigRecoveryAsk := `{"email":"` + strings.Repeat("a", 4200) + `"}`
	bigReset := `{"email":"ana@example.com","code":"` + resetCode + `","newPassword":"` + strings.Repeat("p", 4200) + `","newPasswordConfirmation":"x"}`
	for _, route := range []string{askRecoveryRoute, askPlatformRoute} {
		for _, c := range []struct {
			contentType, body string
			err               error
			want              int
		}{
			{"application/json", askRecoveryBody, nil, http.StatusAccepted},
			{"application/json", askRecoveryBody, errors.New("boom"), http.StatusAccepted},
			{"application/json", `{"email":`, nil, http.StatusBadRequest},
			{"application/json", `{"email":"no-at-sign"}`, nil, http.StatusBadRequest},
			{"text/plain", askRecoveryBody, nil, http.StatusUnsupportedMediaType},
			{"application/json", bigRecoveryAsk, nil, http.StatusRequestEntityTooLarge},
		} {
			run(recoveryHandler(&fakeRecoveryRequester{err: c.err}, &fakeResetter{}, background(time.Second), io.Discard), http.MethodPost, route, c.contentType, c.body, "", c.want)
		}
	}
	for _, route := range []string{resetRoute, resetPlatformRoute} {
		for _, c := range []struct {
			contentType, body string
			err               error
			want              int
		}{
			{"application/json", resetBody, nil, http.StatusNoContent},
			{"application/json", `{"email":`, nil, http.StatusBadRequest},
			{"application/json", resetBody, &recoverpassword.FieldError{Field: "newPassword"}, http.StatusBadRequest},
			{"application/json", resetBody, recoverpassword.ErrCodeRefused, http.StatusUnprocessableEntity},
			{"application/json", resetBody, recoverpassword.ErrTenantNotFound, http.StatusNotFound},
			{"application/json", bigReset, nil, http.StatusRequestEntityTooLarge},
			{"text/plain", resetBody, nil, http.StatusUnsupportedMediaType},
			{"application/json", resetBody, errors.New("boom"), http.StatusInternalServerError},
		} {
			if route == resetPlatformRoute && c.want == http.StatusNotFound {
				continue // the platform has no tenant to be unknown
			}
			run(recoveryHandler(&fakeRecoveryRequester{}, &fakeResetter{err: c.err}, background(time.Second), io.Discard), http.MethodPost, route, c.contentType, c.body, "", c.want)
		}
	}

	// the first Administrator of a tenant, for the saga: only a service, and every answer of the use case
	bigAdmin := `{"fullName":"` + strings.Repeat("a", 4200) + `"}`
	for _, c := range []struct {
		contentType, body, token string
		svc                      *fakeCreator
		want                     int
	}{
		{"application/json", adminBody, svcToken, &fakeCreator{reg: temporaryAdmin(), created: true}, http.StatusCreated},
		{"application/json", adminBody, svcToken, &fakeCreator{reg: temporaryAdmin()}, http.StatusOK},
		{"application/json", `{"fullName":`, svcToken, &fakeCreator{}, http.StatusBadRequest},
		{"application/json", adminBody, svcToken, &fakeCreator{err: &createaccount.FieldError{Field: "password", Err: errors.New("weak")}}, http.StatusBadRequest},
		{"application/json", adminBody, "", &fakeCreator{}, http.StatusUnauthorized},
		{"application/json", adminBody, tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, ""), &fakeCreator{}, http.StatusForbidden},
		{"text/plain", adminBody, svcToken, &fakeCreator{}, http.StatusUnsupportedMediaType},
		{"application/json", bigAdmin, svcToken, &fakeCreator{}, http.StatusRequestEntityTooLarge},
		{"application/json", adminBody, svcToken, &fakeCreator{err: port.ErrEmailTaken}, http.StatusUnprocessableEntity},
		{"application/json", adminBody, svcToken, &fakeCreator{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(adminHandler(c.svc, io.Discard), http.MethodPost, adminRoute, c.contentType, c.body, c.token, c.want)
	}

	// an internal user of the tenant: only an Administrator's ordinary token, and every answer of the use case
	bigUser := `{"fullName":"` + strings.Repeat("a", 4200) + `"}`
	admin := tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "")
	for _, c := range []struct {
		contentType, body, token string
		svc                      *fakeCreator
		want                     int
	}{
		{"application/json", userBody, admin, &fakeCreator{reg: registeredUser(), created: true}, http.StatusCreated},
		{"application/json", userBody, admin, &fakeCreator{reg: registeredUser()}, http.StatusOK},
		{"application/json", `{"fullName":`, admin, &fakeCreator{}, http.StatusBadRequest},
		{"application/json", userBody, admin, &fakeCreator{err: &createaccount.FieldError{Field: "role", Err: errors.New("is not valid")}}, http.StatusBadRequest},
		{"application/json", userBody, "", &fakeCreator{}, http.StatusUnauthorized},
		{"application/json", userBody, tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""), &fakeCreator{}, http.StatusForbidden},
		{"text/plain", userBody, admin, &fakeCreator{}, http.StatusUnsupportedMediaType},
		{"application/json", bigUser, admin, &fakeCreator{}, http.StatusRequestEntityTooLarge},
		{"application/json", userBody, admin, &fakeCreator{err: &createaccount.EmailTakenError{Reason: createaccount.TakenByInactiveInternalUser}}, http.StatusUnprocessableEntity},
		{"application/json", userBody, admin, &fakeCreator{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(usersHandler(c.svc, io.Discard), http.MethodPost, usersRoute, c.contentType, c.body, c.token, c.want)
	}

	// the list of the internal users: only an Administrator's ordinary token, and every answer of the use case
	list := &fakeLister{page: onePage()}
	for _, c := range []struct {
		query, token string
		svc          *fakeLister
		want         int
	}{
		{"", admin, list, http.StatusOK},
		{"?page=2&limit=10&role=MANAGER&status=ACTIVE", admin, list, http.StatusOK},
		{"?sort=email", admin, list, http.StatusBadRequest},
		{"?role=FINAL_CUSTOMER", admin, &fakeLister{err: &listusers.FieldError{Field: "role"}}, http.StatusBadRequest},
		{"", "", list, http.StatusUnauthorized},
		{"", tokenWith(t, []string{"MANAGER"}, accountTenant, ""), list, http.StatusForbidden},
		{"", admin, &fakeLister{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(listHandler(c.svc, io.Discard), http.MethodGet, usersRoute+c.query, "", "", c.token, c.want)
	}

	// inactivating and reactivating: only an Administrator's ordinary token, and every answer of the use case
	for _, path := range []string{inactivate, reactivate} {
		for _, c := range []struct {
			contentType, body, token string
			svc                      *fakeStatus
			want                     int
		}{
			{"application/json", reasonBody, admin, &fakeStatus{reg: registeredUser()}, http.StatusOK},
			{"application/json", `{"reason":`, admin, &fakeStatus{}, http.StatusBadRequest},
			{"application/json", reasonBody, admin, &fakeStatus{err: &changestatus.FieldError{Field: "reason"}}, http.StatusBadRequest},
			{"application/json", reasonBody, "", &fakeStatus{}, http.StatusUnauthorized},
			{"application/json", reasonBody, tokenWith(t, []string{"MANAGER"}, accountTenant, ""), &fakeStatus{}, http.StatusForbidden},
			{"application/json", reasonBody, admin, &fakeStatus{err: port.ErrUserNotFound}, http.StatusNotFound},
			{"text/plain", reasonBody, admin, &fakeStatus{}, http.StatusUnsupportedMediaType},
			{"application/json", `{"reason":"` + strings.Repeat("a", 5000) + `"}`, admin, &fakeStatus{}, http.StatusRequestEntityTooLarge},
			{"application/json", reasonBody, admin, &fakeStatus{err: port.ErrStatusTransition}, http.StatusUnprocessableEntity},
			{"application/json", reasonBody, admin, &fakeStatus{err: errors.New("boom")}, http.StatusInternalServerError},
		} {
			run(statusHandler(c.svc, io.Discard), http.MethodPost, path, c.contentType, c.body, c.token, c.want)
		}
	}

	// a new temporary credential: a Tenant Administrator or the Platform Administrator, and every answer of the use case
	platformToken := tokenWith(t, []string{"PLATFORM_ADMINISTRATOR"}, "", "")
	for _, c := range []struct {
		contentType, body, token string
		svc                      *fakeIssuer
		want                     int
	}{
		{"application/json", credentialBody, admin, &fakeIssuer{reg: issued()}, http.StatusOK},
		{"application/json", credentialBody, platformToken, &fakeIssuer{reg: issued()}, http.StatusOK},
		{"application/json", `{"password":`, admin, &fakeIssuer{}, http.StatusBadRequest},
		{"application/json", credentialBody, admin, &fakeIssuer{err: &issuetemp.FieldError{Field: "password", Err: errors.New("at least 8 characters")}}, http.StatusBadRequest},
		{"application/json", credentialBody, "", &fakeIssuer{}, http.StatusUnauthorized},
		{"application/json", credentialBody, tokenWith(t, []string{"MANAGER"}, accountTenant, ""), &fakeIssuer{}, http.StatusForbidden},
		{"application/json", credentialBody, admin, &fakeIssuer{err: port.ErrUserNotFound}, http.StatusNotFound},
		{"text/plain", credentialBody, admin, &fakeIssuer{}, http.StatusUnsupportedMediaType},
		{"application/json", `{"password":"` + strings.Repeat("a", 5000) + `"}`, admin, &fakeIssuer{}, http.StatusRequestEntityTooLarge},
		{"application/json", credentialBody, admin, &fakeIssuer{err: issuetemp.ErrNotAuthorized}, http.StatusUnprocessableEntity},
		{"application/json", credentialBody, admin, &fakeIssuer{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(issuerHandler(c.svc, io.Discard), http.MethodPost, credentialPath, c.contentType, c.body, c.token, c.want)
	}

	// assigning and removing a special permission: only an Administrator's ordinary token, and every answer of the use case
	for _, path := range []string{grantPath, removalPath} {
		for _, c := range []struct {
			contentType, body, token string
			svc                      *fakePermissions
			want                     int
		}{
			{"application/json", permissionBody, admin, &fakePermissions{reg: registeredUser()}, http.StatusOK},
			{"application/json", `{"permission":`, admin, &fakePermissions{}, http.StatusBadRequest},
			{"application/json", permissionBody, admin, &fakePermissions{err: &changepermission.FieldError{Field: "permission"}}, http.StatusBadRequest},
			{"application/json", permissionBody, "", &fakePermissions{}, http.StatusUnauthorized},
			{"application/json", permissionBody, tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""), &fakePermissions{}, http.StatusForbidden},
			{"application/json", permissionBody, admin, &fakePermissions{err: port.ErrUserNotFound}, http.StatusNotFound},
			{"text/plain", permissionBody, admin, &fakePermissions{}, http.StatusUnsupportedMediaType},
			{"application/json", `{"permission":"` + strings.Repeat("a", 5000) + `"}`, admin, &fakePermissions{}, http.StatusRequestEntityTooLarge},
			{"application/json", permissionBody, admin, &fakePermissions{err: changepermission.ErrNotAssignable}, http.StatusUnprocessableEntity},
			{"application/json", permissionBody, admin, &fakePermissions{err: errors.New("boom")}, http.StatusInternalServerError},
		} {
			run(permissionsHandler(c.svc, io.Discard), http.MethodPost, path, c.contentType, c.body, c.token, c.want)
		}
	}

	// the optional roles of the tenant: only an Administrator's ordinary token, and every answer of the use case
	for _, c := range []struct {
		method, path, token string
		svc                 *fakeRoles
		want                int
	}{
		{http.MethodGet, rolesPath, admin, &fakeRoles{states: threeRoles()}, http.StatusOK},
		{http.MethodGet, rolesPath, "", &fakeRoles{}, http.StatusUnauthorized},
		{http.MethodGet, rolesPath, tokenWith(t, []string{"MANAGER"}, accountTenant, ""), &fakeRoles{}, http.StatusForbidden},
		{http.MethodGet, rolesPath, admin, &fakeRoles{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodPost, enablePath, admin, &fakeRoles{state: threeRoles()[0]}, http.StatusOK},
		{http.MethodPost, enablePath, admin, &fakeRoles{err: &optionalrole.FieldError{Field: "role"}}, http.StatusBadRequest},
		{http.MethodPost, enablePath, "", &fakeRoles{}, http.StatusUnauthorized},
		{http.MethodPost, enablePath, tokenWith(t, []string{"OPERATIONAL_COLLABORATOR"}, accountTenant, ""), &fakeRoles{}, http.StatusForbidden},
		{http.MethodPost, enablePath, admin, &fakeRoles{err: port.ErrStatusTransition}, http.StatusUnprocessableEntity},
		{http.MethodPost, enablePath, admin, &fakeRoles{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodPost, disablePath, admin, &fakeRoles{state: threeRoles()[0]}, http.StatusOK},
		{http.MethodPost, disablePath, admin, &fakeRoles{err: port.ErrRoleInUse}, http.StatusUnprocessableEntity},
		{http.MethodPost, disablePath, admin, &fakeRoles{err: &optionalrole.FieldError{Field: "role"}}, http.StatusBadRequest},
		{http.MethodPost, disablePath, "", &fakeRoles{}, http.StatusUnauthorized},
		{http.MethodPost, disablePath, tokenWith(t, []string{"MANAGER"}, accountTenant, ""), &fakeRoles{}, http.StatusForbidden},
		{http.MethodPost, disablePath, admin, &fakeRoles{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(rolesHandler(c.svc, io.Discard), c.method, c.path, "", "", c.token, c.want)
	}

	// the support access of the Platform Administrator (HU-SEC-007 part A): ask and list the own requests
	platformAdmin := platformAdminToken(t)
	tenantAdmin := tokenWith(t, []string{"TENANT_ADMINISTRATOR"}, accountTenant, "")
	bigSupport := `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"` + strings.Repeat("r", 4200) + `","areas":["CASH"],"hours":1}`
	supportPage := supportrequest.Page{Data: []supportaccess.Access{askedAccess()}, Page: 1, Limit: 20, Total: 1, TotalPages: 1}
	for _, c := range []struct {
		method, contentType, body, query, token string
		svc                                     *fakeSupport
		want                                    int
	}{
		{http.MethodPost, "application/json", supportBody, "", platformAdmin, &fakeSupport{access: askedAccess(), created: true}, http.StatusCreated},
		{http.MethodPost, "application/json", supportBody, "", platformAdmin, &fakeSupport{access: askedAccess()}, http.StatusOK},
		{http.MethodPost, "application/json", supportBody, "", platformAdmin, &fakeSupport{err: &supportrequest.FieldError{Field: "areas"}}, http.StatusBadRequest},
		{http.MethodPost, "application/json", supportBody, "", "", &fakeSupport{}, http.StatusUnauthorized},
		{http.MethodPost, "application/json", supportBody, "", tenantAdmin, &fakeSupport{}, http.StatusForbidden},
		{http.MethodPost, "application/json", supportBody, "", platformAdmin, &fakeSupport{err: supportrequest.ErrTenantNotFound}, http.StatusNotFound},
		{http.MethodPost, "application/json", bigSupport, "", platformAdmin, &fakeSupport{}, http.StatusRequestEntityTooLarge},
		{http.MethodPost, "text/plain", supportBody, "", platformAdmin, &fakeSupport{}, http.StatusUnsupportedMediaType},
		{http.MethodPost, "application/json", supportBody, "", platformAdmin, &fakeSupport{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodGet, "", "", "", platformAdmin, &fakeSupport{page: supportPage}, http.StatusOK},
		{http.MethodGet, "", "", "?limit=500", platformAdmin, &fakeSupport{err: &supportrequest.FieldError{Field: "limit"}}, http.StatusBadRequest},
		{http.MethodGet, "", "", "", "", &fakeSupport{}, http.StatusUnauthorized},
		{http.MethodGet, "", "", "", tenantAdmin, &fakeSupport{}, http.StatusForbidden},
		{http.MethodGet, "", "", "", platformAdmin, &fakeSupport{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(supportHandler(c.svc, io.Discard), c.method, supportRoute+c.query, c.contentType, c.body, c.token, c.want)
	}

	// the Platform Administrator opens an emergency access (HU-SEC-007 part B)
	bigEmergency := `{"tenantId":"3f2b8c1e-5d4a-4f6b-9c7d-1a2b3c4d5e6f","reason":"` + strings.Repeat("r", 4200) + `","statement":"s","areas":["CASH"],"hours":1}`
	for _, c := range []struct {
		contentType, body, token string
		svc                      *fakeEmergency
		want                     int
	}{
		{"application/json", emergencyBody, platformAdmin, &fakeEmergency{access: openedEmergency(false), created: true}, http.StatusCreated},
		{"application/json", emergencyBody, platformAdmin, &fakeEmergency{access: openedEmergency(false)}, http.StatusOK},
		{"application/json", emergencyBody, platformAdmin, &fakeEmergency{err: &supportemergency.FieldError{Field: "statement"}}, http.StatusBadRequest},
		{"application/json", emergencyBody, "", &fakeEmergency{}, http.StatusUnauthorized},
		{"application/json", emergencyBody, tenantAdmin, &fakeEmergency{}, http.StatusForbidden},
		{"application/json", emergencyBody, platformAdmin, &fakeEmergency{err: supportemergency.ErrTenantNotFound}, http.StatusNotFound},
		{"application/json", bigEmergency, platformAdmin, &fakeEmergency{}, http.StatusRequestEntityTooLarge},
		{"text/plain", emergencyBody, platformAdmin, &fakeEmergency{}, http.StatusUnsupportedMediaType},
		{"application/json", emergencyBody, platformAdmin, &fakeEmergency{err: supportaccess.ErrOpenAccessExists}, http.StatusUnprocessableEntity},
		{"application/json", emergencyBody, platformAdmin, &fakeEmergency{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(emergencyHandler(c.svc, io.Discard), http.MethodPost, emergencyRoute, c.contentType, c.body, c.token, c.want)
	}

	// the Tenant Administrator lists and decides the support requests of the tenant (HU-SEC-007 part A)
	tenantSupportAdmin := adminOfTenant(t)
	bigDecision := `{"reason":"` + strings.Repeat("r", 4200) + `"}`
	decisionPage := supportdecision.Page{Data: []supportaccess.Access{askedAccess()}, Page: 1, Limit: 20, Total: 1, TotalPages: 1}
	approvalPath, rejectionPath := decisionsRoute+"/"+requestID+"/approval", decisionsRoute+"/"+requestID+"/rejection"
	for _, c := range []struct {
		method, path, contentType, body, token string
		svc                                    *fakeDecider
		want                                   int
	}{
		{http.MethodGet, decisionsRoute, "", "", tenantSupportAdmin, &fakeDecider{page: decisionPage}, http.StatusOK},
		{http.MethodGet, decisionsRoute + "?limit=500", "", "", tenantSupportAdmin, &fakeDecider{err: &supportdecision.FieldError{Field: "limit"}}, http.StatusBadRequest},
		{http.MethodGet, decisionsRoute, "", "", "", &fakeDecider{}, http.StatusUnauthorized},
		{http.MethodGet, decisionsRoute, "", "", platformAdminToken(t), &fakeDecider{}, http.StatusForbidden},
		{http.MethodGet, decisionsRoute, "", "", tenantSupportAdmin, &fakeDecider{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodPost, approvalPath, "", "", tenantSupportAdmin, &fakeDecider{access: approvedAccess()}, http.StatusOK},
		{http.MethodPost, approvalPath, "", "", "", &fakeDecider{}, http.StatusUnauthorized},
		{http.MethodPost, approvalPath, "", "", platformAdminToken(t), &fakeDecider{}, http.StatusForbidden},
		{http.MethodPost, approvalPath, "", "", tenantSupportAdmin, &fakeDecider{err: supportdecision.ErrNotFound}, http.StatusNotFound},
		{http.MethodPost, approvalPath, "", "", tenantSupportAdmin, &fakeDecider{err: supportaccess.ErrInvalidTransition}, http.StatusUnprocessableEntity},
		{http.MethodPost, approvalPath, "", "", tenantSupportAdmin, &fakeDecider{err: errors.New("boom")}, http.StatusInternalServerError},
		{http.MethodPost, rejectionPath, "application/json", `{"reason":"no"}`, tenantSupportAdmin, &fakeDecider{access: approvedAccess()}, http.StatusOK},
		{http.MethodPost, rejectionPath, "application/json", `{"reason":`, tenantSupportAdmin, &fakeDecider{}, http.StatusBadRequest},
		{http.MethodPost, rejectionPath, "application/json", `{"reason":"no"}`, "", &fakeDecider{}, http.StatusUnauthorized},
		{http.MethodPost, rejectionPath, "application/json", `{"reason":"no"}`, platformAdminToken(t), &fakeDecider{}, http.StatusForbidden},
		{http.MethodPost, rejectionPath, "application/json", `{"reason":"no"}`, tenantSupportAdmin, &fakeDecider{err: supportdecision.ErrNotFound}, http.StatusNotFound},
		{http.MethodPost, rejectionPath, "application/json", bigDecision, tenantSupportAdmin, &fakeDecider{}, http.StatusRequestEntityTooLarge},
		{http.MethodPost, rejectionPath, "text/plain", `{"reason":"no"}`, tenantSupportAdmin, &fakeDecider{}, http.StatusUnsupportedMediaType},
		{http.MethodPost, rejectionPath, "application/json", `{"reason":"no"}`, tenantSupportAdmin, &fakeDecider{err: supportaccess.ErrInvalidTransition}, http.StatusUnprocessableEntity},
		{http.MethodPost, rejectionPath, "application/json", `{"reason":"no"}`, tenantSupportAdmin, &fakeDecider{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(decisionHandler(c.svc, io.Discard), c.method, c.path, c.contentType, c.body, c.token, c.want)
	}

	// the Platform Administrator takes the token of an approved support access and closes it (HU-SEC-007 part A)
	sessionAdmin := platformAdminToken(t)
	bigClosure := `{"reason":"` + strings.Repeat("r", 4200) + `"}`
	for _, c := range []struct {
		path, contentType, body, token string
		svc                            *fakeSession
		want                           int
	}{
		{tokenRoute, "", "", sessionAdmin, &fakeSession{token: someToken()}, http.StatusOK},
		{tokenRoute, "", "", "", &fakeSession{}, http.StatusUnauthorized},
		{tokenRoute, "", "", tenantAdmin, &fakeSession{}, http.StatusForbidden},
		{tokenRoute, "", "", sessionAdmin, &fakeSession{err: supportsession.ErrNotFound}, http.StatusNotFound},
		{tokenRoute, "", "", sessionAdmin, &fakeSession{err: supportaccess.ErrInvalidTransition}, http.StatusUnprocessableEntity},
		{tokenRoute, "", "", sessionAdmin, &fakeSession{err: errors.New("boom")}, http.StatusInternalServerError},
		{closeRoute, "application/json", `{"reason":"done"}`, sessionAdmin, &fakeSession{access: closedAccess()}, http.StatusOK},
		{closeRoute, "application/json", `{"reason":`, sessionAdmin, &fakeSession{}, http.StatusBadRequest},
		{closeRoute, "application/json", `{"reason":"done"}`, "", &fakeSession{}, http.StatusUnauthorized},
		{closeRoute, "application/json", `{"reason":"done"}`, tenantAdmin, &fakeSession{}, http.StatusForbidden},
		{closeRoute, "application/json", `{"reason":"done"}`, sessionAdmin, &fakeSession{err: supportsession.ErrNotFound}, http.StatusNotFound},
		{closeRoute, "application/json", bigClosure, sessionAdmin, &fakeSession{}, http.StatusRequestEntityTooLarge},
		{closeRoute, "text/plain", `{"reason":"done"}`, sessionAdmin, &fakeSession{}, http.StatusUnsupportedMediaType},
		{closeRoute, "application/json", `{"reason":"done"}`, sessionAdmin, &fakeSession{err: supportaccess.ErrInvalidTransition}, http.StatusUnprocessableEntity},
		{closeRoute, "application/json", `{"reason":"done"}`, sessionAdmin, &fakeSession{err: errors.New("boom")}, http.StatusInternalServerError},
	} {
		run(sessionHandler(c.svc, io.Discard), http.MethodPost, c.path, c.contentType, c.body, c.token, c.want)
	}

	for path, item := range doc.Paths.Map() {
		for method, operation := range item.Operations() {
			for status := range operation.Responses.Map() {
				if !exercised[method+" "+path+" "+status] {
					t.Errorf("the response %s of %s %s was never produced", status, method, path)
				}
			}
		}
	}
}
