package httpadapter_test

import (
	"io"
	"testing"
)

// The side a person signs in from travels in the body (HU-SEC-008, AC2).

const goodBodyWithSide = `{"email":"ana@example.com","password":"s3cret-pass","context":"TEAM"}`

func TestC_SignInWithASideHandsItToTheUseCase(t *testing.T) {
	svc := &fakeSignIn{tokens: okTokens()}
	if rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", goodBodyWithSide, "trace-1"); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(svc.tenantReq) != 1 || svc.tenantReq[0].Context != "TEAM" {
		t.Fatalf("%+v", svc.tenantReq)
	}
}

func TestC_SignInWithNoSideHandsItAnEmptyOne(t *testing.T) {
	svc := &fakeSignIn{tokens: okTokens()}
	post(signInHandler(svc, io.Discard), tenantRoute, "application/json", goodBody, "trace-1")
	if len(svc.tenantReq) != 1 || svc.tenantReq[0].Context != "" {
		t.Fatalf("%+v", svc.tenantReq)
	}
}

func TestC_ASideThatIsNotAStringIsABadBody(t *testing.T) {
	svc := &fakeSignIn{}
	rec := post(signInHandler(svc, io.Discard), tenantRoute, "application/json", `{"email":"a@b.co","password":"x","context":7}`, "trace-1")
	if rec.Code != 400 || len(svc.tenantReq) != 0 {
		t.Fatalf("%d", rec.Code)
	}
}
