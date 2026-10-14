package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// The first Platform Administrator exists only because a one-shot command made the account (RN-SEC-001-09,
// I·bootstrap_creates_one_admin_once). The command reads the e-mail from the environment and the temporary password from
// the console, and prints neither the password nor anything that could help guess it.

const (
	rootEmail    = "root@example.com"
	rootPassword = "Tr4vesia-Natural"
)

func envOf(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func runBootstrap(url, email, stdin string) (string, error) {
	var out bytes.Buffer
	err := execute(context.Background(), []string{"bootstrap-platform-admin"},
		envOf(map[string]string{"DATABASE_URL": url, "PLATFORM_ADMIN_EMAIL": email}), strings.NewReader(stdin), &out, os.ReadFile, time.Now)
	return out.String(), err
}

func TestC_TheCommandMakesTheAdministratorWhoSignsInAtThePlatformAndChoosesAPassword(t *testing.T) {
	pool, url := pgtest.OpenURL(t)
	out, err := runBootstrap(url, " Root@Example.com ", rootPassword+"\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, rootEmail) || !strings.Contains(out, "72 hours") || strings.Contains(out, rootPassword) {
		t.Fatalf("it says who was made and for how long, and never the password: %q", out)
	}
	s := newStackOn(t, pool)
	signed := s.signIn(rootURL, rootEmail, rootPassword)
	a, claims := s.claims(t, signed)
	if claims["access"] != "password-change" || a.RefreshToken != "" {
		t.Fatalf("the first sign-in only serves to choose a password: %v %+v", claims, a)
	}
	if rec := s.changePassword(a.AccessToken, "An0ther-Good-Pass"); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	_, normal := s.claims(t, s.signIn(rootURL, rootEmail, "An0ther-Good-Pass"))
	if _, hasTenant := normal["tenantId"]; hasTenant || normal["access"] != nil {
		t.Fatalf("the platform token has no tenant and no mark: %v", normal)
	}
	if roles, _ := normal["roles"].([]any); len(roles) != 1 || roles[0] != "PLATFORM_ADMINISTRATOR" {
		t.Fatalf("roles = %v", normal["roles"])
	}
}

func TestC_ASecondRunDoesNothingAndSaysSoWithoutAnError(t *testing.T) {
	pool, url := pgtest.OpenURL(t)
	if _, err := runBootstrap(url, rootEmail, rootPassword); err != nil {
		t.Fatal(err)
	}
	out, err := runBootstrap(url, "other@example.com", "Another-Good-1!")
	if err != nil || !strings.Contains(out, "already") || strings.Contains(out, "Another-Good-1!") {
		t.Fatalf("%q %v", out, err)
	}
	var accounts int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM security.identity`).Scan(&accounts); err != nil || accounts != 1 {
		t.Fatalf("still one account: %d %v", accounts, err)
	}
}

func TestC_WhatIsMissingOrWrongIsRefusedWithoutEchoingThePassword(t *testing.T) {
	_, url := pgtest.OpenURL(t)
	cases := map[string]struct{ url, email, stdin, wantInError string }{
		"no e-mail":            {url, "", rootPassword, "PLATFORM_ADMIN_EMAIL"},
		"e-mail not valid":     {url, "root.example.com", rootPassword, "e-mail"},
		"no password":          {url, rootEmail, "", "password"},
		"empty line":           {url, rootEmail, "\n", "password"},
		"weak password":        {url, rootEmail, "sh0rt!A\n", "policy"},
		"common password":      {url, rootEmail, "Password1!\n", "policy"},
		"no database url":      {"", rootEmail, rootPassword, "DATABASE_URL"},
		"database unreachable": {"postgres://security_app:s3cret-pw@127.0.0.1:1/x?sslmode=disable", rootEmail, rootPassword, "does not answer"},
		"not a postgres URL":   {"mysql://u:s3cret-pw@h/x", rootEmail, rootPassword, "postgres URL"},
		"blank e-mail":         {url, "   ", rootPassword, "e-mail"},
		"password over 72":     {url, rootEmail, strings.Repeat("aA1!", 19) + "\n", "policy"},
		"line over 1 KB":       {url, rootEmail, strings.Repeat("aA1!", 400), "policy"},
	}
	for name, c := range cases {
		out, err := runBootstrap(c.url, c.email, c.stdin)
		if err == nil || !strings.Contains(err.Error(), c.wantInError) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, secret := range []string{strings.TrimSpace(c.stdin), "s3cret-pw"} {
			if secret != "" && (strings.Contains(err.Error(), secret) || strings.Contains(out, secret)) {
				t.Errorf("%s: the password shows: %v %q", name, err, out)
			}
		}
	}
}

func TestC_ThePasswordIsReadAsTypedWithOnlyTheLineEndRemoved(t *testing.T) {
	pool, url := pgtest.OpenURL(t)
	if _, err := runBootstrap(url, rootEmail, "  Spaced Pass-1  \n"); err != nil {
		t.Fatal(err)
	}
	s := newStackOn(t, pool)
	if rec := s.signIn(rootURL, rootEmail, "  Spaced Pass-1  "); rec.Code != http.StatusOK {
		t.Fatalf("the spaces are part of the password: %d", rec.Code)
	}
}

func TestC_AnUnknownCommandIsRefusedAndTheKnownOnesAreListed(t *testing.T) {
	var out bytes.Buffer
	err := execute(context.Background(), []string{"Sup3r-Secret-Pass!"}, envOf(nil), strings.NewReader(""), &out, os.ReadFile, time.Now)
	if err == nil || !strings.Contains(err.Error(), "bootstrap-platform-admin") || strings.Contains(err.Error(), "Sup3r") {
		t.Fatalf("%v", err)
	}
}
