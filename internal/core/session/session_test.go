package session_test

import (
	"encoding/base64"
	"regexp"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/session"
)

func TestD_ASessionLastsSevenDays(t *testing.T) {
	if session.Life != 7*24*time.Hour {
		t.Fatalf("a session lasts 7 days (ADR-004 D5), got %v", session.Life)
	}
}

func TestD_ARenewalValueIsURLSafeOf256BitsAndNeverRepeats(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		value, hash, err := session.NewRefreshValue()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(raw) < 32 || !regexp.MustCompile(`^[A-Za-z0-9_-]{43,}$`).MatchString(value) {
			t.Fatalf("a value is unpadded URL-safe base64 of at least 32 bytes, got %q (%v)", value, err)
		}
		if seen[value] {
			t.Fatal("a value repeated")
		}
		seen[value] = true
		if session.Hash(value) != hash {
			t.Fatal("Hash must give the hash NewRefreshValue returned")
		}
	}
}

func TestD_TheStoredHashIsSHA256InHexAndStable(t *testing.T) {
	known := map[string]string{
		"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	for value, want := range known {
		if got := session.Hash(value); got != want {
			t.Fatalf("Hash(%q) = %s", value, got)
		}
	}
}
