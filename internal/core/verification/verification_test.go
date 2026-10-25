package verification_test

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/verification"
)

var now = time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)

func TestD_ALinkIsRandomUrlSafeAndKeptOnlyAsASha256(t *testing.T) {
	link, err := verification.New(bytes.NewReader(bytes.Repeat([]byte{0xfb}, 32)), now)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(link.Raw) {
		t.Fatalf("raw = %q, want 43 characters of the URL-safe alphabet and no padding", link.Raw)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(link.Hash) || strings.Contains(link.Hash, link.Raw) {
		t.Fatalf("hash = %q, want 64 lower-case hexadecimal characters that do not hold the link", link.Hash)
	}
	if link.Hash != verification.Hash(link.Raw) {
		t.Fatal("the hash of a link must be the hash of what the person sends back")
	}
	if !link.ExpiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("expires at %s, want 24 hours after now", link.ExpiresAt)
	}
}

func TestD_TwoLinksDifferAndAShortSourceOfRandomnessIsAnError(t *testing.T) {
	a, _ := verification.New(bytes.NewReader(bytes.Repeat([]byte{1}, 32)), now)
	b, _ := verification.New(bytes.NewReader(bytes.Repeat([]byte{2}, 32)), now)
	if a.Raw == "" || a.Raw == b.Raw || a.Hash == b.Hash {
		t.Fatal("two different random values must make two different links")
	}
	if _, err := verification.New(bytes.NewReader([]byte{1, 2, 3}), now); err == nil {
		t.Fatal("a source that gives fewer than 32 bytes must not make a link")
	}
	if _, err := verification.New(errReader{}, now); err == nil {
		t.Fatal("a source that fails must not make a link")
	}
}

func TestD_TheHashIsTheSha256InLowerCaseHexadecimal(t *testing.T) {
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := verification.Hash("abc"); got != abc {
		t.Fatalf("hash = %q, want the SHA-256 of abc", got)
	}
}

func TestD_OnlyTheShapeOfALinkIsAccepted(t *testing.T) {
	good := strings.Repeat("a", 43)
	if !verification.ValidShape(good) {
		t.Fatal("43 URL-safe characters must be accepted")
	}
	for _, bad := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 44), strings.Repeat("a", 42) + "=", strings.Repeat("a", 42) + "+", strings.Repeat("a", 42) + " ", strings.Repeat("é", 43)} {
		if verification.ValidShape(bad) {
			t.Fatalf("%q must not be accepted", bad)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }
