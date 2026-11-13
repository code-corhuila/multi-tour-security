package recovery_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/recovery"
)

var (
	now = time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	key = []byte(strings.Repeat("k", 32))
)

// numbers feeds the random source with the 32-bit values the code is made from.
func numbers(values ...uint32) *bytes.Reader {
	var b []byte
	for _, v := range values {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return bytes.NewReader(b)
}

func TestD_ACodeIsEightDigitsAndLastsThirtyMinutes(t *testing.T) {
	code, err := recovery.New(numbers(48213907), key, "acc-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if code.Raw != "48213907" {
		t.Fatalf("raw = %q", code.Raw)
	}
	if !code.ExpiresAt.Equal(now.Add(30*time.Minute)) || !code.CreatedAt.Equal(now) {
		t.Fatalf("created %v expires %v", code.CreatedAt, code.ExpiresAt)
	}
	if !recovery.ValidShape(code.Raw) {
		t.Fatal("a code must have the shape it is checked with")
	}
}

func TestD_ACodeKeepsItsLeadingZeros(t *testing.T) {
	code, err := recovery.New(numbers(42), key, "acc-1", now)
	if err != nil || code.Raw != "00000042" {
		t.Fatalf("raw = %q err = %v", code.Raw, err)
	}
}

func TestD_TheCodeIsMadeWithoutBias(t *testing.T) {
	// 4 200 000 000 is the first value that would make the low numbers more likely than the high ones: it is skipped
	code, err := recovery.New(numbers(4_200_000_000, 4_294_967_295, 7), key, "acc-1", now)
	if err != nil || code.Raw != "00000007" {
		t.Fatalf("raw = %q err = %v", code.Raw, err)
	}
	if _, err := recovery.New(numbers(4_200_000_000, 4_200_000_001, 4_200_000_002, 4_200_000_003, 4_200_000_004, 4_200_000_005,
		4_200_000_006, 4_200_000_007, 4_200_000_008, 4_200_000_009, 4_200_000_010, 4_200_000_011, 4_200_000_012, 4_200_000_013,
		4_200_000_014, 4_200_000_015, 4_200_000_016), key, "acc-1", now); err == nil {
		t.Fatal("a source that never gives a usable value must make no code")
	}
}

func TestD_AFailingRandomSourceMakesNoCode(t *testing.T) {
	if _, err := recovery.New(bytes.NewReader([]byte{1, 2}), key, "acc-1", now); err == nil {
		t.Fatal("a short source must make no code")
	}
}

func TestD_TheHMACDependsOnTheKeyTheAccountAndTheCode(t *testing.T) {
	a := recovery.HMAC(key, "acc-1", "48213907")
	if len(a) != 64 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("the HMAC must be 64 lower-case hexadecimal characters: %q", a)
	}
	if recovery.HMAC(key, "acc-2", "48213907") == a || recovery.HMAC(key, "acc-1", "48213908") == a ||
		recovery.HMAC([]byte(strings.Repeat("z", 32)), "acc-1", "48213907") == a {
		t.Fatal("the account, the code and the key must each change the HMAC")
	}
	if strings.Contains(a, "48213907") {
		t.Fatal("the HMAC must not carry the code")
	}
}

func TestD_TheShapeIsEightDigitsAndNothingElse(t *testing.T) {
	for _, ok := range []string{"00000000", "48213907", "99999999"} {
		if !recovery.ValidShape(ok) {
			t.Errorf("%q must be accepted", ok)
		}
	}
	for _, bad := range []string{"", "1234567", "123456789", "1234567a", "1234 678", "１２３４５６７８", "-1234567", "+1234567"} {
		if recovery.ValidShape(bad) {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestD_TwoHMACsAreComparedWithoutLeakingWhereTheyDiffer(t *testing.T) {
	a := recovery.HMAC(key, "acc-1", "48213907")
	if !recovery.Equal(a, a) || recovery.Equal(a, recovery.HMAC(key, "acc-1", "00000000")) || recovery.Equal(a, "") {
		t.Fatal("Equal must say whether two HMACs are the same")
	}
}

func TestD_TheCauseOfAFailedSendNeverHoldsTheCodeAndIsBounded(t *testing.T) {
	got := recovery.Cause(errors.New("535 rejected 48213907 for ana"), "48213907")
	if strings.Contains(got, "48213907") || !strings.Contains(got, "[code]") {
		t.Fatalf("cause = %q", got)
	}
	if long := recovery.Cause(errors.New(strings.Repeat("é", 300)), ""); len(long) > recovery.MaxCause {
		t.Fatalf("the cause has %d bytes", len(long))
	}
	if recovery.Cause(nil, "x") != "" {
		t.Fatal("no error, no cause")
	}
}

func TestD_TheLimitsAreThoseOfADR004D10(t *testing.T) {
	if recovery.Life != 30*time.Minute || recovery.CodesPerWindow != 3 || recovery.Window != time.Hour || recovery.MaxWrongTries != 5 {
		t.Fatalf("life %v, codes %d per %v, tries %d", recovery.Life, recovery.CodesPerWindow, recovery.Window, recovery.MaxWrongTries)
	}
}
