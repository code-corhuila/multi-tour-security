package bcryptadapter_test

import (
	"strings"
	"testing"

	bcryptadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/bcrypt"
	"golang.org/x/crypto/bcrypt"
)

func TestA_TheLimitIsInBytesAndNotInCharacters(t *testing.T) {
	h := bcryptadapter.Hasher{}
	thirtySix := strings.Repeat("ñ", 36) // 72 bytes
	hash, err := bcryptadapter.Hash(thirtySix)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Compare(hash, thirtySix) {
		t.Error("36 two-byte characters are 72 bytes and work")
	}
	if h.Compare(hash, thirtySix+"ñ") {
		t.Error("37 two-byte characters are 74 bytes and must not match through their first 72")
	}
	if _, err := bcryptadapter.Hash(thirtySix + "ñ"); err == nil {
		t.Error("a password of 74 bytes was hashed")
	}
}

func TestA_AHashOfAnotherCostStillMatchesAndAnAbsurdOneNeverPanics(t *testing.T) {
	h := bcryptadapter.Hasher{}
	cheap, err := bcrypt.GenerateFromPassword([]byte("old password"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Compare(string(cheap), "old password") {
		t.Error("a hash made at another cost must still be compared")
	}
	if h.Compare(strings.Repeat("$2a$12$", 10000), "x") || h.Compare("\x00\xff", "x") {
		t.Error("an absurd hash matched")
	}
}
