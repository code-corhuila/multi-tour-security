package bcryptadapter_test

import (
	"regexp"
	"strings"
	"testing"

	bcryptadapter "github.com/code-corhuila/multi-tour-security/internal/adapter/bcrypt"
	"golang.org/x/crypto/bcrypt"
)

// the shape the column password_hash of the table accepts
var tableShape = regexp.MustCompile(`^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$`)

func TestA_APasswordIsHashedWithCost12AndComparedExactly(t *testing.T) {
	hash, err := bcryptadapter.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !tableShape.MatchString(hash) {
		t.Fatalf("the hash must fit the column: %q", hash)
	}
	if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost != 12 {
		t.Fatalf("cost = %d, %v: the cost of the plan is 12", cost, err)
	}
	h := bcryptadapter.Hasher{}
	if !h.Compare(hash, "correct horse") {
		t.Error("the right password was refused")
	}
	for _, wrong := range []string{"correct hors", "correct horse ", "Correct horse", ""} {
		if h.Compare(hash, wrong) {
			t.Errorf("%q was accepted", wrong)
		}
	}
}

func TestA_ASaltMakesTwoHashesOfOnePasswordDifferent(t *testing.T) {
	a, _ := bcryptadapter.Hash("same")
	b, _ := bcryptadapter.Hash("same")
	if a == b || a == "" {
		t.Fatal("the same password must not give the same hash twice")
	}
}

func TestA_BcryptReadsOnly72BytesSoALongerPasswordIsNeverAcceptedForItsPrefix(t *testing.T) {
	seventyTwo := strings.Repeat("a", 72)
	hash, err := bcryptadapter.Hash(seventyTwo)
	if err != nil {
		t.Fatal(err)
	}
	h := bcryptadapter.Hasher{}
	if !h.Compare(hash, seventyTwo) {
		t.Error("a password of 72 bytes is the limit and works")
	}
	if h.Compare(hash, seventyTwo+"b") {
		t.Error("a longer password matched through its first 72 bytes")
	}
	if _, err := bcryptadapter.Hash(seventyTwo + "b"); err == nil {
		t.Error("a password of 73 bytes was hashed")
	}
	if _, err := bcryptadapter.Hash(""); err == nil {
		t.Error("an empty password was hashed")
	}
}

func TestA_AHashThatIsNotOneNeverMatches(t *testing.T) {
	h := bcryptadapter.Hasher{}
	for _, bad := range []string{"", "plain", "$2a$12$short", strings.Repeat("$", 60)} {
		if h.Compare(bad, "anything") {
			t.Errorf("%q matched", bad)
		}
	}
}

func TestA_TheDummyHashHasTheCostOfARealOneAndMatchesNothing(t *testing.T) {
	dummy, err := bcryptadapter.NewDummyHash()
	if err != nil {
		t.Fatal(err)
	}
	if cost, err := bcrypt.Cost([]byte(dummy)); err != nil || cost != 12 || !tableShape.MatchString(dummy) {
		t.Fatalf("the dummy hash must cost as much as a real one: %d %v %q", cost, err, dummy)
	}
	other, _ := bcryptadapter.NewDummyHash()
	if dummy == other {
		t.Error("the dummy hash must not be a constant of the source")
	}
	h := bcryptadapter.Hasher{}
	for _, guess := range []string{"", "password", "dummy", dummy} {
		if h.Compare(dummy, guess) {
			t.Errorf("the dummy hash matched %q", guess)
		}
	}
}
