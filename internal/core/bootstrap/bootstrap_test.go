package bootstrap_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/bootstrap"
)

var now = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

type created struct {
	email, hash string
	until       time.Time
}

type fakeAdmins struct {
	made   []created
	exists bool
	err    error
}

func (f *fakeAdmins) CreateFirst(_ context.Context, email, hash string, until time.Time) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.exists {
		return false, nil
	}
	f.made = append(f.made, created{email, hash, until})
	return true, nil
}

type fakeHasher struct {
	err    error
	hashed []string
}

func (f *fakeHasher) Compare(hash, pw string) bool { return hash == "hash:"+pw }
func (f *fakeHasher) Hash(pw string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.hashed = append(f.hashed, pw)
	return "hash:" + pw, nil
}

func service(admins *fakeAdmins, hasher *fakeHasher) *bootstrap.Service {
	return &bootstrap.Service{Admins: admins, Hasher: hasher, Clock: func() time.Time { return now }}
}

var ctx = context.Background()

const good = "Tr4vesia-Natural"

func TestA_TheFirstAdministratorIsMadeWithTheHashOfATemporaryPasswordValidFor72Hours(t *testing.T) {
	admins, hasher := &fakeAdmins{}, &fakeHasher{}
	made, err := service(admins, hasher).CreateFirst(ctx, "  Root@Example.COM ", good)
	if err != nil || !made {
		t.Fatalf("made=%v err=%v", made, err)
	}
	want := created{"root@example.com", "hash:" + good, now.Add(72 * time.Hour)}
	if len(admins.made) != 1 || admins.made[0] != want {
		t.Fatalf("created %+v, want %+v", admins.made, want)
	}
}

func TestA_ASecondCallDoesNothingAndIsNotAnError(t *testing.T) {
	admins := &fakeAdmins{exists: true}
	made, err := service(admins, &fakeHasher{}).CreateFirst(ctx, "other@example.com", good)
	if err != nil || made || len(admins.made) != 0 {
		t.Fatalf("made=%v err=%v %+v", made, err, admins.made)
	}
}

func TestA_AnEmailThatIsNotOneOrAPasswordThatBreaksThePolicyCreatesNothingAndHashesNothing(t *testing.T) {
	for name, c := range map[string]struct{ email, pw string }{
		"no at sign": {"root.example.com", good}, "empty email": {"", good}, "not ASCII": {"rñt@example.com", good},
		"short password": {"root@example.com", "sh0rt!A"}, "no special": {"root@example.com", "Travesia1Natural"}, "common": {"root@example.com", "Password1!"},
		"empty password": {"root@example.com", ""}, "73 bytes": {"root@example.com", "aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!aA1!a"},
	} {
		admins, hasher := &fakeAdmins{}, &fakeHasher{}
		made, err := service(admins, hasher).CreateFirst(ctx, c.email, c.pw)
		if err == nil || made || len(admins.made) != 0 || len(hasher.hashed) != 0 {
			t.Errorf("%s: made=%v err=%v", name, made, err)
		}
		if (name == "short password" || name == "common" || name == "no special" || name == "empty password" || name == "73 bytes") && !errors.Is(err, bootstrap.ErrWeakPassword) {
			t.Errorf("%s: a password that breaks the policy is ErrWeakPassword, got %v", name, err)
		}
		if (name == "no at sign" || name == "empty email" || name == "not ASCII") && !errors.Is(err, bootstrap.ErrInvalidEmail) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestA_AFailureOfTheHasherOrTheStoreIsAnErrorAndNeverALeakOfThePassword(t *testing.T) {
	boom := errors.New("connection reset")
	for name, s := range map[string]*bootstrap.Service{
		"hasher": service(&fakeAdmins{}, &fakeHasher{err: boom}),
		"store":  service(&fakeAdmins{err: boom}, &fakeHasher{}),
	} {
		made, err := s.CreateFirst(ctx, "root@example.com", good)
		if made || !errors.Is(err, boom) || err.Error() == "" {
			t.Errorf("%s: made=%v err=%v", name, made, err)
		}
	}
}

func TestA_AServiceWithoutAPieceRefusesToWorkAndNeverPanics(t *testing.T) {
	for name, s := range map[string]*bootstrap.Service{
		"admins": {Hasher: &fakeHasher{}, Clock: func() time.Time { return now }},
		"hasher": {Admins: &fakeAdmins{}, Clock: func() time.Time { return now }},
		"clock":  {Admins: &fakeAdmins{}, Hasher: &fakeHasher{}},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("without the %s the service panicked: %v", name, r)
				}
			}()
			if made, err := s.CreateFirst(ctx, "root@example.com", good); made || err == nil {
				t.Errorf("without the %s the service answered", name)
			}
		}()
	}
}
