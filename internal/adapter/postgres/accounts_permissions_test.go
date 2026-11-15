package postgres_test

import (
	"slices"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres"
	"github.com/code-corhuila/multi-tour-security/internal/adapter/postgres/pgtest"
)

// HU-SEC-006, RN-SEC-005-11: what the token issuer reads, against the real engine.

func TestI_PermissionsOfReadsOnlyTheHeldPermissionsOfTheActiveMembership(t *testing.T) {
	pool := pgtest.Open(t)
	accounts, permissions := postgres.NewAccounts(pool), postgres.NewUserPermissions(pool)
	colab := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	for _, p := range []string{"MANAGE_CASH", "CONSULT_SENSITIVE_DATA", "VALIDATE_PAYMENT_PROOFS"} {
		if _, err := permissions.Grant(ctx, permChange(colab, p)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := permissions.Remove(ctx, permChange(colab, "VALIDATE_PAYMENT_PROOFS")); err != nil {
		t.Fatal(err)
	}
	got, err := accounts.PermissionsOf(ctx, colab)
	if err != nil || !slices.Equal(got, []string{"CONSULT_SENSITIVE_DATA", "MANAGE_CASH"}) {
		t.Fatalf("%v %v: the held ones, sorted, without the removed one", got, err)
	}
}

func TestI_PermissionsOfAnAccountWithNoneOrAnInactiveMembershipOrNoAccountIsEmptyAndNotAnError(t *testing.T) {
	pool := pgtest.Open(t)
	accounts, permissions := postgres.NewAccounts(pool), postgres.NewUserPermissions(pool)
	none := user(t, pool, tenant, "none@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	gone := user(t, pool, tenant, "gone@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := permissions.Grant(ctx, permChange(gone, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE security.membership SET membership_status = 'INACTIVE' WHERE identity_id = $1::uuid`, gone); err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{"an account with none": none, "an inactive membership": gone, "no account": missing} {
		got, err := accounts.PermissionsOf(ctx, id)
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("%s: %#v %v", name, got, err)
		}
	}
}

func TestI_PermissionsOfAnInactiveUserAreStillThereForTheDayTheyAreReactivated(t *testing.T) {
	pool := pgtest.Open(t)
	accounts, permissions := postgres.NewAccounts(pool), postgres.NewUserPermissions(pool)
	id := user(t, pool, tenant, "colab@example.com", pgtest.Options{}, "OPERATIONAL_COLLABORATOR")
	if _, err := permissions.Grant(ctx, permChange(id, "MANAGE_CASH")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE security.identity SET identity_status = 'INACTIVE' WHERE identity_id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	if got, err := accounts.PermissionsOf(ctx, id); err != nil || !slices.Equal(got, []string{"MANAGE_CASH"}) {
		t.Fatalf("%v %v: refusing an inactive account is the work of the sign-in and not of this read", got, err)
	}
}
