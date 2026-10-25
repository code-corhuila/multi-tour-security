#!/bin/sh
# I·db_ci_builds_reruns_rolls_back_and_rebuilds and I·security_app_writes_only_its_schema.
#
# Builds the security schema from an EMPTY PostgreSQL, applies the migrations a second time (zero
# changes), rolls everything back (empty again) and applies them once more (Annex A, db-ci; Annex J,
# J.6 and J.10). It starts its own throwaway PostgreSQL and Liquibase containers on a private network,
# with passwords generated now, so it touches nothing else and writes no secret. Docker is the only
# requirement; the CI and a developer run this same file.
set -u
cd "$(dirname "$0")/../.." || exit 1

# Git Bash on Windows rewrites container paths such as /workspace; no effect elsewhere
export MSYS_NO_PATHCONV=1

POSTGRES_IMAGE="postgres:18.6-alpine"
RUN_ID="security-dbci-$$"
# the same image the runner of deploy/compose.yml uses: Liquibase plus the PostgreSQL driver
LIQUIBASE_IMAGE="$RUN_ID-liquibase"
DB="multitour_test"
ADMIN_PASSWORD="admin-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
APP_PASSWORD="app-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fail=0

cleanup() {
  docker rm -f "$RUN_ID" >/dev/null 2>&1 || true
  docker network rm "$RUN_ID" >/dev/null 2>&1 || true
  docker rmi "$LIQUIBASE_IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 1' INT TERM

psql_admin() { docker exec -e PGPASSWORD="$ADMIN_PASSWORD" "$RUN_ID" psql -h 127.0.0.1 -U postgres -d "$DB" -v ON_ERROR_STOP=1 -tA "$@"; }

# Each -db owns its control table (J.6); the runner uses the instance administrator (ADR-005 E7)
lb() {
  docker run --rm --network "$RUN_ID" -v "$PWD/db:/workspace:ro" \
    -e LIQUIBASE_COMMAND_URL="jdbc:postgresql://$RUN_ID:5432/$DB" \
    -e LIQUIBASE_COMMAND_USERNAME=postgres -e LIQUIBASE_COMMAND_PASSWORD="$ADMIN_PASSWORD" \
    "$LIQUIBASE_IMAGE" --search-path=/workspace --changelog-file=changelog/changelog-master.yaml \
    --database-changelog-table-name=databasechangelog_security \
    --database-changelog-lock-table-name=databasechangeloglock_security "$@"
}

check() { # name, then the command that must succeed
  name=$1; shift
  if reason=$("$@" 2>&1); then
    echo "PASS  $name"
  else
    echo "FAIL  $name"
    printf '%s\n' "$reason" | tail -n 8 | sed 's/^/        /'
    fail=1
  fi
}

# The schemas where security_app can write, by the privilege query of J.10: only its own may appear
writable_schemas() {
  psql_admin -c "SELECT string_agg(DISTINCT table_schema, ',' ORDER BY table_schema) FROM information_schema.tables
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
      AND has_table_privilege('security_app', format('%I.%I', table_schema, table_name), 'INSERT,UPDATE,DELETE')"
}

# A positive control first: the check must SEE a write privilege when one exists, or it would pass
# only because the other schema is out of reach. The grant is revoked right after.
writes_only_its_schema() {
  psql_admin -c "GRANT INSERT ON other_domain.probe TO security_app" >/dev/null || return 1
  seen=$(writable_schemas)
  psql_admin -c "REVOKE INSERT ON other_domain.probe FROM security_app" >/dev/null || return 1
  [ "$seen" = "other_domain,security" ] || { echo "the privilege query did not see a granted write: '$seen'"; return 1; }
  [ "$(writable_schemas)" = "security" ] || { echo "security_app can write in: $(writable_schemas)"; return 1; }
  [ "$(psql_admin -c "SELECT has_schema_privilege('security_app', 'public', 'CREATE')")" = "f" ] || { echo "security_app can create in public"; return 1; }
  [ "$(psql_admin -c "SELECT has_schema_privilege('security_app', 'security', 'CREATE')")" = "f" ] || { echo "security_app can create objects in security"; return 1; }
}

# What AC-00.3 promises besides the writes: its own control table, login-less roles without a password,
# and the grant of the writer role to the instance user.
owns_its_control_table_and_roles() {
  [ "$(psql_admin -c "SELECT count(*) FROM information_schema.tables WHERE table_name IN ('databasechangelog_security', 'databasechangeloglock_security')")" = 2 ] || { echo "the control tables with the security suffix are missing"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM information_schema.tables WHERE table_name IN ('databasechangelog', 'databasechangeloglock')")" = 0 ] || { echo "a default-named control table exists, two domains would share it"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM pg_authid WHERE rolname IN ('security_reader', 'security_writer') AND NOT rolcanlogin AND rolpassword IS NULL")" = 2 ] || { echo "the roles must be NOLOGIN and have no password"; return 1; }
  [ "$(psql_admin -c "SELECT pg_has_role('security_app', 'security_writer', 'MEMBER')")" = "t" ] || { echo "security_app is not a member of security_writer"; return 1; }
}

# The state of the control table, so a second update that applied anything shows as a difference
changelog_state() {
  psql_admin -c "SELECT count(*) || ':' || coalesce(md5(string_agg(id || md5sum, ',' ORDER BY orderexecuted)), '') FROM databasechangelog_security"
}

second_update_changes_nothing() {
  before=$(changelog_state)
  out=$(lb update 2>&1) || { printf '%s\n' "$out" | tail -n 8; return 1; }
  [ "$before" = "$(changelog_state)" ] || { echo "the second update changed the control table"; return 1; }
  case $before in 0:*) echo "no changeset was ever recorded"; return 1 ;; esac
}

rolled_back_to_empty() {
  lb rollback-count 999 >/dev/null 2>&1 || { echo "rollback-count 999 failed"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM information_schema.schemata WHERE schema_name = 'security'")" = 0 ] || { echo "the schema security is still there"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM pg_roles WHERE rolname IN ('security_reader', 'security_writer')")" = 0 ] || { echo "a security role is still there"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = 'security_app'")" = 0 ] || { echo "security_app is still a member of a role"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM pg_default_acl")" = 0 ] || { echo "a default privilege is left behind"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM databasechangelog_security")" = 0 ] || { echo "the control table still lists changesets"; return 1; }
}

# ---- the probes of the tables of HU-SEC-001 (spec 001-hu-sec-001, task SEC-04): what the engine refuses
T1=00000000-0000-4000-8000-0000000000a1
T2=00000000-0000-4000-8000-0000000000a2
HASH='$2a$12$'"$(printf 'a%.0s' $(seq 1 53))"
SESSION=00000000-0000-4000-8000-0000000000b1

# a statement the database must refuse, for the reason named by a fragment of its message
refused() { # fragment, statement
  out=$(psql_admin -c "$2" 2>&1) && { echo "the database accepted: $2"; return 1; }
  printf '%s' "$out" | grep -q "$1" || { echo "refused, but not for the expected reason ($1): $out"; return 1; }
}
# every table with a foreign key to these must be in the list, or the TRUNCATE fails and the probes say so
clean() {
  # the key table (HU-SEC-002) references identity, so it joins the TRUNCATE once it exists
  extra=$(psql_admin -c "SELECT CASE WHEN to_regclass('security.idempotency_key') IS NULL THEN '' ELSE ', security.idempotency_key' END") || return 1
  psql_admin -c "TRUNCATE security.refresh_token, security.session, security.membership_role, security.membership, security.identity, security.tenant_copy$extra" >/dev/null || { echo "could not clean the tables"; return 1; }
}
identity() { # tenant (quoted uuid or NULL), e-mail, status
  printf "INSERT INTO security.identity (identity_id, tenant_id, email_normalized, password_hash, identity_status) VALUES (gen_random_uuid(), %s, '%s', '%s', '%s')" "$1" "$2" "$HASH" "${3:-ACTIVE}"
}

account_is_unique_per_tenant_and_email_even_when_inactive() {
  clean; psql_admin -c "$(identity "'$T1'" ana@example.com INACTIVE)" >/dev/null || return 1
  refused uq_identity_tenant_email "$(identity "'$T1'" ana@example.com)"
}
same_email_in_another_tenant_is_another_account() {
  clean; psql_admin -c "$(identity "'$T1'" ana@example.com)" -c "$(identity "'$T2'" ana@example.com)" >/dev/null
}
the_platform_administrator_email_is_unique_though_it_has_no_tenant() {
  clean; psql_admin -c "$(identity NULL root@example.com)" >/dev/null || return 1
  refused uq_identity_tenant_email "$(identity NULL root@example.com)"
}
one_membership_per_account_and_roles_never_repeat() {
  clean; psql_admin -c "$(identity "'$T1'" ana@example.com)" >/dev/null || return 1
  id=$(psql_admin -c "SELECT identity_id FROM security.identity LIMIT 1")
  psql_admin -c "INSERT INTO security.membership (membership_id, identity_id, membership_status, created_by) VALUES ('$SESSION', '$id', 'ACTIVE', 'test')" >/dev/null || return 1
  refused uq_membership_identity "INSERT INTO security.membership (membership_id, identity_id, membership_status, created_by) VALUES (gen_random_uuid(), '$id', 'ACTIVE', 'test')" || return 1
  psql_admin -c "INSERT INTO security.membership_role (membership_id, role) VALUES ('$SESSION', 'TENANT_ADMINISTRATOR')" >/dev/null || return 1
  refused pk_membership_role "INSERT INTO security.membership_role (membership_id, role) VALUES ('$SESSION', 'TENANT_ADMINISTRATOR')" || return 1
  refused chk_membership_role_role "INSERT INTO security.membership_role (membership_id, role) VALUES ('$SESSION', 'SUPERUSER')"
}
password_hash_must_be_a_bcrypt_hash() {
  clean; refused chk_identity_password_hash "INSERT INTO security.identity (identity_id, tenant_id, email_normalized, password_hash, identity_status) VALUES (gen_random_uuid(), '$T1', 'ana@example.com', 'plain-password', 'ACTIVE')"
}
refresh_token_is_kept_only_as_a_hash() {
  clean; psql_admin -c "$(identity "'$T1'" ana@example.com)" >/dev/null || return 1
  id=$(psql_admin -c "SELECT identity_id FROM security.identity LIMIT 1")
  psql_admin -c "INSERT INTO security.session (session_id, identity_id, expires_at) VALUES ('$SESSION', '$id', now() + interval '7 days')" >/dev/null || return 1
  refused chk_refresh_token_hash "INSERT INTO security.refresh_token (token_hash, session_id, expires_at) VALUES ('plain-secret', '$SESSION', now() + interval '7 days')" || return 1
  psql_admin -c "INSERT INTO security.refresh_token (token_hash, session_id, expires_at) VALUES ('$(printf 'ab%.0s' $(seq 1 32))', '$SESSION', now() + interval '7 days')" >/dev/null
}
tenant_copy_has_one_row_per_tenant_and_a_known_status() {
  clean; psql_admin -c "INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at) VALUES ('$T1', 'acme-tours', 'ACTIVE', now())" >/dev/null || return 1
  refused pk_tenant_copy "INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at) VALUES ('$T1', 'acme-tours', 'ACTIVE', now())" || return 1
  refused chk_tenant_copy_status "INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at) VALUES ('$T2', 'other-tours', 'DELETED', now())"
}

foreign_keys_hold_and_restrict_or_cascade_as_declared() {
  clean || return 1; psql_admin -c "$(identity "'$T1'" ana@example.com)" >/dev/null || return 1
  id=$(psql_admin -c "SELECT identity_id FROM security.identity LIMIT 1")
  ghost=00000000-0000-4000-8000-0000000000ff
  refused fk_membership_identity "INSERT INTO security.membership (membership_id, identity_id, membership_status, created_by) VALUES (gen_random_uuid(), '$ghost', 'ACTIVE', 'test')" || return 1
  refused fk_session_identity "INSERT INTO security.session (session_id, identity_id, expires_at) VALUES (gen_random_uuid(), '$ghost', now() + interval '1 day')" || return 1
  refused fk_refresh_token_session "INSERT INTO security.refresh_token (token_hash, session_id, expires_at) VALUES ('$(printf 'cd%.0s' $(seq 1 32))', '$ghost', now() + interval '1 day')" || return 1
  refused fk_membership_role_membership "INSERT INTO security.membership_role (membership_id, role) VALUES ('$ghost', 'ANALYST')" || return 1
  psql_admin -c "INSERT INTO security.membership (membership_id, identity_id, membership_status, created_by) VALUES ('$SESSION', '$id', 'ACTIVE', 'test')" \
             -c "INSERT INTO security.membership_role (membership_id, role) VALUES ('$SESSION', 'ANALYST')" \
             -c "INSERT INTO security.session (session_id, identity_id, expires_at) VALUES ('$SESSION', '$id', now() + interval '1 day')" \
             -c "INSERT INTO security.refresh_token (token_hash, session_id, expires_at) VALUES ('$(printf 'ef%.0s' $(seq 1 32))', '$SESSION', now() + interval '1 day')" >/dev/null || return 1
  refused fk_membership_identity "DELETE FROM security.identity WHERE identity_id = '$id'" || return 1
  psql_admin -c "DELETE FROM security.membership WHERE membership_id = '$SESSION'" -c "DELETE FROM security.session WHERE session_id = '$SESSION'" >/dev/null || return 1
  [ "$(psql_admin -c "SELECT (SELECT count(*) FROM security.membership_role) + (SELECT count(*) FROM security.refresh_token)")" = 0 ] || { echo "the roles or the renewal values did not follow their parent"; return 1; }
}
the_other_checks_refuse_what_they_name() {
  clean || return 1
  h() { printf "INSERT INTO security.identity (identity_id, tenant_id, email_normalized, password_hash, identity_status) VALUES (gen_random_uuid(), '$T1', '%s', %s, '%s')" "$1" "$2" "${3:-ACTIVE}"; }
  b="'\$2a\$12\$'"
  refused chk_identity_password_hash "$(h a1@example.com "$b || repeat('a', 52)")" || return 1
  refused chk_identity_password_hash "$(h a2@example.com "$b || repeat('a', 54)")" || return 1
  refused chk_identity_password_hash "$(h a3@example.com "'\$2c\$12\$' || repeat('a', 53)")" || return 1
  refused chk_identity_password_hash "$(h a4@example.com "'\$2a\$99\$' || repeat('a', 53)")" || return 1
  refused chk_identity_password_hash "$(h a5@example.com "$b || repeat('a', 52) || chr(10)")" || return 1
  refused chk_identity_status "$(h a6@example.com "'$HASH'" DELETED)" || return 1
  refused chk_identity_email "$(h Upper@example.com "'$HASH'")" || return 1
  refused chk_identity_email "$(h ab "'$HASH'")" || return 1
  refused chk_refresh_token_hash "INSERT INTO security.refresh_token (token_hash, session_id, expires_at) VALUES ('$(printf 'AB%.0s' $(seq 1 32))', '$SESSION', now() + interval '1 day')" || return 1
  refused chk_tenant_copy_identifier "INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at) VALUES ('$T1', 'ab', 'ACTIVE', now())" || return 1
  psql_admin -c "INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at) VALUES ('$T1', 'acme-tours', 'ACTIVE', now())" >/dev/null || return 1
  refused uq_tenant_copy_identifier "INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at) VALUES ('$T2', 'acme-tours', 'ACTIVE', now())" || return 1
  psql_admin -c "$(identity "'$T1'" ana@example.com)" >/dev/null || return 1
  id=$(psql_admin -c "SELECT identity_id FROM security.identity LIMIT 1")
  refused chk_session_expires "INSERT INTO security.session (session_id, identity_id, expires_at) VALUES (gen_random_uuid(), '$id', now() + interval '8 days')" || return 1
  refused chk_membership_created_by "INSERT INTO security.membership (membership_id, identity_id, membership_status, created_by) VALUES (gen_random_uuid(), '$id', 'ACTIVE', '')"
}
the_app_user_writes_the_new_tables_and_the_indexes_exist() {
  for t in identity membership membership_role session refresh_token tenant_copy; do
    [ "$(psql_admin -c "SELECT has_table_privilege('security_app', 'security.$t', 'INSERT,UPDATE,DELETE')")" = t ] || { echo "security_app cannot write security.$t"; return 1; }
  done
  [ "$(psql_admin -c "SELECT count(*) FROM pg_indexes WHERE schemaname = 'security' AND indexname IN ('idx_session_identity_id', 'idx_refresh_token_session_id', 'idx_session_expires_at', 'idx_refresh_token_expires_at')")" = 4 ] || { echo "an index of the accounts is missing"; return 1; }
}

# ---- the probes of the account creation (spec 002-hu-sec-002, task ACC-03): profile columns and the idempotency key
a_profile_is_optional_and_refuses_a_name_or_phone_out_of_range() {
  clean || return 1
  psql_admin -c "$(identity "'$T1'" ana@example.com)" >/dev/null || return 1
  psql_admin -c "UPDATE security.identity SET full_name = NULL, phone = NULL" >/dev/null || { echo "a profile of null was refused"; return 1; }
  psql_admin -c "UPDATE security.identity SET full_name = repeat('n', 100), phone = '+57 (300) 123-4567'" >/dev/null || { echo "a valid profile was refused"; return 1; }
  refused chk_identity_full_name "UPDATE security.identity SET full_name = ''" || return 1
  refused chk_identity_full_name "UPDATE security.identity SET full_name = repeat('n', 101)" || return 1
  refused chk_identity_phone "UPDATE security.identity SET phone = '123456'" || return 1
  refused chk_identity_phone "UPDATE security.identity SET phone = repeat('1', 21)" || return 1
  refused chk_identity_phone "UPDATE security.identity SET phone = '300 abc 4567'"
}
the_idempotency_key_is_unique_per_scope_and_between_8_and_128_characters() {
  clean || return 1
  psql_admin -c "$(identity "'$T1'" ana@example.com)" >/dev/null || return 1
  id=$(psql_admin -c "SELECT identity_id FROM security.identity LIMIT 1")
  key() { printf "INSERT INTO security.idempotency_key (scope, idempotency_key, identity_id) VALUES ('%s', '%s', '$id')" "$1" "$2"; }
  psql_admin -c "$(key customer:$T1 abcdefgh)" >/dev/null || return 1
  refused pk_idempotency_key "$(key customer:$T1 abcdefgh)" || return 1
  psql_admin -c "$(key customer:$T2 abcdefgh)" -c "$(key first-admin:$T1 abcdefgh)" >/dev/null || { echo "the same key in another scope was refused"; return 1; }
  refused chk_idempotency_key_length "$(key customer:$T1 abcdefg)" || return 1
  refused chk_idempotency_key_length "$(key customer:$T1 "$(printf 'k%.0s' $(seq 1 129))")" || return 1
  psql_admin -c "$(key customer:$T1 "$(printf 'k%.0s' $(seq 1 128))")" >/dev/null
}
the_idempotency_key_follows_its_account_and_has_its_index() {
  clean || return 1
  ghost=00000000-0000-4000-8000-0000000000ff
  refused fk_idempotency_key_identity "INSERT INTO security.idempotency_key (scope, idempotency_key, identity_id) VALUES ('customer:$T1', 'abcdefgh', '$ghost')" || return 1
  psql_admin -c "$(identity "'$T1'" ana@example.com)" >/dev/null || return 1
  id=$(psql_admin -c "SELECT identity_id FROM security.identity LIMIT 1")
  psql_admin -c "INSERT INTO security.idempotency_key (scope, idempotency_key, identity_id) VALUES ('customer:$T1', 'abcdefgh', '$id')" >/dev/null || return 1
  psql_admin -c "DELETE FROM security.identity WHERE identity_id = '$id'" >/dev/null || { echo "the account could not be deleted with its key"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM security.idempotency_key")" = 0 ] || { echo "the key did not follow its account"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM pg_indexes WHERE schemaname = 'security' AND indexname = 'idx_idempotency_key_identity_id'")" = 1 ] || { echo "the index of the key's account is missing"; return 1; }
  [ "$(psql_admin -c "SELECT has_table_privilege('security_app', 'security.idempotency_key', 'INSERT,UPDATE,DELETE')")" = t ] || { echo "security_app cannot write the key table"; return 1; }
}

# ---- the probes of the e-mail verification (spec 004-hu-sec-003, task VER-02): the pending status, the link rows, the
# commercial name of the tenant and the accounts that already exist
psql_file() { # a SQL file run by the administrator, read from this checkout
  docker exec -i -e PGPASSWORD="$ADMIN_PASSWORD" "$RUN_ID" psql -h 127.0.0.1 -U postgres -d "$DB" -v ON_ERROR_STOP=1 -tA < "$1"
}
LINK_HASH=$(printf 'ab%.0s' $(seq 1 32))

a_pending_status_is_accepted_and_the_moment_of_verification_is_kept() {
  clean || return 1
  psql_admin -c "$(identity "'$T1'" ana@example.com PENDING)" >/dev/null || { echo "a PENDING account was refused"; return 1; }
  refused chk_identity_status "$(identity "'$T1'" bob@example.com VERIFIED)" || return 1
  psql_admin -c "UPDATE security.identity SET email_verified = true, email_verified_at = now(), identity_status = 'ACTIVE'" >/dev/null \
    || { echo "email_verified_at is missing"; return 1; }
}
link_rows_are_valid_unique_and_follow_their_account() {
  clean || return 1
  psql_admin -c "$(identity "'$T1'" ana@example.com PENDING)" >/dev/null || return 1
  id=$(psql_admin -c "SELECT identity_id FROM security.identity LIMIT 1")
  link() { printf "INSERT INTO security.email_verification (identity_id, token_hash, expires_at) VALUES ('%s', '%s', now() + interval '%s')" "$id" "$1" "${2:-24 hours}"; }
  psql_admin -c "$(link "$LINK_HASH")" >/dev/null || { echo "a valid link row was refused"; return 1; }
  refused idx_email_verification_token_hash "$(link "$LINK_HASH")" || return 1
  refused chk_email_verification_hash "$(link not-a-hash)" || return 1
  refused chk_email_verification_hash "$(link "$(printf 'AB%.0s' $(seq 1 32))")" || return 1
  refused chk_email_verification_expiry "$(link "$(printf 'cd%.0s' $(seq 1 32))" '-1 hour')" || return 1
  refused chk_email_verification_send_error "UPDATE security.email_verification SET send_failed_at = now(), send_error = repeat('e', 201)" || return 1
  refused fk_email_verification_identity "INSERT INTO security.email_verification (identity_id, token_hash, expires_at) VALUES ('00000000-0000-4000-8000-0000000000ff', '$(printf 'ef%.0s' $(seq 1 32))', now() + interval '1 day')" || return 1
  psql_admin -c "DELETE FROM security.identity WHERE identity_id = '$id'" >/dev/null || { echo "the account could not be deleted with its links"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM security.email_verification")" = 0 ] || { echo "the links did not follow their account"; return 1; }
  [ "$(psql_admin -c "SELECT count(*) FROM pg_indexes WHERE schemaname = 'security' AND indexname IN ('idx_email_verification_token_hash', 'idx_email_verification_identity_created_at')")" = 2 ] || { echo "an index of the links is missing"; return 1; }
  [ "$(psql_admin -c "SELECT has_table_privilege('security_app', 'security.email_verification', 'INSERT,UPDATE,DELETE')")" = t ] || { echo "security_app cannot write the links"; return 1; }
}
the_tenant_copy_keeps_an_optional_commercial_name() {
  clean || return 1
  psql_admin -c "INSERT INTO security.tenant_copy (tenant_id, identifier, status, occurred_at) VALUES ('$T1', 'acme-tours', 'ACTIVE', now())" >/dev/null || { echo "a copy without a name was refused"; return 1; }
  psql_admin -c "UPDATE security.tenant_copy SET commercial_name = 'Acme Tours SAS'" >/dev/null || { echo "the commercial name is missing"; return 1; }
  refused chk_tenant_copy_commercial_name "UPDATE security.tenant_copy SET commercial_name = ''" || return 1
  refused chk_tenant_copy_commercial_name "UPDATE security.tenant_copy SET commercial_name = repeat('n', 101)"
}
existing_unverified_customer_accounts_become_pending() {
  clean || return 1
  role() { # the account of an e-mail gets a membership with this role
    psql_admin -c "INSERT INTO security.membership (identity_id, created_by) SELECT identity_id, 'test' FROM security.identity WHERE email_normalized = '$1'" \
               -c "INSERT INTO security.membership_role (membership_id, role) SELECT m.membership_id, '$2' FROM security.membership m JOIN security.identity i USING (identity_id) WHERE i.email_normalized = '$1'" >/dev/null
  }
  psql_admin -c "$(identity "'$T1'" customer@example.com)" -c "$(identity "'$T1'" verified@example.com)" \
             -c "$(identity "'$T1'" staff@example.com)" -c "$(identity "'$T1'" both@example.com)" -c "$(identity NULL root@example.com)" >/dev/null || return 1
  psql_admin -c "UPDATE security.identity SET email_verified = true WHERE email_normalized = 'verified@example.com'" >/dev/null || return 1
  role customer@example.com FINAL_CUSTOMER && role verified@example.com FINAL_CUSTOMER && role staff@example.com ANALYST \
    && role both@example.com FINAL_CUSTOMER && role both@example.com ANALYST && role root@example.com PLATFORM_ADMINISTRATOR || return 1
  status() { psql_admin -c "SELECT identity_status FROM security.identity WHERE email_normalized = '$1'"; }

  psql_file db/02_dml/001_pending_for_unverified_customers.sql >/dev/null || { echo "the data migration did not run"; return 1; }
  [ "$(status customer@example.com)" = PENDING ] || { echo "an unverified customer account did not become pending"; return 1; }
  for e in verified@example.com staff@example.com both@example.com root@example.com; do
    [ "$(status $e)" = ACTIVE ] || { echo "$e must stay active"; return 1; }
  done
  psql_file db/05_rollbacks/02_dml/001_pending_for_unverified_customers.rollback.sql >/dev/null || { echo "its rollback did not run"; return 1; }
  [ "$(status customer@example.com)" = ACTIVE ] || { echo "the rollback did not restore the account"; return 1; }
}

# ---- an empty instance, as multi-tour-infra-postgres leaves it for this domain (J.7)
docker build -q -f deploy/liquibase.Dockerfile -t "$LIQUIBASE_IMAGE" deploy >/dev/null || { echo "the runner image did not build"; exit 1; }
docker network create "$RUN_ID" >/dev/null || exit 1
docker run -d --name "$RUN_ID" --network "$RUN_ID" -e POSTGRES_DB="$DB" -e POSTGRES_PASSWORD="$ADMIN_PASSWORD" "$POSTGRES_IMAGE" >/dev/null || exit 1
ready=0
for _ in $(seq 1 60); do
  if docker exec "$RUN_ID" pg_isready -h 127.0.0.1 -U postgres -d "$DB" >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || { echo "the throwaway PostgreSQL did not start"; exit 1; }
psql_admin -c "CREATE EXTENSION IF NOT EXISTS pgcrypto" \
           -c "CREATE ROLE security_app LOGIN PASSWORD '$APP_PASSWORD'" \
           -c "ALTER ROLE security_app SET search_path = security" \
           -c "CREATE SCHEMA other_domain" -c "CREATE TABLE other_domain.probe (id int)" >/dev/null || exit 1

check "I·db_ci_builds_from_empty" lb update
check "I·db_ci_second_update_changes_nothing" second_update_changes_nothing
check "I·security_app_writes_only_its_schema" writes_only_its_schema
check "I·owns_its_control_table_and_roles" owns_its_control_table_and_roles
check "I·account_is_unique_per_tenant_and_email_even_when_inactive" account_is_unique_per_tenant_and_email_even_when_inactive
check "I·same_email_in_another_tenant_is_another_account" same_email_in_another_tenant_is_another_account
check "I·the_platform_administrator_email_is_unique_though_it_has_no_tenant" the_platform_administrator_email_is_unique_though_it_has_no_tenant
check "I·one_membership_per_account_and_roles_never_repeat" one_membership_per_account_and_roles_never_repeat
check "I·password_hash_must_be_a_bcrypt_hash" password_hash_must_be_a_bcrypt_hash
check "I·refresh_token_is_kept_only_as_a_hash" refresh_token_is_kept_only_as_a_hash
check "I·tenant_copy_has_one_row_per_tenant_and_a_known_status" tenant_copy_has_one_row_per_tenant_and_a_known_status
check "I·foreign_keys_hold_and_restrict_or_cascade_as_declared" foreign_keys_hold_and_restrict_or_cascade_as_declared
check "I·the_other_checks_refuse_what_they_name" the_other_checks_refuse_what_they_name
check "I·the_app_user_writes_the_new_tables_and_the_indexes_exist" the_app_user_writes_the_new_tables_and_the_indexes_exist
check "I·a_profile_is_optional_and_refuses_a_name_or_phone_out_of_range" a_profile_is_optional_and_refuses_a_name_or_phone_out_of_range
check "I·the_idempotency_key_is_unique_per_scope_and_between_8_and_128_characters" the_idempotency_key_is_unique_per_scope_and_between_8_and_128_characters
check "I·the_idempotency_key_follows_its_account_and_has_its_index" the_idempotency_key_follows_its_account_and_has_its_index
check "I·a_pending_status_is_accepted_and_the_moment_of_verification_is_kept" a_pending_status_is_accepted_and_the_moment_of_verification_is_kept
check "I·link_rows_are_valid_unique_and_follow_their_account" link_rows_are_valid_unique_and_follow_their_account
check "I·the_tenant_copy_keeps_an_optional_commercial_name" the_tenant_copy_keeps_an_optional_commercial_name
check "I·existing_unverified_customer_accounts_become_pending" existing_unverified_customer_accounts_become_pending
# a pending account and a link row exist when the rollback runs, which must still leave the instance empty
clean
psql_admin -c "$(identity "'$T1'" ana@example.com PENDING)" >/dev/null
check "I·db_ci_rolls_back_to_empty" rolled_back_to_empty
check "I·db_ci_rebuilds_after_the_rollback" lb update
check "I·security_app_writes_only_its_schema_after_the_rebuild" writes_only_its_schema
check "I·owns_its_control_table_and_roles_after_the_rebuild" owns_its_control_table_and_roles

# the single name the spec uses for the whole sequence (AC-00.3)
[ "$fail" = 0 ] && echo "PASS  I·db_ci_builds_reruns_rolls_back_and_rebuilds"
[ "$fail" = 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit "$fail"
