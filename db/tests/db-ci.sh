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
check "I·db_ci_rolls_back_to_empty" rolled_back_to_empty
check "I·db_ci_rebuilds_after_the_rollback" lb update
check "I·security_app_writes_only_its_schema_after_the_rebuild" writes_only_its_schema
check "I·owns_its_control_table_and_roles_after_the_rebuild" owns_its_control_table_and_roles

# the single name the spec uses for the whole sequence (AC-00.3)
[ "$fail" = 0 ] && echo "PASS  I·db_ci_builds_reruns_rolls_back_and_rebuilds"
[ "$fail" = 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit "$fail"
