#!/usr/bin/env bash
# Tests only an isolated GitHub Actions PostgreSQL service container.
set -euo pipefail
: "${PG16_CONTAINER_ID:?Required disposable postgres service container}"
[[ "$PG16_CONTAINER_ID" =~ ^[a-f0-9]{12,64}$ ]] || { echo "Invalid container id" >&2; exit 1; }
[[ "$(docker inspect --format '{{.Config.Image}}' "$PG16_CONTAINER_ID")" == postgres:16 ]] || {
    echo "Expected postgres:16 service" >&2; exit 1;
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
db=cephas_t02_test
pw_registry="$(openssl rand -hex 32)"
pw_migration="$(openssl rand -hex 32)"
pw_a1="$(openssl rand -hex 32)"
pw_a2="$(openssl rand -hex 32)"
pw_b1="$(openssl rand -hex 32)"
admin() {
    docker exec -i "$PG16_CONTAINER_ID" psql -X -w -U postgres -d "$db" -v ON_ERROR_STOP=1 "$@"
}
login() {
    local role="$1" password
    shift
    case "$role" in
        cephas_registry_admin) password="$pw_registry" ;;
        cephas_migration) password="$pw_migration" ;;
        cephas_test_scope_a1) password="$pw_a1" ;;
        cephas_test_scope_a2) password="$pw_a2" ;;
        cephas_test_scope_b1) password="$pw_b1" ;;
        *) echo "Unknown fixture role" >&2; return 1 ;;
    esac
    docker exec -i -e PGPASSWORD="$password" "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 \
        -U "$role" -d "$db" -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
deny() {
    local role="$1" state="$2" query="$3" output
    if output="$(login "$role" -c "$query" 2>&1)"; then
        echo "Unexpected success: $role / $query" >&2
        exit 1
    fi
    if ! grep -Eq "ERROR:[[:space:]]+$state:" <<< "$output"; then
        echo "Wrong failure for $role; expected $state" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    printf 'Expected denial: %s / %s\n' "$role" "$state"
}
printf 'Commit: %s\n' "${GITHUB_SHA:-$(git rev-parse HEAD)}"
sha256sum db/migrations/0001_foundation.sql
admin -Atc 'SHOW server_version'
admin < db/migrations/0001_foundation.sql
# Re-application is intentionally rejected; no idempotency or upgrade claim.
if admin < db/migrations/0001_foundation.sql > /tmp/cephas-t02-repeat.log 2>&1; then
    echo "Unexpected repeat migration success" >&2; exit 1
fi
grep -q 'already exists' /tmp/cephas-t02-repeat.log
admin -v pw_registry="$pw_registry" -v pw_migration="$pw_migration" -v pw_a1="$pw_a1" -v pw_a2="$pw_a2" -v pw_b1="$pw_b1" < db/tests/0001_fixture.sql
# A scope A1 credential must not authenticate as scope B1.
if wrong_login="$(docker exec -i -e PGPASSWORD="$pw_a1" "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U cephas_test_scope_b1 -d "$db" -Atc 'SELECT session_user' 2>&1)"; then
    echo "Cross-role password unexpectedly accepted" >&2; exit 1
fi
grep -q 'password authentication failed' <<< "$wrong_login"
admin < db/tests/0001_catalog.sql
[[ "$(login cephas_registry_admin -Atc 'SELECT session_user')" == cephas_registry_admin ]]
login cephas_registry_admin -c "INSERT INTO security.tenant VALUES ('A'), ('B'); INSERT INTO security.business_unit VALUES ('A','1'), ('A','2'), ('B','1');"
[[ "$(login cephas_registry_admin -Atc 'SELECT count(*) FROM security.business_unit')" == 3 ]]
deny cephas_registry_admin 23514 "INSERT INTO security.tenant VALUES ('-bad')"
deny cephas_registry_admin 23514 "INSERT INTO security.tenant VALUES (repeat('A',129))"
deny cephas_registry_admin 23514 "INSERT INTO security.tenant VALUES (E'A\n')"
deny cephas_registry_admin 23514 "INSERT INTO security.tenant VALUES ('é')"
deny cephas_registry_admin 23503 "INSERT INTO security.business_unit VALUES ('missing','1')"
deny cephas_registry_admin 23505 "INSERT INTO security.business_unit VALUES ('A','1')"
deny cephas_registry_admin 42501 "UPDATE security.tenant SET tenant_id='C'"
deny cephas_registry_admin 42501 "DELETE FROM security.business_unit"
deny cephas_registry_admin 42501 "TRUNCATE security.tenant"
deny cephas_registry_admin 42501 "SET ROLE cephas_owner"
for role in cephas_test_scope_a1 cephas_test_scope_a2 cephas_test_scope_b1; do
    [[ "$(login "$role" -Atc 'SELECT session_user')" == "$role" ]]
    deny "$role" 42501 "SELECT * FROM security.tenant"
    deny "$role" 42501 "INSERT INTO security.business_unit VALUES ('A','9')"
    deny "$role" 42501 "SET ROLE scoped_runtime"
    deny "$role" 42501 "SET ROLE cephas_owner"
    deny "$role" 42501 "SET SESSION AUTHORIZATION cephas_registry_admin"
    deny "$role" 42501 "CREATE TABLE ops.forbidden (id int)"
    deny "$role" 42501 "CREATE TEMP TABLE forbidden (id int)"
done
# Verify future-object defaults using the real migration login, not bootstrap SET ROLE.
[[ "$(login cephas_migration -Atc 'SELECT session_user')" == cephas_migration ]]
deny cephas_migration 42501 "CREATE TABLE ops.forbidden (id int)"
login cephas_migration -c 'SET ROLE cephas_owner; CREATE TABLE ops.future_probe (id int); CREATE FUNCTION ops.future_function() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$; RESET ROLE;'
deny cephas_test_scope_a1 42501 "SELECT * FROM ops.future_probe"
deny cephas_test_scope_a1 42501 "SELECT ops.future_function()"
login cephas_migration -c 'SET ROLE cephas_owner; DROP FUNCTION ops.future_function(); DROP TABLE ops.future_probe; RESET ROLE;'
# Owner is subject to forced RLS (no ordinary SELECT policy).
[[ "$(login cephas_migration -Atc 'SET ROLE cephas_owner; SELECT count(*) FROM security.tenant; RESET ROLE;' | grep -E '^[0-9]+$')" == 0 ]]
echo "T-02.2B PostgreSQL 16 foundation checks passed (not operational RLS qualification)"
