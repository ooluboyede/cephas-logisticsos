#!/usr/bin/env bash
set -euo pipefail
: "${PG16_CONTAINER_ID:?Required disposable postgres service container}"
[[ "$PG16_CONTAINER_ID" =~ ^[a-f0-9]{12,64}$ ]]
[[ "$(docker inspect --format '{{.Config.Image}}' "$PG16_CONTAINER_ID")" == postgres:16 ]]
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
admin() {
    docker exec -i "$PG16_CONTAINER_ID" psql -X -w -U postgres -d cephas_t02_test -v ON_ERROR_STOP=1 "$@"
}
verify() {
    admin < db/tests/0004_role_inventory.sql || return $?
}
drift() {
    local mutation="$1" restore="$2" reason="$3" output
    admin -c "$mutation"
    if output="$(verify 2>&1)"; then
        echo "Role manifest unexpectedly accepted: $reason" >&2; exit 1
    fi
    if ! grep -Fq "ERROR:  role manifest: $reason" <<< "$output"; then
        printf 'Unexpected role manifest failure: %s\n%s\n' "$reason" "$output" >&2; exit 1
    fi
    admin -c "$restore"
    verify
    printf 'Role manifest detected drift: %s\n' "$reason"
}
sha256sum db/tests/0004_role_inventory.sql
verify
drift 'CREATE ROLE cephas_test_unexpected NOLOGIN' 'DROP ROLE cephas_test_unexpected' 'role inventory'
drift 'ALTER ROLE cephas_test_assoc_1 BYPASSRLS' 'ALTER ROLE cephas_test_assoc_1 NOBYPASSRLS' 'role attributes'
drift 'ALTER ROLE cephas_test_assoc_1 SET row_security=off' 'ALTER ROLE cephas_test_assoc_1 RESET row_security' 'unexpected role settings'
drift 'GRANT cephas_owner TO cephas_test_assoc_1 WITH SET TRUE' 'REVOKE cephas_owner FROM cephas_test_assoc_1' 'membership graph'
drift 'GRANT scoped_runtime TO cephas_test_assoc_1 WITH SET TRUE' 'GRANT scoped_runtime TO cephas_test_assoc_1 WITH SET FALSE' 'membership graph'
drift 'GRANT TEMP ON DATABASE cephas_t02_test TO scoped_runtime' 'REVOKE TEMP ON DATABASE cephas_t02_test FROM scoped_runtime' 'database ACL'
drift 'GRANT USAGE ON SCHEMA membership TO scoped_runtime' 'REVOKE USAGE ON SCHEMA membership FROM scoped_runtime' 'schema ACL'
drift 'CREATE VIEW public.unexpected AS SELECT 1' 'DROP VIEW public.unexpected' 'alternate access objects'
drift 'ALTER DEFAULT PRIVILEGES FOR ROLE cephas_owner GRANT EXECUTE ON FUNCTIONS TO PUBLIC' 'ALTER DEFAULT PRIVILEGES FOR ROLE cephas_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC' 'owner default privileges'

# Direct TCP authentication for every control role and three independent association scopes.
# Random disposable credentials; never print them or add a production credential.
declare -A pw
login() {
    local role="$1"; shift
    docker exec -i -e PGPASSWORD="${pw[$role]}" "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U "$role" -d cephas_t02_test -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
deny() {
    local role="$1" query="$2" output
    if output="$(login "$role" -Atqc "$query" 2>&1)"; then
        printf 'Unexpected access success: %s\n' "$role" >&2; exit 1
    fi
    if ! grep -Eq 'ERROR:[[:space:]]+42501:' <<< "$output"; then
        printf 'Wrong access-denial SQLSTATE: %s\n' "$role" >&2; exit 1
    fi
}
for role in cephas_migration cephas_membership cephas_registry_admin cephas_approver cephas_issuer cephas_activator cephas_retirer cephas_test_assoc_1 cephas_test_assoc_2 cephas_test_assoc_3; do
    pw[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${pw[$role]}" | admin >/dev/null
    [[ "$(login "$role" -Atqc 'SELECT session_user')" == "$role" ]]
    deny "$role" 'SET ROLE scoped_runtime'
    deny "$role" 'SET SESSION AUTHORIZATION postgres'
    deny "$role" 'CREATE TEMP TABLE forbidden (id int)'
    deny "$role" 'CREATE TABLE public.forbidden (id int)'
    deny "$role" 'CREATE TABLE ops.forbidden (id int)'
    if [[ "$role" != cephas_migration ]]; then
        deny "$role" 'SET ROLE cephas_owner'
    else
        [[ "$(login "$role" -Atqc 'SET ROLE cephas_owner; SELECT current_user; RESET ROLE;')" == cephas_owner ]]
    fi
    if [[ "$role" == cephas_test_assoc_* ]]; then
        deny "$role" 'SELECT count(*) FROM security.binding_approval'
        deny "$role" 'SELECT count(*) FROM security.role_issuance'
    else
        deny "$role" 'SELECT count(*) FROM ops.scoped_entity'
        deny "$role" 'SELECT count(*) FROM ops.scoped_association'
    fi
    printf 'Verified direct-login access boundaries: %s\n' "$role"
done
verify
echo 'T-02.2D.4A fixture role inventory and direct-login privilege qualification passed'
