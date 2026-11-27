#!/usr/bin/env bash
# Run only after run_foundation.sh in the same disposable PG16 service.
set -euo pipefail
: "${PG16_CONTAINER_ID:?Required disposable postgres service container}"
[[ "$PG16_CONTAINER_ID" =~ ^[a-f0-9]{12,64}$ ]]
[[ "$(docker inspect --format '{{.Config.Image}}' "$PG16_CONTAINER_ID")" == postgres:16 ]]
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
db=cephas_t02_test
admin() {
    docker exec -i "$PG16_CONTAINER_ID" psql -X -w -U postgres -d "$db" -v ON_ERROR_STOP=1 "$@"
}
declare -A passwords
for role in cephas_approver cephas_issuer cephas_activator cephas_retirer cephas_test_scope_a1 cephas_test_scope_a2 cephas_test_scope_b1; do
    passwords[$role]="$(openssl rand -hex 32)"
    # Fixture identities only. Password sent over stdin, never logged as a command.
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${passwords[$role]}" | admin >/dev/null
done
login() {
    local role="$1"
    shift
    docker exec -i -e PGPASSWORD="${passwords[$role]}" "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U "$role" -d "$db" -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
deny() {
    local role="$1" state="$2" query="$3" output
    if output="$(login "$role" -c "$query" 2>&1)"; then
        echo "Unexpected success: $role / $query" >&2; exit 1
    fi
    if ! grep -Eq "ERROR:[[:space:]]+$state:" <<< "$output"; then
        echo "Wrong failure for $role; expected $state" >&2
        printf '%s\n' "$output" >&2; exit 1
    fi
    printf 'Expected registry denial: %s / %s\n' "$role" "$state"
}
count_as() {
    local role="$1" expected="$2" query="$3"
    [[ "$(login "$role" -Atc "$query")" == "$expected" ]] || { echo "Unexpected registry result: $role" >&2; exit 1; }
}
sha256sum db/migrations/0002_registry.sql
admin < db/migrations/0002_registry.sql
# No operational tables. Existing B fixture roles are reused only in this disposable test.
admin -c 'ALTER ROLE cephas_test_scope_a1 NOLOGIN; ALTER ROLE cephas_test_scope_a2 NOLOGIN; ALTER ROLE cephas_test_scope_b1 NOLOGIN;'
approval() {
    local role="$1" seq="$2" tenant="$3" unit="$4"
    printf "INSERT INTO security.binding_approval (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id,approver_subject,second_approver_subject,change_ref,approval_evidence_sha256,expires_at) SELECT '00000000-0000-4000-8000-00000000000%s','t02-test-deployment',rolname,oid,'10000000-0000-4000-8000-00000000000%s','%s','%s','human1','human2','change-%s',repeat('a',64),statement_timestamp()+interval '10 minutes' FROM pg_catalog.pg_roles WHERE rolname='%s';" "$seq" "$seq" "$tenant" "$unit" "$seq" "$role"
}
issue() {
    local role="$1"
    login cephas_issuer -c "BEGIN; INSERT INTO security.role_issuance (role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id) SELECT role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id FROM security.binding_approval WHERE role_name='$role'; INSERT INTO security.scope_binding (role_name,role_oid,generation,tenant_id,business_unit_id) SELECT role_name,role_oid,generation,tenant_id,business_unit_id FROM security.role_issuance WHERE role_name='$role'; COMMIT;"
}
activate() {
    local role="$1"
    admin -c "ALTER ROLE $role LOGIN"
    [[ "$(login cephas_activator -Atc "UPDATE security.scope_binding SET state='active' WHERE role_name='$role' AND state='pending' RETURNING state" | head -n1)" == active ]]
}
for item in 'cephas_test_scope_a1 1 A 1' 'cephas_test_scope_a2 2 A 2' 'cephas_test_scope_b1 3 B 1'; do
    read -r role seq tenant unit <<< "$item"
    login cephas_approver -c "$(approval "$role" "$seq" "$tenant" "$unit")"
    issue "$role"
    admin -c "ALTER ROLE $role LOGIN"
    count_as "$role" 0 'SELECT count(role_name) FROM security.scope_binding'
    activate "$role"
    count_as "$role" 1 'SELECT count(role_name) FROM security.scope_binding'
    count_as "$role" "$role" 'SELECT role_name FROM security.scope_binding'
    deny "$role" 42501 'SELECT generation FROM security.scope_binding'
    deny "$role" 42501 "UPDATE security.scope_binding SET state='retired'"
    deny "$role" 42501 'SELECT * FROM security.binding_approval'
done
deny cephas_issuer 42501 "UPDATE security.scope_binding SET tenant_id='B'"
deny cephas_activator 42501 "UPDATE security.scope_binding SET tenant_id='B'"
deny cephas_retirer 42501 "UPDATE security.scope_binding SET tenant_id='B'"
deny cephas_issuer 42501 'DELETE FROM security.role_issuance'
deny cephas_issuer 42501 'TRUNCATE security.role_issuance'
deny cephas_approver 42501 "UPDATE security.binding_approval SET tenant_id='B'"
[[ "$(login cephas_activator -Atc "WITH changed AS (UPDATE security.scope_binding SET state='pending' WHERE role_name='cephas_test_scope_a1' RETURNING 1) SELECT count(*) FROM changed")" == 0 ]]
[[ "$(login cephas_retirer -Atc "WITH changed AS (UPDATE security.scope_binding SET state='retired' WHERE role_name='cephas_test_scope_a1' AND state='active' RETURNING 1) SELECT count(*) FROM changed")" == 1 ]]
count_as cephas_test_scope_a1 0 'SELECT count(role_name) FROM security.scope_binding'
[[ "$(login cephas_activator -Atc "WITH changed AS (UPDATE security.scope_binding SET state='active' WHERE role_name='cephas_test_scope_a1' RETURNING 1) SELECT count(*) FROM changed")" == 0 ]]
# Deliberate disposable stale-name recreation: old binding must not authorize new OID.
admin -c 'DROP ROLE cephas_test_scope_b1; CREATE ROLE cephas_test_scope_b1 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4; GRANT scoped_runtime TO cephas_test_scope_b1 WITH INHERIT TRUE; GRANT scoped_runtime TO cephas_test_scope_b1 WITH SET FALSE; GRANT scoped_runtime TO cephas_test_scope_b1 WITH ADMIN FALSE;'
printf "ALTER ROLE cephas_test_scope_b1 PASSWORD '%s';\n" "${passwords[cephas_test_scope_b1]}" | admin >/dev/null
count_as cephas_test_scope_b1 0 'SELECT count(role_name) FROM security.scope_binding'
# Registry tests also exercise a deliberately over-broad permissive policy.
admin -c 'SET ROLE cephas_owner; CREATE POLICY test_widen ON security.scope_binding FOR SELECT TO scoped_runtime USING (true); RESET ROLE;'
count_as cephas_test_scope_a2 1 'SELECT count(role_name) FROM security.scope_binding'
count_as cephas_test_scope_a1 0 'SELECT count(role_name) FROM security.scope_binding'
admin -c 'SET ROLE cephas_owner; DROP POLICY test_widen ON security.scope_binding; RESET ROLE;'
admin -c "DO \$\$ BEGIN IF (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='security' AND c.relname IN ('binding_approval','role_issuance','scope_binding') AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner='cephas_owner'::regrole) <> 3 THEN RAISE EXCEPTION 'registry RLS mismatch'; END IF; END \$\$;"
echo 'T-02.2C database registry smoke checks passed; external lifecycle not qualified'
