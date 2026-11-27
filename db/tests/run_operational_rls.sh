#!/usr/bin/env bash
# Disposable service only; direct TCP authenticated fixture identities.
set -euo pipefail
: "${PG16_CONTAINER_ID:?Required disposable postgres service container}"
[[ "$PG16_CONTAINER_ID" =~ ^[a-f0-9]{12,64}$ ]]
[[ "$(docker inspect --format '{{.Config.Image}}' "$PG16_CONTAINER_ID")" == postgres:16 ]]
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
db=cephas_t02_test
admin() {
    docker exec -i "$PG16_CONTAINER_ID" psql -X -w -U postgres -d "$db" -v ON_ERROR_STOP=1 "$@"
}
sha256sum db/migrations/0003_operational_rls.sql
admin < db/migrations/0003_operational_rls.sql
# New role names: do not reuse retired or recreated identities from earlier tests.
declare -A pw
for role in cephas_registry_admin cephas_approver cephas_issuer cephas_activator cephas_retirer; do
    pw[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${pw[$role]}" | admin >/dev/null
done
login() {
    local role="$1"; shift
    docker exec -i -e PGPASSWORD="${pw[$role]}" "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U "$role" -d "$db" -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
login cephas_registry_admin -c "INSERT INTO security.tenant VALUES ('RLSA'),('RLSB'); INSERT INTO security.business_unit VALUES ('RLSA','1'),('RLSA','2'),('RLSB','1');"
for item in '1 RLSA 1' '2 RLSA 2' '3 RLSB 1'; do
    read -r n tenant unit <<< "$item"
    role="cephas_test_rls_$n"
    admin -c "CREATE ROLE $role NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4; GRANT scoped_runtime TO $role WITH INHERIT TRUE; GRANT scoped_runtime TO $role WITH SET FALSE; GRANT scoped_runtime TO $role WITH ADMIN FALSE;"
    pw[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${pw[$role]}" | admin >/dev/null
    login cephas_approver -c "INSERT INTO security.binding_approval (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id,approver_subject,second_approver_subject,change_ref,approval_evidence_sha256,expires_at) SELECT '60000000-0000-4000-8000-00000000000$n','t02-test-deployment',rolname,oid,'70000000-0000-4000-8000-00000000000$n','$tenant','$unit','human1','human2','rls-change-$n',repeat('d',64),statement_timestamp()+interval '10 minutes' FROM pg_roles WHERE rolname='$role';"
    login cephas_issuer -c "BEGIN; INSERT INTO security.role_issuance (role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id) SELECT role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id FROM security.binding_approval WHERE role_name='$role'; INSERT INTO security.scope_binding (role_name,role_oid,generation,tenant_id,business_unit_id) SELECT role_name,role_oid,generation,tenant_id,business_unit_id FROM security.role_issuance WHERE role_name='$role'; COMMIT;"
    admin -c "ALTER ROLE $role LOGIN;"
    [[ "$(login cephas_activator -Atqc "WITH c AS (UPDATE security.scope_binding SET state='active' WHERE role_name='$role' AND state='pending' RETURNING 1) SELECT count(*) FROM c;")" == 1 ]]
done
context() {
    printf "SET LOCAL cephas.subject_id='subject1'; SET LOCAL cephas.tenant_id='%s'; SET LOCAL cephas.business_unit_id='%s';" "$1" "$2"
}
query() {
    local role="$1" tenant="$2" unit="$3" sql="$4"
    login "$role" -Atqc "BEGIN; $(context "$tenant" "$unit") $sql; COMMIT;"
}
expect() {
    local role="$1" tenant="$2" unit="$3" expected="$4" sql="$5"
    [[ "$(query "$role" "$tenant" "$unit" "$sql")" == "$expected" ]] || {
        echo "Unexpected scoped result: $role / $tenant / $unit" >&2; exit 1;
    }
}
deny() {
    local role="$1" tenant="$2" unit="$3" state="$4" sql="$5" output
    if output="$(query "$role" "$tenant" "$unit" "$sql" 2>&1)"; then
        echo "Unexpected scoped write success: $role" >&2; exit 1
    fi
    if ! grep -Eq "ERROR:[[:space:]]+$state:" <<< "$output"; then
        printf 'Unexpected failure for %s: %s\n%s\n' "$role" "$state" "$output" >&2; exit 1
    fi
    printf 'Expected scoped denial: %s / %s\n' "$role" "$state"
}
for item in '1 RLSA 1' '2 RLSA 2' '3 RLSB 1'; do
    read -r n tenant unit <<< "$item"
    role="cephas_test_rls_$n"
    expect "$role" "$tenant" "$unit" "$role" 'SELECT session_user'
    expect "$role" "$tenant" "$unit" 1 "WITH c AS (INSERT INTO ops.scoped_entity VALUES ('$tenant','$unit','same','p$n') RETURNING 1) SELECT count(*) FROM c"
done
for item in '1 RLSA 1' '2 RLSA 2' '3 RLSB 1'; do
    read -r n tenant unit <<< "$item"
    role="cephas_test_rls_$n"
    expect "$role" "$tenant" "$unit" "p$n" "SELECT payload FROM ops.scoped_entity WHERE entity_id='same'"
    expect "$role" "$tenant" "$unit" 1 "SELECT count(*) FROM ops.scoped_entity"
    expect "$role" "$tenant" "$unit" 1 "WITH c AS (UPDATE ops.scoped_entity SET payload='own$n' WHERE entity_id='same' RETURNING 1) SELECT count(*) FROM c"
    expect "$role" "$tenant" "$unit" "up$n" "INSERT INTO ops.scoped_entity VALUES ('$tenant','$unit','same','up$n') ON CONFLICT (tenant_id,business_unit_id,entity_id) DO UPDATE SET payload=EXCLUDED.payload RETURNING payload"
    expect "$role" "$tenant" "$unit" 1 "WITH c AS (INSERT INTO ops.scoped_entity VALUES ('$tenant','$unit','delete-me','x') RETURNING 1) SELECT count(*) FROM c"
    expect "$role" "$tenant" "$unit" 1 "WITH c AS (DELETE FROM ops.scoped_entity WHERE entity_id='delete-me' RETURNING 1) SELECT count(*) FROM c"
    deny "$role" "$tenant" "$unit" 42501 "UPDATE ops.scoped_entity SET entity_id='changed'"
    deny "$role" "$tenant" "$unit" 42501 "UPDATE ops.scoped_entity SET tenant_id='RLSB'"
    deny "$role" "$tenant" "$unit" 42501 "UPDATE ops.scoped_entity SET business_unit_id='2'"
    deny "$role" "$tenant" "$unit" 42501 'TRUNCATE ops.scoped_entity'
    for foreign in 'RLSA 1' 'RLSA 2' 'RLSB 1'; do
        read -r ft fu <<< "$foreign"
        [[ "$ft $fu" != "$tenant $unit" ]] || continue
        # Both correct-context foreign rows and forged foreign context must remain invisible.
        expect "$role" "$tenant" "$unit" 0 "SELECT count(*) FROM ops.scoped_entity WHERE tenant_id='$ft' AND business_unit_id='$fu'"
        expect "$role" "$ft" "$fu" 0 'SELECT count(*) FROM ops.scoped_entity'
        expect "$role" "$ft" "$fu" 0 "WITH c AS (UPDATE ops.scoped_entity SET payload='bad' RETURNING 1) SELECT count(*) FROM c"
        expect "$role" "$ft" "$fu" 0 "WITH c AS (DELETE FROM ops.scoped_entity RETURNING 1) SELECT count(*) FROM c"
        deny "$role" "$tenant" "$unit" 42501 "INSERT INTO ops.scoped_entity VALUES ('$ft','$fu','foreign','bad')"
        deny "$role" "$ft" "$fu" 42501 "INSERT INTO ops.scoped_entity VALUES ('$ft','$fu','same','bad') ON CONFLICT (tenant_id,business_unit_id,entity_id) DO UPDATE SET payload=EXCLUDED.payload"
    done
    [[ "$(login "$role" -Atqc 'SELECT count(*) FROM ops.scoped_entity')" == 0 ]]
    for setting in subject_id tenant_id business_unit_id; do
        expect "$role" "$tenant" "$unit" 0 "SET LOCAL cephas.$setting=''; SELECT count(*) FROM ops.scoped_entity"
        expect "$role" "$tenant" "$unit" 0 "SET LOCAL cephas.$setting='-bad'; SELECT count(*) FROM ops.scoped_entity"
        expect "$role" "$tenant" "$unit" 0 "SET LOCAL cephas.$setting=E'bad\\n'; SELECT count(*) FROM ops.scoped_entity"
    done
    # No context survives a committed transaction on the same connection.
    [[ "$(login "$role" -Atqc "BEGIN; $(context "$tenant" "$unit") SELECT count(*) FROM ops.scoped_entity; COMMIT; SELECT count(*) FROM ops.scoped_entity")" == $'1\n0' ]]
done
admin -c 'SET ROLE cephas_owner; CREATE POLICY test_widen ON ops.scoped_entity FOR ALL TO scoped_runtime USING (true) WITH CHECK (true); RESET ROLE;'
expect cephas_test_rls_1 RLSA 1 1 'SELECT count(*) FROM ops.scoped_entity'
expect cephas_test_rls_1 RLSB 1 0 'SELECT count(*) FROM ops.scoped_entity'
deny cephas_test_rls_1 RLSB 1 42501 "INSERT INTO ops.scoped_entity VALUES ('RLSB','1','foreign','bad')"
admin -c 'SET ROLE cephas_owner; DROP POLICY test_widen ON ops.scoped_entity; RESET ROLE;'
# Retired mapping is invisible even while a fixture login can still connect.
[[ "$(login cephas_retirer -Atqc "WITH c AS (UPDATE security.scope_binding SET state='retired' WHERE role_name='cephas_test_rls_3' AND state='active' RETURNING 1) SELECT count(*) FROM c;")" == 1 ]]
expect cephas_test_rls_3 RLSB 1 0 'SELECT count(*) FROM ops.scoped_entity'
deny cephas_test_rls_3 RLSB 1 42501 "INSERT INTO ops.scoped_entity VALUES ('RLSB','1','new','bad')"
admin -c 'ALTER ROLE cephas_test_rls_3 NOLOGIN;'
expect cephas_test_rls_1 RLSA 1 up1 "SELECT payload FROM ops.scoped_entity WHERE entity_id='same'"
expect cephas_test_rls_2 RLSA 2 up2 "SELECT payload FROM ops.scoped_entity WHERE entity_id='same'"
echo 'T-02.2D.1 operational RLS direct-login tests passed'
