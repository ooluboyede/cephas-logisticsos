#!/usr/bin/env bash
# Disposable PG16 service; direct fixture logins, not customer admission.
set -euo pipefail
: "${PG16_CONTAINER_ID:?Required disposable postgres service container}"
[[ "$PG16_CONTAINER_ID" =~ ^[a-f0-9]{12,64}$ ]]
[[ "$(docker inspect --format '{{.Config.Image}}' "$PG16_CONTAINER_ID")" == postgres:16 ]]
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
db=cephas_t02_test
admin() {
    docker exec -i "$PG16_CONTAINER_ID" psql -X -w -U postgres -d "$db" -v ON_ERROR_STOP=1 "$@"
}
sha256sum db/migrations/0004_scoped_associations.sql
admin < db/migrations/0004_scoped_associations.sql
declare -A pw
# Provision new fixture scopes so earlier lifecycle tests are not disturbed.
for role in cephas_registry_admin cephas_approver cephas_issuer cephas_activator; do
    pw[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${pw[$role]}" | admin >/dev/null
done
login() {
    local role="$1"; shift
    docker exec -i -e PGPASSWORD="${pw[$role]}" "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U "$role" -d "$db" -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
login cephas_registry_admin -c "INSERT INTO security.tenant VALUES ('ASSOCA'),('ASSOCB'); INSERT INTO security.business_unit VALUES ('ASSOCA','1'),('ASSOCA','2'),('ASSOCB','1');"
for item in '1 ASSOCA 1' '2 ASSOCA 2' '3 ASSOCB 1'; do
    read -r n tenant unit <<< "$item"
    role="cephas_test_assoc_$n"
    admin -c "CREATE ROLE $role NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4; GRANT scoped_runtime TO $role WITH INHERIT TRUE; GRANT scoped_runtime TO $role WITH SET FALSE; GRANT scoped_runtime TO $role WITH ADMIN FALSE;"
    pw[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${pw[$role]}" | admin >/dev/null
    login cephas_approver -c "INSERT INTO security.binding_approval (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id,approver_subject,second_approver_subject,change_ref,approval_evidence_sha256,expires_at) SELECT '80000000-0000-4000-8000-00000000000$n','t02-test-deployment',rolname,oid,'90000000-0000-4000-8000-00000000000$n','$tenant','$unit','human1','human2','assoc-change-$n',repeat('e',64),statement_timestamp()+interval '10 minutes' FROM pg_roles WHERE rolname='$role';"
    login cephas_issuer -c "BEGIN; INSERT INTO security.role_issuance (role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id) SELECT role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id FROM security.binding_approval WHERE role_name='$role'; INSERT INTO security.scope_binding (role_name,role_oid,generation,tenant_id,business_unit_id) SELECT role_name,role_oid,generation,tenant_id,business_unit_id FROM security.role_issuance WHERE role_name='$role'; COMMIT;"
    admin -c "ALTER ROLE $role LOGIN;"
    [[ "$(login cephas_activator -Atqc "WITH c AS (UPDATE security.scope_binding SET state='active' WHERE role_name='$role' AND state='pending' RETURNING 1) SELECT count(*) FROM c;")" == 1 ]]
done
query() {
    local role="$1" tenant="$2" unit="$3" sql="$4"
    login "$role" -Atqc "BEGIN; SET LOCAL cephas.subject_id='subject1'; SET LOCAL cephas.tenant_id='$tenant'; SET LOCAL cephas.business_unit_id='$unit'; $sql; COMMIT;"
}
expect() {
    local role="$1" tenant="$2" unit="$3" expected="$4" sql="$5"
    [[ "$(query "$role" "$tenant" "$unit" "$sql")" == "$expected" ]] || {
        echo "Unexpected association result: $role" >&2; exit 1;
    }
}
deny() {
    local role="$1" tenant="$2" unit="$3" state="$4" sql="$5" output
    if output="$(query "$role" "$tenant" "$unit" "$sql" 2>&1)"; then
        echo "Unexpected association success: $role" >&2; exit 1
    fi
    if ! grep -Eq "ERROR:[[:space:]]+$state:" <<< "$output"; then
        # Fixture errors only. Do not forward server detail to end users.
        printf 'Unexpected association SQLSTATE for %s: %s\n' "$role" "$state" >&2; exit 1
    fi
    printf 'Expected association denial: %s / %s\n' "$role" "$state"
}
for item in '1 ASSOCA 1' '2 ASSOCA 2' '3 ASSOCB 1'; do
    read -r n tenant unit <<< "$item"
    role="cephas_test_assoc_$n"
    expect "$role" "$tenant" "$unit" 3 "WITH c AS (INSERT INTO ops.scoped_entity VALUES ('$tenant','$unit','source','s$n'),('$tenant','$unit','target','t$n'),('$tenant','$unit','exclusive$n','e$n') RETURNING 1) SELECT count(*) FROM c"
    expect "$role" "$tenant" "$unit" 1 "WITH c AS (INSERT INTO ops.scoped_association VALUES ('$tenant','$unit','same','source','target','p$n') RETURNING 1) SELECT count(*) FROM c"
done
for item in '1 ASSOCA 1' '2 ASSOCA 2' '3 ASSOCB 1'; do
    read -r n tenant unit <<< "$item"
    role="cephas_test_assoc_$n"
    expect "$role" "$tenant" "$unit" "p$n" "SELECT payload FROM ops.scoped_association WHERE association_id='same'"
    expect "$role" "$tenant" "$unit" 1 'SELECT count(*) FROM ops.scoped_association'
    expect "$role" "$tenant" "$unit" "up$n" "INSERT INTO ops.scoped_association VALUES ('$tenant','$unit','same','source','target','up$n') ON CONFLICT (tenant_id,business_unit_id,association_id) DO UPDATE SET payload=EXCLUDED.payload RETURNING payload"
    deny "$role" "$tenant" "$unit" 42501 "UPDATE ops.scoped_association SET source_entity_id='target'"
    deny "$role" "$tenant" "$unit" 42501 "UPDATE ops.scoped_association SET target_entity_id='source'"
    deny "$role" "$tenant" "$unit" 42501 "UPDATE ops.scoped_association SET association_id='new'"
    deny "$role" "$tenant" "$unit" 42501 "UPDATE ops.scoped_association SET tenant_id='ASSOCB'"
    deny "$role" "$tenant" "$unit" 42501 "UPDATE ops.scoped_association SET business_unit_id='2'"
    deny "$role" "$tenant" "$unit" 23503 "DELETE FROM ops.scoped_entity WHERE entity_id='source'"
    for foreign in '1 ASSOCA 1' '2 ASSOCA 2' '3 ASSOCB 1'; do
        read -r fn ft fu <<< "$foreign"
        [[ "$fn" != "$n" ]] || continue
        # Foreign-only endpoint ID and nonexistent endpoint ID must fail with same SQLSTATE.
        for endpoint in "exclusive$fn" never_exists; do
            deny "$role" "$tenant" "$unit" 23503 "INSERT INTO ops.scoped_association VALUES ('$tenant','$unit','bad-source','$endpoint','target','bad')"
            deny "$role" "$tenant" "$unit" 23503 "INSERT INTO ops.scoped_association VALUES ('$tenant','$unit','bad-target','source','$endpoint','bad')"
        done
        expect "$role" "$ft" "$fu" 0 'SELECT count(*) FROM ops.scoped_association'
        expect "$role" "$ft" "$fu" 0 "WITH c AS (UPDATE ops.scoped_association SET payload='bad' RETURNING 1) SELECT count(*) FROM c"
        expect "$role" "$ft" "$fu" 0 "WITH c AS (DELETE FROM ops.scoped_association RETURNING 1) SELECT count(*) FROM c"
        for id in same never_exists; do
            deny "$role" "$ft" "$fu" 42501 "INSERT INTO ops.scoped_association VALUES ('$ft','$fu','$id','source','target','bad') ON CONFLICT (tenant_id,business_unit_id,association_id) DO UPDATE SET payload=EXCLUDED.payload"
        done
    done
    expect "$role" "$tenant" "$unit" "up$n" "SELECT payload FROM ops.scoped_association WHERE association_id='same'"
    [[ "$(login "$role" -Atqc 'SELECT count(*) FROM ops.scoped_association')" == 0 ]]
done
# Scope guard survives an extra permissive policy.
admin -c 'CREATE POLICY test_assoc_widen ON ops.scoped_association FOR ALL TO scoped_runtime USING (true) WITH CHECK (true);'
expect cephas_test_assoc_1 ASSOCA 2 0 'SELECT count(*) FROM ops.scoped_association'
deny cephas_test_assoc_1 ASSOCA 2 42501 "INSERT INTO ops.scoped_association VALUES ('ASSOCA','2','forged','source','target','bad')"
admin -c 'DROP POLICY test_assoc_widen ON ops.scoped_association;'
expect cephas_test_assoc_1 ASSOCA 1 1 "WITH c AS (DELETE FROM ops.scoped_association WHERE association_id='same' RETURNING 1) SELECT count(*) FROM c"
expect cephas_test_assoc_1 ASSOCA 1 1 "WITH c AS (DELETE FROM ops.scoped_entity WHERE entity_id='source' RETURNING 1) SELECT count(*) FROM c"
expect cephas_test_assoc_2 ASSOCA 2 up2 "SELECT payload FROM ops.scoped_association WHERE association_id='same'"
expect cephas_test_assoc_3 ASSOCB 1 up3 "SELECT payload FROM ops.scoped_association WHERE association_id='same'"
echo 'T-02.2D.3A scoped associations and paired constraint-denial tests passed'
