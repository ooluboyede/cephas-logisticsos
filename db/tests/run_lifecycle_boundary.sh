#!/usr/bin/env bash
# T-02.2C.2B.2A — real PG16 admission/termination probes. No live infrastructure adapter.
set -euo pipefail
: "${PG16_CONTAINER_ID:?Required disposable postgres service container}"
[[ "$PG16_CONTAINER_ID" =~ ^[a-f0-9]{12,64}$ ]]
[[ "$(docker inspect --format '{{.Config.Image}}' "$PG16_CONTAINER_ID")" == postgres:16 ]]
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
db=cephas_t02_test
admin() {
    docker exec -i "$PG16_CONTAINER_ID" psql -X -w -U postgres -d "$db" -v ON_ERROR_STOP=1 "$@"
}
[[ "$(admin -Atqc "SELECT current_database()='cephas_t02_test' AND current_setting('server_version_num')::integer BETWEEN 160000 AND 169999 AND NOT pg_is_in_recovery() AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)")" == t ]]
declare -A passwords oids
for role in cephas_registry_admin cephas_approver cephas_issuer cephas_activator cephas_retirer; do
    passwords[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${passwords[$role]}" | admin >/dev/null
done
login() {
    local role="$1"
    shift
    docker exec -i -e PGPASSWORD="${passwords[$role]}" -e PGAPPNAME="${LIFECYCLE_APP:-t02-boundary}" \
        -e PGOPTIONS='-c statement_timeout=60000 -c lock_timeout=10000' \
        "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U "$role" -d "$db" \
        -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
eq() {
    local role="$1" expected="$2" query="$3"
    [[ "$(login "$role" -Atqc "$query")" == "$expected" ]] || {
        echo "Unexpected database result for $role" >&2; exit 1;
    }
}
login cephas_registry_admin -c "INSERT INTO security.business_unit VALUES ('A','admit1'),('A','admit2');"
for n in 1 2; do
    role="cephas_test_admit_$n"
    admin -c "CREATE ROLE $role NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4; GRANT scoped_runtime TO $role WITH INHERIT TRUE; GRANT scoped_runtime TO $role WITH SET FALSE; GRANT scoped_runtime TO $role WITH ADMIN FALSE;"
    passwords[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${passwords[$role]}" | admin >/dev/null
    oids[$n]="$(admin -Atqc "SELECT oid FROM pg_roles WHERE rolname='$role'")"
    [[ "${oids[$n]}" =~ ^[0-9]+$ ]]
done
approval() {
    local n="$1" duration="$2"
    login cephas_approver -c "INSERT INTO security.binding_approval (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id,approver_subject,second_approver_subject,change_ref,approval_evidence_sha256,expires_at) SELECT '40000000-0000-4000-8000-00000000000$n','t02-test-deployment',rolname,oid,'50000000-0000-4000-8000-00000000000$n','A','admit$n','human1','human2','admit-change-$n',repeat('c',64),statement_timestamp()+interval '$duration' FROM pg_roles WHERE rolname='cephas_test_admit_$n';"
}
issue() {
    local n="$1" role="cephas_test_admit_$1"
    login cephas_issuer -c "BEGIN; INSERT INTO security.role_issuance (role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id) SELECT role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id FROM security.binding_approval WHERE role_name='$role'; INSERT INTO security.scope_binding (role_name,role_oid,generation,tenant_id,business_unit_id) SELECT role_name,role_oid,generation,tenant_id,business_unit_id FROM security.role_issuance WHERE role_name='$role'; COMMIT;"
}
probe() {
    local n="$1" expected="$2" oid="${3:-${oids[$1]}}" unit="${4:-admit$1}" actual
    actual="$(admin -Atq -v deployment=t02-test-deployment -v role_name="cephas_test_admit_$n" \
        -v role_oid="$oid" -v generation="50000000-0000-4000-8000-00000000000$n" \
        -v tenant=A -v unit="$unit" -v approval_id="40000000-0000-4000-8000-00000000000$n" \
        -v evidence_sha256="$(printf '%064d' 0 | tr 0 c)" < db/tests/first_admission_probe.sql)"
    [[ "$actual" == "$expected" ]] || { echo "First admission probe expected $expected got $actual" >&2; exit 1; }
}
# Positive and negative exact-tuple cases.
approval 1 '10 minutes'
issue 1
admin -c 'ALTER ROLE cephas_test_admit_1 LOGIN;'
probe 1 f
eq cephas_activator 1 "WITH changed AS (UPDATE security.scope_binding SET state='active' WHERE role_name='cephas_test_admit_1' AND state='pending' RETURNING 1) SELECT count(*) FROM changed;"
probe 1 t
probe 1 f 0
probe 1 f "${oids[1]}" admit2
# Extra direct membership, wrong membership options and transitive membership fail closed.
admin -c 'GRANT pg_read_all_data TO cephas_test_admit_1 WITH INHERIT FALSE;'
probe 1 f
admin -c 'REVOKE pg_read_all_data FROM cephas_test_admit_1; GRANT scoped_runtime TO cephas_test_admit_1 WITH SET TRUE;'
probe 1 f
admin -c 'GRANT scoped_runtime TO cephas_test_admit_1 WITH SET FALSE; GRANT pg_read_all_data TO scoped_runtime WITH INHERIT FALSE;'
probe 1 f
admin -c 'REVOKE pg_read_all_data FROM scoped_runtime;'
probe 1 t
echo 'Verified committed first-admission tuple and role graph drift denial'
# A valid activation statement may commit after expiry. The post-commit probe must deny.
approval 2 '20 seconds'
issue 2
admin -c 'ALTER ROLE cephas_test_admit_2 LOGIN;'
login cephas_activator -c "BEGIN; UPDATE security.scope_binding SET state='active' WHERE role_name='cephas_test_admit_2' AND state='pending'; SELECT pg_sleep(GREATEST(0,extract(epoch FROM (expires_at-clock_timestamp()))+0.2)::double precision) FROM security.binding_approval WHERE role_name='cephas_test_admit_2'; COMMIT;"
eq cephas_issuer active "SELECT state FROM security.scope_binding WHERE role_name='cephas_test_admit_2';"
eq cephas_issuer t "SELECT expires_at<=clock_timestamp() FROM security.binding_approval WHERE role_name='cephas_test_admit_2';"
probe 2 f
echo 'Verified post-commit expiry denies first admission despite active binding'
admin -c 'ALTER ROLE cephas_test_admit_2 NOLOGIN;'
eq cephas_retirer 1 "WITH changed AS (UPDATE security.scope_binding SET state='retired' WHERE role_name='cephas_test_admit_2' AND state='active' RETURNING 1) SELECT count(*) FROM changed;"
# Establish one actual live scoped session and verify positive termination wait plus zero sessions.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
LIFECYCLE_APP=t02-termination-victim login cephas_test_admit_1 -Atqc 'SELECT pg_sleep(50);' >"$tmp/victim" 2>&1 &
victim=$!
found=false
for _ in $(seq 1 80); do
    if [[ "$(admin -Atqc "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usesysid=${oids[1]}::oid AND usename='cephas_test_admit_1' AND application_name='t02-termination-victim' AND wait_event='PgSleep';")" == 1 ]]; then
        found=true; break
    fi
    sleep 0.1
done
[[ "$found" == true ]] || { echo 'Live backend not observed' >&2; exit 1; }
# NOLOGIN is a database reconnect fence, not proof of network/vault fencing.
admin -c 'ALTER ROLE cephas_test_admit_1 NOLOGIN;'
eq cephas_retirer 1 "WITH changed AS (UPDATE security.scope_binding SET state='retired' WHERE role_name='cephas_test_admit_1' AND state='active' RETURNING 1) SELECT count(*) FROM changed;"
[[ "$(admin -Atqc "SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity WHERE datname=current_database() AND usesysid=${oids[1]}::oid AND usename='cephas_test_admit_1' AND application_name='t02-termination-victim';")" == t ]]
if wait "$victim"; then
    echo 'Terminated backend unexpectedly completed' >&2; exit 1
fi
grep -Eq 'terminating connection due to administrator command|57P01' "$tmp/victim"
[[ "$(admin -Atqc "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usesysid=${oids[1]}::oid;")" == 0 ]]
if output="$(login cephas_test_admit_1 -Atqc 'SELECT session_user' 2>&1)"; then
    echo 'Retired role unexpectedly reconnected' >&2; exit 1
fi
grep -Eq 'not permitted to log in|28000' <<< "$output"
probe 1 f
echo 'Verified positive termination wait, zero matching sessions and denied database reconnect'
echo 'T-02.2C.2B.2A PostgreSQL boundary qualification passed (network/vault fencing not qualified)'
