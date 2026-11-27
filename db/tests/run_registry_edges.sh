#!/usr/bin/env bash
# T-02.2C.2A: adversarial database lifecycle qualification; disposable service only.
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
for role in cephas_registry_admin cephas_approver cephas_issuer cephas_activator cephas_retirer; do
    passwords[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${passwords[$role]}" | admin >/dev/null
done
login() {
    local role="$1"
    shift
    docker exec -i -e PGPASSWORD="${passwords[$role]}" -e PGAPPNAME="${LIFECYCLE_APP:-t02-edge}" \
        -e PGOPTIONS='-c statement_timeout=30000 -c lock_timeout=25000' \
        "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U "$role" -d "$db" -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
deny() {
    local role="$1" state="$2" query="$3" output
    if output="$(login "$role" -c "$query" 2>&1)"; then
        echo "Unexpected lifecycle success: $role" >&2; exit 1
    fi
    if ! grep -Eq "ERROR:[[:space:]]+$state:" <<< "$output"; then
        printf 'Wrong failure: %s expected %s\n%s\n' "$role" "$state" "$output" >&2
        exit 1
    fi
    printf 'Expected lifecycle denial: %s / %s\n' "$role" "$state"
}
eq() {
    local role="$1" expected="$2" query="$3" actual
    actual="$(login "$role" -Atqc "$query")"
    [[ "$actual" == "$expected" ]] || { printf 'Expected %s, got %s (%s)\n' "$expected" "$actual" "$role" >&2; exit 1; }
}
login cephas_registry_admin -c "INSERT INTO security.business_unit VALUES ('A','edge1'),('A','edge2'),('A','edge3'),('A','edge4'),('A','edge5'),('A','edge6');"
for n in 1 2 3 4 5 6 7; do
    admin -c "CREATE ROLE cephas_test_life_$n NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4; GRANT scoped_runtime TO cephas_test_life_$n WITH INHERIT TRUE; GRANT scoped_runtime TO cephas_test_life_$n WITH SET FALSE; GRANT scoped_runtime TO cephas_test_life_$n WITH ADMIN FALSE;"
done
approval() {
    local n="$1" unit="$2" interval="$3" deployment="${4:-t02-test-deployment}" second="${5:-human2}"
    printf "INSERT INTO security.binding_approval (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id,approver_subject,second_approver_subject,change_ref,approval_evidence_sha256,expires_at) SELECT '20000000-0000-4000-8000-00000000000%s','%s',rolname,oid,'30000000-0000-4000-8000-00000000000%s','A','%s','human1','%s','edge-change-%s',repeat('b',64),statement_timestamp()+interval '%s' FROM pg_catalog.pg_roles WHERE rolname='cephas_test_life_%s';" "$n" "$deployment" "$n" "$unit" "$second" "$n" "$interval" "$n"
}
issuance() {
    local n="$1"
    printf "INSERT INTO security.role_issuance (role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id) SELECT role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id FROM security.binding_approval WHERE role_name='cephas_test_life_%s';" "$n"
}
binding() {
    local n="$1"
    printf "INSERT INTO security.scope_binding (role_name,role_oid,generation,tenant_id,business_unit_id) SELECT role_name,role_oid,generation,tenant_id,business_unit_id FROM security.role_issuance WHERE role_name='cephas_test_life_%s';" "$n"
}
issue() {
    local n="$1"
    login cephas_issuer -c "BEGIN; $(issuance "$n") $(binding "$n") COMMIT;"
}
transition() {
    local n="$1" from="$2" to="$3"
    printf "WITH changed AS (UPDATE security.scope_binding SET state='%s' WHERE role_name='cephas_test_life_%s' AND state='%s' RETURNING 1) SELECT count(*) FROM changed;" "$to" "$n" "$from"
}
# Approval structural checks. RLS WITH CHECK denies a wrong deployment or already-expired record.
deny cephas_approver 42501 "$(approval 1 edge1 '10 minutes' wrong-deployment)"
deny cephas_approver 42501 "$(approval 1 edge1 '-1 second')"
deny cephas_approver 23514 "$(approval 1 edge1 '10 minutes' t02-test-deployment human1)"
login cephas_approver -c "$(approval 1 edge1 '10 minutes')"
deny cephas_approver 23505 "$(approval 1 edge1 '10 minutes')"
# A mismatched scope cannot be issued even with a real unexpired approval.
deny cephas_issuer 42501 "INSERT INTO security.role_issuance (role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id) SELECT role_name,generation,role_oid,approval_id,deployment_id,'A','edge2' FROM security.binding_approval WHERE role_name='cephas_test_life_1';"
# No matching approval: attempt a concrete tuple, not a zero-row INSERT SELECT.
deny cephas_issuer 42501 "INSERT INTO security.role_issuance (role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id) SELECT rolname,'30000000-0000-4000-8000-000000000007',oid,'20000000-0000-4000-8000-000000000007','t02-test-deployment','A','edge6' FROM pg_catalog.pg_roles WHERE rolname='cephas_test_life_7';"
issue 1
deny cephas_issuer 23505 "$(issuance 1)"
login cephas_approver -c "$(approval 2 edge1 '10 minutes')"
# Second live binding to the same scope must roll back the complete issuance transaction.
deny cephas_issuer 23505 "BEGIN; $(issuance 2) $(binding 2) COMMIT;"
eq cephas_issuer 0 "SELECT count(*) FROM security.role_issuance WHERE role_name='cephas_test_life_2';"
eq cephas_issuer 0 "SELECT count(*) FROM security.scope_binding WHERE role_name='cephas_test_life_2';"
# Two short-lived approvals: one already issued, one not issued.
login cephas_approver -c "$(approval 3 edge2 '12 seconds') $(approval 4 edge3 '12 seconds')"
issue 3
admin -c "ALTER ROLE cephas_test_life_3 LOGIN;"
# Poll the authoritative server clock; avoid relying on runner time.
expired=false
for _ in $(seq 1 100); do
    if [[ "$(login cephas_issuer -Atqc "SELECT count(*) FROM security.binding_approval WHERE role_name IN ('cephas_test_life_3','cephas_test_life_4') AND expires_at<=clock_timestamp();")" == 2 ]]; then
        expired=true; break
    fi
    sleep 0.2
done
[[ "$expired" == true ]] || { echo 'Expiry observation timed out' >&2; exit 1; }
deny cephas_issuer 42501 "$(issuance 4)"
deny cephas_activator 42501 "$(transition 3 pending active)"
eq cephas_issuer pending "SELECT state FROM security.scope_binding WHERE role_name='cephas_test_life_3';"
eq cephas_retirer 1 "$(transition 3 pending retired)"
eq cephas_activator 0 "$(transition 3 pending active)"
admin -c "ALTER ROLE cephas_test_life_3 NOLOGIN;"
# Two concurrent row-transition cases, with server-observed lock contention.
login cephas_approver -c "$(approval 5 edge4 '10 minutes') $(approval 6 edge5 '10 minutes')"
issue 5
issue 6
admin -c "ALTER ROLE cephas_test_life_5 LOGIN; ALTER ROLE cephas_test_life_6 LOGIN;"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
wait_event() {
    local app="$1" predicate="$2"
    for _ in $(seq 1 60); do
        if [[ "$(admin -Atqc "SELECT count(*) FROM pg_stat_activity WHERE application_name='$app' AND ($predicate);")" == 1 ]]; then
            return 0
        fi
        sleep 0.1
    done
    echo "Expected server wait not observed: $app" >&2; return 1
}
race() {
    local n="$1" first_role="$2" first_to="$3" second_role="$4" second_to="$5"
    local first_app="t02-edge-first-$n" second_app="t02-edge-second-$n"
    # First transaction updates and holds the row lock. Second uses exact expected old state.
    LIFECYCLE_APP="$first_app" login "$first_role" -Atqc "BEGIN; $(transition "$n" pending "$first_to") SELECT pg_sleep(15); COMMIT;" >"$tmp/first-$n" 2>&1 &
    local first_pid=$!
    wait_event "$first_app" "wait_event='PgSleep'"
    LIFECYCLE_APP="$second_app" login "$second_role" -Atqc "$(transition "$n" pending "$second_to")" >"$tmp/second-$n" 2>&1 &
    local second_pid=$!
    wait_event "$second_app" "wait_event_type='Lock'"
    wait "$first_pid" || { cat "$tmp/first-$n" >&2; return 1; }
    wait "$second_pid" || { cat "$tmp/second-$n" >&2; return 1; }
    grep -qx '1' "$tmp/first-$n"
    [[ "$(cat "$tmp/second-$n")" == 0 ]]
    eq cephas_issuer "$first_to" "SELECT state FROM security.scope_binding WHERE role_name='cephas_test_life_$n';"
    printf 'Observed concurrent lock and stale-state rejection: %s then %s\n' "$first_to" "$second_to"
}
race 5 cephas_retirer retired cephas_activator active
eq cephas_activator 0 "$(transition 5 pending active)"
race 6 cephas_activator active cephas_retirer retired
# Retirement must re-read committed state and explicitly compare the new expected state.
eq cephas_retirer 1 "$(transition 6 active retired)"
eq cephas_activator 0 "$(transition 6 pending active)"
admin -c 'ALTER ROLE cephas_test_life_5 NOLOGIN; ALTER ROLE cephas_test_life_6 NOLOGIN;'
echo 'T-02.2C.2A registry expiry, issuance rollback and row-transition contention checks passed'
