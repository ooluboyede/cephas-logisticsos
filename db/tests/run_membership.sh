#!/usr/bin/env bash
set -euo pipefail
: "${PG16_CONTAINER_ID:?Required disposable postgres service container}"
[[ "$PG16_CONTAINER_ID" =~ ^[a-f0-9]{12,64}$ ]]
[[ "$(docker inspect --format '{{.Config.Image}}' "$PG16_CONTAINER_ID")" == postgres:16 ]]
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
admin() {
    docker exec -i "$PG16_CONTAINER_ID" psql -X -w -U postgres -d cephas_t02_test -v ON_ERROR_STOP=1 "$@"
}
sha256sum db/migrations/0005_membership.sql
admin < db/migrations/0005_membership.sql
declare -A pw
for role in cephas_migration cephas_membership cephas_test_assoc_1; do
    pw[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${pw[$role]}" | admin >/dev/null
done
login() {
    local role="$1"; shift
    docker exec -i -e PGPASSWORD="${pw[$role]}" "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U "$role" -d cephas_t02_test -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
writer() {
    login cephas_migration -Atqc "BEGIN; SET LOCAL ROLE cephas_owner; $1; COMMIT;"
}
lookup() {
    login cephas_membership -Atqc "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY; $1; COMMIT;"
}
deny() {
    local role="$1" state="$2" query="$3" output
    if output="$(login "$role" -Atqc "$query" 2>&1)"; then
        echo "Unexpected membership success: $role" >&2; exit 1
    fi
    if ! grep -Eq "ERROR:[[:space:]]+$state:" <<< "$output"; then
        printf 'Wrong membership denial: %s / %s\n%s\n' "$role" "$state" "$output" >&2; exit 1
    fi
}
[[ "$(lookup 'SELECT pg_is_in_recovery()')" == f ]]
[[ "$(lookup 'SHOW transaction_isolation')" == 'read committed' ]]
[[ "$(lookup 'SHOW transaction_read_only')" == on ]]
gen1=11000000-0000-4000-8000-000000000001
gen2=11000000-0000-4000-8000-000000000002
writer "INSERT INTO membership.subject_scope (subject_id,tenant_id,business_unit_id,generation,change_ref) VALUES ('member1','ASSOCA','1','$gen1','m-create-1'),('member1','ASSOCB','1','$gen2','m-create-2')"
[[ "$(lookup "SELECT revision||':'||active::text FROM membership.subject_scope WHERE subject_id='member1' AND tenant_id='ASSOCA' AND business_unit_id='1'")" == '1:true' ]]
[[ "$(writer "SELECT count(*) FROM membership.change_audit WHERE actor='cephas_migration' AND revision=1")" == 2 ]]
deny cephas_membership 42501 "UPDATE membership.subject_scope SET active=false"
deny cephas_membership 42501 "SELECT change_ref FROM membership.subject_scope"
deny cephas_membership 42501 "SELECT count(*) FROM membership.change_audit"
deny cephas_membership 42501 "SET ROLE cephas_owner"
deny cephas_test_assoc_1 42501 "SELECT count(*) FROM membership.subject_scope"
deny cephas_migration 42501 "UPDATE membership.subject_scope SET active=false"
deny cephas_migration 42501 "SET ROLE cephas_owner; UPDATE membership.subject_scope SET revision=99 WHERE generation='$gen1'"
deny cephas_migration 42501 "SET ROLE cephas_owner; UPDATE membership.subject_scope SET generation='$gen2' WHERE generation='$gen1'"
deny cephas_migration 42501 "SET ROLE cephas_owner; UPDATE membership.subject_scope SET tenant_id='ASSOCB' WHERE generation='$gen1'"
deny cephas_migration 23505 "SET ROLE cephas_owner; INSERT INTO membership.subject_scope (subject_id,tenant_id,business_unit_id,generation,change_ref) VALUES ('member2','ASSOCA','1','$gen1','m-reuse')"
deny cephas_migration 23505 "SET ROLE cephas_owner; UPDATE membership.subject_scope SET change_ref='m-create-2' WHERE generation='$gen1'"
deny cephas_migration 42501 "SET ROLE cephas_owner; UPDATE membership.subject_scope SET changed_at=statement_timestamp() WHERE generation='$gen1'"
deny cephas_migration 42501 "SET ROLE cephas_owner; INSERT INTO membership.subject_scope (subject_id,tenant_id,business_unit_id,generation,revision,change_ref) VALUES ('member2','ASSOCA','1','11000000-0000-4000-8000-000000000003',2,'m-invalid-revision')"
deny cephas_migration 23502 "SET ROLE cephas_owner; INSERT INTO membership.subject_scope (subject_id,tenant_id,business_unit_id,generation,change_ref) VALUES ('member2','ASSOCA','1',NULL,'m-null-generation')"
[[ "$(lookup "SELECT revision FROM membership.subject_scope WHERE generation='$gen1'")" == 1 ]]
# Explicit rollback proves no audit or state change can survive separately.
login cephas_migration -Atqc "BEGIN; SET LOCAL ROLE cephas_owner; UPDATE membership.subject_scope SET change_ref='m-rollback' WHERE generation='$gen1'; ROLLBACK;"
[[ "$(lookup "SELECT revision FROM membership.subject_scope WHERE generation='$gen1'")" == 1 ]]
[[ "$(writer "SELECT count(*) FROM membership.change_audit WHERE change_ref='m-rollback'")" == 0 ]]
# Two actual concurrent CAS attempts; observe lock contention before first commit.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
login cephas_migration -Atqc "BEGIN; SET LOCAL ROLE cephas_owner; SET LOCAL application_name='member-cas-first'; WITH c AS (UPDATE membership.subject_scope SET change_ref='m-cas-first' WHERE generation='$gen1' AND revision=1 RETURNING 1) SELECT count(*) FROM c; SELECT pg_sleep(12); COMMIT;" >"$tmp/first" 2>&1 &
first=$!
seen=false
for _ in $(seq 1 80); do
    if [[ "$(admin -Atqc "SELECT count(*) FROM pg_stat_activity WHERE application_name='member-cas-first' AND wait_event='PgSleep'")" == 1 ]]; then seen=true; break; fi
    sleep 0.1
done
[[ "$seen" == true ]]
# A separate primary READ COMMITTED lookup must not see uncommitted changes.
[[ "$(lookup "SELECT revision FROM membership.subject_scope WHERE generation='$gen1'")" == 1 ]]
login cephas_migration -Atqc "BEGIN; SET LOCAL ROLE cephas_owner; SET LOCAL application_name='member-cas-second'; SET LOCAL statement_timeout='20s'; WITH c AS (UPDATE membership.subject_scope SET change_ref='m-cas-second' WHERE generation='$gen1' AND revision=1 RETURNING 1) SELECT count(*) FROM c; COMMIT;" >"$tmp/second" 2>&1 &
second=$!
seen=false
for _ in $(seq 1 40); do
    if [[ "$(admin -Atqc "SELECT count(*) FROM pg_stat_activity WHERE application_name='member-cas-second' AND wait_event_type='Lock'")" == 1 ]]; then seen=true; break; fi
    sleep 0.1
done
[[ "$seen" == true ]]
wait "$first"
wait "$second"
[[ "$(head -n1 "$tmp/first")" == 1 ]]
[[ "$(cat "$tmp/second")" == 0 ]]
[[ "$(lookup "SELECT revision FROM membership.subject_scope WHERE generation='$gen1'")" == 2 ]]
[[ "$(writer "SELECT count(*) FROM membership.change_audit WHERE generation='$gen1'")" == 2 ]]
writer "UPDATE membership.subject_scope SET active=false,change_ref='m-revoke' WHERE generation='$gen1' AND revision=2"
[[ "$(lookup "SELECT revision||':'||active::text FROM membership.subject_scope WHERE generation='$gen1'")" == '3:false' ]]
deny cephas_migration 42501 "SET ROLE cephas_owner; UPDATE membership.subject_scope SET active=true,change_ref='m-reactivate' WHERE generation='$gen1'"
# Owner has no DELETE policy, so row-level DELETE can affect zero rows rather than error.
[[ "$(writer "WITH c AS (DELETE FROM membership.subject_scope WHERE generation='$gen1' RETURNING 1) SELECT count(*) FROM c")" == 0 ]]
[[ "$(writer "WITH c AS (DELETE FROM membership.change_audit WHERE generation='$gen1' RETURNING 1) SELECT count(*) FROM c")" == 0 ]]
deny cephas_migration 42501 "SET ROLE cephas_owner; TRUNCATE membership.change_audit,membership.subject_scope"
[[ "$(writer "WITH c AS (UPDATE membership.change_audit SET active=true WHERE generation='$gen1' RETURNING 1) SELECT count(*) FROM c")" == 0 ]]
[[ "$(writer "SELECT count(*) FROM membership.change_audit WHERE generation='$gen1'")" == 3 ]]
deny cephas_migration 23505 "SET ROLE cephas_owner; INSERT INTO membership.subject_scope (subject_id,tenant_id,business_unit_id,generation,change_ref) VALUES ('member1','ASSOCA','1','11000000-0000-4000-8000-000000000004','m-reenrol')"
[[ "$(lookup "SELECT revision||':'||active::text FROM membership.subject_scope WHERE generation='$gen2'")" == '1:true' ]]
echo 'T-02.2E.1A membership generation, revision, concurrent CAS and atomic audit tests passed'
