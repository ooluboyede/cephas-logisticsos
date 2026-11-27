#!/usr/bin/env bash
set -euo pipefail
: "${PG16_CONTAINER_ID:?Required disposable postgres service container}"
[[ "$PG16_CONTAINER_ID" =~ ^[a-f0-9]{12,64}$ ]]
[[ "$(docker inspect --format '{{.Config.Image}}' "$PG16_CONTAINER_ID")" == postgres:16 ]]
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
admin() {
    docker exec -i "$PG16_CONTAINER_ID" psql -X -w -U postgres -d cephas_t02_test -v ON_ERROR_STOP=1 "$@"
}
sha256sum db/migrations/0006_membership_admin.sql db/tests/0006_membership_admin_catalog.sql
admin < db/migrations/0006_membership_admin.sql
admin < db/tests/0006_membership_admin_catalog.sql
declare -A pw
for role in cephas_membership_admin cephas_membership cephas_migration cephas_test_assoc_1; do
    pw[$role]="$(openssl rand -hex 32)"
    printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "${pw[$role]}" | admin >/dev/null
done
login() {
    local role="$1"; shift
    docker exec -i -e PGPASSWORD="${pw[$role]}" "$PG16_CONTAINER_ID" psql -X -w -h 127.0.0.1 -U "$role" -d cephas_t02_test -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
change() {
    login cephas_membership_admin -Atqc "$1"
}
lookup() {
    login cephas_membership -Atqc "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY; $1; COMMIT;"
}
deny() {
    local role="$1" state="$2" query="$3" output
    if output="$(login "$role" -Atqc "$query" 2>&1)"; then
        echo "Unexpected membership admin success: $role" >&2; exit 1
    fi
    if ! grep -Eq "ERROR:[[:space:]]+$state:" <<< "$output"; then
        printf 'Wrong membership admin denial: %s / %s\n%s\n' "$role" "$state" "$output" >&2; exit 1
    fi
}
old=11000000-0000-4000-8000-000000000001
new=12000000-0000-4000-8000-000000000001
next=12000000-0000-4000-8000-000000000002
root=12000000-0000-4000-8000-000000000003
[[ "$(change 'SELECT session_user')" == cephas_membership_admin ]]
deny cephas_membership_admin 42501 'SELECT count(*) FROM membership.subject_scope'
deny cephas_membership_admin 42501 'UPDATE membership.subject_scope SET active=false'
deny cephas_membership_admin 42501 'SELECT count(*) FROM membership.change_audit'
deny cephas_membership_admin 42501 'INSERT INTO membership.change_audit (revision) VALUES (1)'
deny cephas_membership_admin 42501 'SET ROLE cephas_membership_executor'
deny cephas_membership_admin 42501 'SET ROLE cephas_owner'
deny cephas_membership_admin 42501 'CREATE TEMP TABLE forbidden (id int)'
deny cephas_membership_admin 42501 'SELECT count(*) FROM ops.scoped_entity'
for role in cephas_membership cephas_migration cephas_test_assoc_1; do
    deny "$role" 42501 "SELECT membership.change_state('$old',3,true,'forged')"
done
deny cephas_membership_admin 42501 "SELECT membership.enrol('member1','ASSOCA','1','$new','$old',2,'wrong-revision')"
deny cephas_membership_admin 42501 "SELECT membership.enrol('member1','ASSOCB','1','$new','$old',3,'wrong-scope')"
deny cephas_membership_admin 23505 "SELECT membership.enrol('member1','ASSOCA','1','$new',NULL,NULL,'root-reuse')"
[[ "$(change "SELECT membership.enrol('member1','ASSOCA','1','$new','$old',3,'admin-reenrol')")" == 1 ]]
[[ "$(lookup "SELECT generation FROM membership.subject_scope WHERE subject_id='member1' AND tenant_id='ASSOCA' AND business_unit_id='1' AND active")" == "$new" ]]
[[ "$(lookup "SELECT revision||':'||active::text FROM membership.subject_scope WHERE generation='$old'")" == '3:false' ]]
deny cephas_membership_admin 42501 "SELECT membership.enrol('member1','ASSOCA','1','$next','$new',1,'active-predecessor')"
deny cephas_membership_admin 23505 "SELECT membership.enrol('member-other','ASSOCA','1','$new',NULL,NULL,'duplicate-generation')"
deny cephas_membership_admin 42501 "SELECT membership.enrol('member1','ASSOCA','1','$next','$old',3,'predecessor-reuse')"
deny cephas_membership_admin 42501 "SELECT membership.change_state('$old',3,true,'old-reactivation')"
[[ "$(change "SELECT membership.change_state('$new',1,true,'admin-refresh')")" == 2 ]]
deny cephas_membership_admin 42501 "SELECT membership.change_state('$new',1,false,'stale-revoke')"
deny cephas_membership_admin 23505 "SELECT membership.change_state('$new',2,false,'admin-refresh')"
[[ "$(lookup "SELECT revision||':'||active::text FROM membership.subject_scope WHERE generation='$new'")" == '2:true' ]]
change "BEGIN; SELECT membership.change_state('$new',2,false,'admin-rollback'); ROLLBACK;"
[[ "$(lookup "SELECT revision||':'||active::text FROM membership.subject_scope WHERE generation='$new'")" == '2:true' ]]
[[ "$(admin -Atqc "SELECT count(*) FROM membership.change_audit WHERE change_ref='admin-rollback'")" == 0 ]]
[[ "$(change "SELECT membership.change_state('$new',2,false,'admin-revoke')")" == 3 ]]
[[ "$(change "SELECT membership.enrol('member1','ASSOCA','1','$next','$new',3,'admin-reenrol-again')")" == 1 ]]
deny cephas_membership_admin 42501 "SELECT membership.enrol('member1','ASSOCA','1','$root','$old',3,'stale-chain')"
[[ "$(change "SELECT membership.enrol('member-overflow','ASSOCA','2','$root',NULL,NULL,'admin-root')")" == 1 ]]
[[ "$(admin -Atqc "SELECT count(*) FROM membership.change_audit WHERE actor='cephas_membership_admin'")" == 5 ]]
# Migration can still inspect, but ordinary DML through owner has no write policy.
deny cephas_migration 42501 "SET ROLE cephas_owner; INSERT INTO membership.change_audit (generation,revision,subject_id,tenant_id,business_unit_id,active,change_ref,actor,changed_at) VALUES ('$new',9,'member1','ASSOCA','1',true,'forge','cephas_membership_admin',statement_timestamp())"
# Synthetic maximum-revision fixture: privileged setup and all changes roll back.
# This tests the numerical boundary, not a fabricated continuous audit history.
admin <<'SQL'
BEGIN;
ALTER TABLE membership.subject_scope DISABLE TRIGGER member_transition;
ALTER TABLE membership.subject_scope DISABLE TRIGGER member_audit;
UPDATE membership.subject_scope SET revision=9223372036854775806
WHERE generation='12000000-0000-4000-8000-000000000003';
ALTER TABLE membership.subject_scope ENABLE TRIGGER member_transition;
ALTER TABLE membership.subject_scope ENABLE TRIGGER member_audit;
SET LOCAL SESSION AUTHORIZATION cephas_membership_admin;
DO $boundary$
BEGIN
    BEGIN
        PERFORM membership.change_state('12000000-0000-4000-8000-000000000003',
            9223372036854775806,true,'overflow-refresh');
        RAISE EXCEPTION 'reserved revision unexpectedly used';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    IF membership.change_state('12000000-0000-4000-8000-000000000003',
        9223372036854775806,false,'overflow-revoke')<>9223372036854775807
    THEN RAISE EXCEPTION 'terminal revision mismatch'; END IF;
    BEGIN
        PERFORM membership.change_state('12000000-0000-4000-8000-000000000003',
            9223372036854775807,false,'overflow-wrap');
        RAISE EXCEPTION 'terminal revision unexpectedly reused';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
END
$boundary$;
RESET SESSION AUTHORIZATION;
DO $check$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM membership.subject_scope
        WHERE generation='12000000-0000-4000-8000-000000000003'
        AND revision=9223372036854775807 AND NOT active)
    THEN RAISE EXCEPTION 'terminal boundary not recorded'; END IF;
END
$check$;
ROLLBACK;
SQL
[[ "$(lookup "SELECT revision||':'||active::text FROM membership.subject_scope WHERE generation='$root'")" == '1:true' ]]
admin < db/tests/0006_membership_admin_catalog.sql
echo 'T-02.2E.1B protected membership administration and revision boundary tests passed'
