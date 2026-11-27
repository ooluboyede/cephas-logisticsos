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
    admin < db/tests/0003_catalog_manifest.sql
}
drift() {
    local mutation="$1" restore="$2" reason="$3" output
    admin -c "$mutation"
    if output="$(verify 2>&1)"; then
        echo "Catalog drift unexpectedly accepted: $reason" >&2; exit 1
    fi
    if ! grep -Fq "manifest: $reason" <<< "$output"; then
        printf 'Unexpected manifest failure: %s\n%s\n' "$reason" "$output" >&2; exit 1
    fi
    admin -c "$restore"
    verify
    printf 'Manifest detected drift: %s\n' "$reason"
}
sha256sum db/tests/0003_catalog_manifest.sql
verify
drift 'ALTER TABLE ops.scoped_entity NO FORCE ROW LEVEL SECURITY' 'ALTER TABLE ops.scoped_entity FORCE ROW LEVEL SECURITY' 'relation ownership, kind or RLS'
drift 'CREATE VIEW ops.unexpected AS SELECT 1' 'DROP VIEW ops.unexpected' 'unexpected operational objects'
drift 'GRANT UPDATE ON ops.scoped_entity TO scoped_runtime' 'REVOKE UPDATE ON ops.scoped_entity FROM scoped_runtime; GRANT UPDATE (payload) ON ops.scoped_entity TO scoped_runtime' 'table ACL'
drift 'GRANT CREATE ON SCHEMA ops TO scoped_runtime' 'REVOKE CREATE ON SCHEMA ops FROM scoped_runtime' 'schema ACL'
drift 'GRANT pg_read_all_data TO scoped_runtime WITH INHERIT FALSE' 'REVOKE pg_read_all_data FROM scoped_runtime' 'runtime group'
drift 'CREATE POLICY unexpected ON ops.scoped_entity FOR SELECT TO scoped_runtime USING (true)' 'DROP POLICY unexpected ON ops.scoped_entity' 'policy inventory or metadata'
# Change expression inside a disposable transaction; verifier must reject even when
# policy name, count, command and role remain unchanged. Restore by replaying original
# policy expression from the trusted migration, not by trusting the mutated catalog.
policy_sql="$(sed -n '/^CREATE POLICY scoped_entity_select /,/^CREATE POLICY scoped_entity_insert /p' db/migrations/0003_operational_rls.sql | sed '$d')"
[[ "$policy_sql" == 'CREATE POLICY scoped_entity_select '* ]]
drift 'ALTER POLICY scoped_entity_select ON ops.scoped_entity USING (true)' "DROP POLICY scoped_entity_select ON ops.scoped_entity; $policy_sql" 'normalized policy expression'
echo 'T-02.2D.2A exact operational catalog and drift checks passed'
