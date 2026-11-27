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
    admin < db/tests/0002_registry_manifest.sql
    admin < db/tests/0004_entity_manifest.sql
    admin < db/tests/0004_association_manifest.sql
    admin < db/tests/0004_registry_expressions.sql
}
drift() {
    local mutation="$1" restore="$2" reason="$3" output
    admin -c "$mutation"
    if output="$(verify 2>&1)"; then
        echo "Expanded manifest unexpectedly accepted drift: $reason" >&2; exit 1
    fi
    if ! grep -Fq "$reason" <<< "$output"; then
        printf 'Unexpected expanded manifest failure: %s\n%s\n' "$reason" "$output" >&2; exit 1
    fi
    admin -c "$restore"
    verify
    printf 'Expanded manifest detected drift: %s\n' "$reason"
}
sha256sum db/tests/0004_*manifest.sql db/tests/0004_registry_expressions.sql
verify
drift 'ALTER TABLE ops.scoped_association NO FORCE ROW LEVEL SECURITY' 'ALTER TABLE ops.scoped_association FORCE ROW LEVEL SECURITY' 'manifest: relation ownership, kind or RLS'
drift 'GRANT UPDATE (target_entity_id) ON ops.scoped_association TO scoped_runtime' 'REVOKE UPDATE (target_entity_id) ON ops.scoped_association FROM scoped_runtime' 'manifest: column ACL'
drift 'DROP INDEX ops.scoped_association_target_idx' 'CREATE INDEX scoped_association_target_idx ON ops.scoped_association (tenant_id,business_unit_id,target_entity_id)' 'manifest: unexpected operational objects'
drift 'ALTER TABLE security.scope_binding ADD CONSTRAINT unexpected_check CHECK (true)' 'ALTER TABLE security.scope_binding DROP CONSTRAINT unexpected_check' 'expanded manifest: registry CHECK expressions'
drift "DROP INDEX security.scope_binding_live_oid; CREATE UNIQUE INDEX scope_binding_live_oid ON security.scope_binding (role_oid) WHERE state='active'" "DROP INDEX security.scope_binding_live_oid; CREATE UNIQUE INDEX scope_binding_live_oid ON security.scope_binding (role_oid) WHERE state IN ('pending','active')" 'expanded manifest: partial-index predicate'
PYTHONPATH=src python3 db/tests/identifier_parity.py
echo 'T-02.2D.3B expanded final schema and identifier equivalence checks passed'
