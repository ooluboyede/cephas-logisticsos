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
}
drift() {
    local mutation="$1" restore="$2" reason="$3" output
    admin -c "$mutation"
    if output="$(verify 2>&1)"; then
        echo "Registry drift unexpectedly accepted: $reason" >&2; exit 1
    fi
    if ! grep -Fq "registry manifest: $reason" <<< "$output"; then
        printf 'Unexpected registry manifest failure: %s\n%s\n' "$reason" "$output" >&2; exit 1
    fi
    admin -c "$restore"
    verify
    printf 'Registry manifest detected drift: %s\n' "$reason"
}
sha256sum db/tests/0002_registry_manifest.sql
verify
drift 'ALTER TABLE security.scope_binding NO FORCE ROW LEVEL SECURITY' 'ALTER TABLE security.scope_binding FORCE ROW LEVEL SECURITY' 'relation inventory or RLS'
drift 'SET ROLE cephas_owner; GRANT SELECT ON security.role_issuance TO scoped_runtime; RESET ROLE;' 'SET ROLE cephas_owner; REVOKE SELECT ON security.role_issuance FROM scoped_runtime; RESET ROLE;' 'table ACL'
drift 'SET ROLE cephas_owner; GRANT UPDATE (tenant_id) ON security.scope_binding TO cephas_activator; RESET ROLE;' 'SET ROLE cephas_owner; REVOKE UPDATE (tenant_id) ON security.scope_binding FROM cephas_activator; RESET ROLE;' 'column ACL'
drift 'ALTER TABLE security.scope_binding DISABLE TRIGGER binding_transition' 'ALTER TABLE security.scope_binding ENABLE TRIGGER binding_transition' 'trigger configuration'
drift 'SET ROLE cephas_owner; GRANT EXECUTE ON FUNCTION security.guard_binding_update() TO scoped_runtime; RESET ROLE;' 'SET ROLE cephas_owner; REVOKE EXECUTE ON FUNCTION security.guard_binding_update() FROM scoped_runtime; RESET ROLE;' 'routine security'
drift 'CREATE POLICY unauthorized ON security.scope_binding FOR SELECT TO scoped_runtime USING (true)' 'DROP POLICY unauthorized ON security.scope_binding' 'policy inventory'
policy_sql="$(grep '^CREATE POLICY binding_runtime_invariant ' db/migrations/0002_registry.sql)"
[[ "$policy_sql" == 'CREATE POLICY binding_runtime_invariant '* ]]
drift 'ALTER POLICY binding_runtime_invariant ON security.scope_binding USING (true)' "DROP POLICY binding_runtime_invariant ON security.scope_binding; $policy_sql" 'policy expression or metadata'
drift "ALTER TABLE security.scope_binding ALTER COLUMN state SET DEFAULT 'active'" "ALTER TABLE security.scope_binding ALTER COLUMN state SET DEFAULT 'pending'" 'defaults'
drift 'DROP INDEX security.scope_binding_live_oid' "CREATE UNIQUE INDEX scope_binding_live_oid ON security.scope_binding (role_oid) WHERE state IN ('pending','active')" 'indexes'
echo 'T-02.2D.2B registry policy, trigger and ACL manifest checks passed'
