-- Executed as bootstrap administrator; verifies the deliberately narrow B foundation.
DO $check$
DECLARE
    bad integer;
BEGIN
    SELECT count(*) INTO bad FROM pg_catalog.pg_roles
    WHERE rolname IN ('cephas_owner','scoped_runtime','cephas_migration','cephas_membership',
        'cephas_registry_admin','cephas_approver','cephas_issuer','cephas_activator',
        'cephas_retirer','cephas_test_scope_a1','cephas_test_scope_a2','cephas_test_scope_b1')
        AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication OR rolinherit
            OR rolcanlogin <> (rolname NOT IN ('cephas_owner','scoped_runtime')));
    IF bad <> 0 OR (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN
        ('cephas_owner','scoped_runtime','cephas_migration','cephas_membership',
        'cephas_registry_admin','cephas_approver','cephas_issuer','cephas_activator',
        'cephas_retirer','cephas_test_scope_a1','cephas_test_scope_a2','cephas_test_scope_b1')) <> 12
    THEN RAISE EXCEPTION 'role attributes mismatch'; END IF;
    SELECT count(*) INTO bad FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member
    JOIN pg_catalog.pg_roles granted_role ON granted_role.oid=m.roleid
    WHERE member_role.rolname IN ('cephas_owner','scoped_runtime','cephas_migration','cephas_membership',
        'cephas_registry_admin','cephas_approver','cephas_issuer','cephas_activator',
        'cephas_retirer','cephas_test_scope_a1','cephas_test_scope_a2','cephas_test_scope_b1')
        AND NOT ((member_role.rolname='cephas_migration' AND granted_role.rolname='cephas_owner'
            AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option)
          OR (member_role.rolname IN ('cephas_test_scope_a1','cephas_test_scope_a2','cephas_test_scope_b1')
            AND granted_role.rolname='scoped_runtime' AND m.inherit_option
            AND NOT m.set_option AND NOT m.admin_option));
    IF bad <> 0 OR (SELECT count(*) FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles r ON r.oid=m.member
        WHERE r.rolname IN ('cephas_migration','cephas_test_scope_a1','cephas_test_scope_a2','cephas_test_scope_b1')) <> 4
    THEN RAISE EXCEPTION 'unexpected role graph'; END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='security' AND c.relname IN ('tenant','business_unit')
        AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
        AND c.relowner='cephas_owner'::regrole) <> 2
    THEN RAISE EXCEPTION 'registry RLS or ownership mismatch'; END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_policies WHERE schemaname='security') <> 4
    THEN RAISE EXCEPTION 'unexpected metadata policy count'; END IF;
    IF has_table_privilege('scoped_runtime','security.tenant','SELECT')
        OR has_table_privilege('scoped_runtime','security.business_unit','INSERT')
        OR has_schema_privilege('scoped_runtime','security','CREATE')
        OR has_schema_privilege('scoped_runtime','ops','CREATE')
        OR has_database_privilege('scoped_runtime',current_database(),'TEMP')
        OR has_schema_privilege('scoped_runtime','public','USAGE')
        OR has_schema_privilege('scoped_runtime','membership','USAGE')
        OR has_table_privilege('cephas_registry_admin','security.tenant','UPDATE')
        OR has_table_privilege('cephas_registry_admin','security.business_unit','DELETE')
        OR has_table_privilege('cephas_registry_admin','security.tenant','TRUNCATE')
    THEN RAISE EXCEPTION 'unexpected effective privileges'; END IF;
END
$check$;
