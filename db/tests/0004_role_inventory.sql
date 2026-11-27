-- T-02.2D.4A: fixed role and privilege inventory for the disposable test cluster.
-- Test bootstrap only; never an attestation or production migration.
BEGIN;
SET LOCAL search_path=pg_catalog;
DO $verify$
DECLARE
    expected_names text[] := ARRAY['cephas_activator','cephas_approver','cephas_issuer','cephas_membership','cephas_migration','cephas_owner','cephas_registry_admin','cephas_retirer','cephas_test_admit_1','cephas_test_admit_2','cephas_test_assoc_1','cephas_test_assoc_2','cephas_test_assoc_3','cephas_test_life_1','cephas_test_life_2','cephas_test_life_3','cephas_test_life_4','cephas_test_life_5','cephas_test_life_6','cephas_test_life_7','cephas_test_rls_1','cephas_test_rls_2','cephas_test_rls_3','cephas_test_scope_a1','cephas_test_scope_a2','cephas_test_scope_b1','scoped_runtime']::text[];
    scope_names text[] := ARRAY['cephas_test_admit_1','cephas_test_admit_2','cephas_test_assoc_1','cephas_test_assoc_2','cephas_test_assoc_3','cephas_test_life_1','cephas_test_life_2','cephas_test_life_3','cephas_test_life_4','cephas_test_life_5','cephas_test_life_6','cephas_test_life_7','cephas_test_rls_1','cephas_test_rls_2','cephas_test_rls_3','cephas_test_scope_a1','cephas_test_scope_a2','cephas_test_scope_b1']::text[];
    own oid := 'cephas_owner'::regrole;
    runtime oid := 'scoped_runtime'::regrole;
    bootstrap oid := 'postgres'::regrole;
    got text[];
    s record;
    r record;
BEGIN
    IF current_database()<>'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR current_user<>'postgres'
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE oid=bootstrap AND rolsuper)
    THEN RAISE EXCEPTION 'role manifest: environment'; END IF;

    -- All user-created roles in this isolated cluster, not just a name prefix.
    SELECT array_agg(rolname::text ORDER BY rolname COLLATE "C") INTO got
    FROM pg_roles WHERE oid>=16384 OR rolname=ANY(expected_names);
    IF got IS DISTINCT FROM expected_names
    THEN RAISE EXCEPTION 'role manifest: role inventory'; END IF;
    IF EXISTS (SELECT 1 FROM (VALUES
        ('cephas_owner',false,-1),
        ('scoped_runtime',false,-1),
        ('cephas_migration',true,4),
        ('cephas_membership',true,8),
        ('cephas_registry_admin',true,1),
        ('cephas_approver',true,1),
        ('cephas_issuer',true,1),
        ('cephas_activator',true,1),
        ('cephas_retirer',true,1),
        ('cephas_test_scope_a1',true,4),
        ('cephas_test_scope_a2',true,4),
        ('cephas_test_scope_b1',true,4),
        ('cephas_test_life_1',false,4),
        ('cephas_test_life_2',false,4),
        ('cephas_test_life_3',false,4),
        ('cephas_test_life_4',false,4),
        ('cephas_test_life_5',false,4),
        ('cephas_test_life_6',false,4),
        ('cephas_test_life_7',false,4),
        ('cephas_test_admit_1',false,4),
        ('cephas_test_admit_2',false,4),
        ('cephas_test_rls_1',true,4),
        ('cephas_test_rls_2',true,4),
        ('cephas_test_rls_3',false,4),
        ('cephas_test_assoc_1',true,4),
        ('cephas_test_assoc_2',true,4),
        ('cephas_test_assoc_3',true,4)
    ) AS e(name,login,lim) LEFT JOIN pg_roles p ON p.rolname=e.name
        WHERE p.oid IS NULL OR p.rolcanlogin<>e.login OR p.rolconnlimit<>e.lim
        OR p.rolsuper OR p.rolbypassrls OR p.rolcreatedb OR p.rolcreaterole
        OR p.rolreplication OR p.rolinherit)
    THEN RAISE EXCEPTION 'role manifest: role attributes'; END IF;

    IF EXISTS (SELECT 1 FROM pg_db_role_setting d
        WHERE d.setrole=0 AND d.setdatabase IN (0,(SELECT oid FROM pg_database WHERE datname=current_database()))
           OR d.setrole IN (SELECT oid FROM pg_roles WHERE rolname=ANY(expected_names)))
    THEN RAISE EXCEPTION 'role manifest: unexpected role settings'; END IF;

    -- Check every edge entering or leaving a managed role; only these edges are allowed.
    IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
        JOIN pg_roles granted ON granted.oid=m.roleid
        WHERE member.rolname=ANY(expected_names) OR granted.rolname=ANY(expected_names))<>19
        OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
            JOIN pg_roles granted ON granted.oid=m.roleid
            WHERE (member.rolname=ANY(expected_names) OR granted.rolname=ANY(expected_names))
            AND NOT (m.grantor=bootstrap AND NOT m.admin_option AND
                ((member.rolname='cephas_migration' AND m.roleid=own
                  AND NOT m.inherit_option AND m.set_option)
                 OR (member.rolname=ANY(scope_names) AND m.roleid=runtime
                  AND m.inherit_option AND NOT m.set_option))))
        OR EXISTS (SELECT 1 FROM pg_roles p WHERE p.rolname=ANY(scope_names)
            AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=p.oid AND roleid=runtime))
        OR NOT EXISTS (SELECT 1 FROM pg_auth_members
            WHERE member='cephas_migration'::regrole AND roleid=own)
    THEN RAISE EXCEPTION 'role manifest: membership graph'; END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname=current_database() AND datdba=bootstrap)
    THEN RAISE EXCEPTION 'role manifest: database owner'; END IF;
    SELECT array_agg(x.grantee::regrole::text||':'||x.privilege_type ORDER BY
        (x.grantee::regrole::text||':'||x.privilege_type) COLLATE "C") INTO got
    FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) x
    WHERE d.datname=current_database() AND x.grantee<>bootstrap;
    IF got IS DISTINCT FROM ARRAY['cephas_activator:CONNECT','cephas_approver:CONNECT','cephas_issuer:CONNECT','cephas_membership:CONNECT','cephas_migration:CONNECT','cephas_registry_admin:CONNECT','cephas_retirer:CONNECT','scoped_runtime:CONNECT']::text[]
        OR EXISTS (SELECT 1 FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) x
            WHERE d.datname=current_database() AND x.grantee<>bootstrap
            AND (x.grantor<>bootstrap OR x.is_grantable))
    THEN RAISE EXCEPTION 'role manifest: database ACL'; END IF;

    SELECT array_agg(nspname::text ORDER BY nspname COLLATE "C") INTO got FROM pg_namespace
        WHERE left(nspname::text,3)<>'pg_' AND nspname<>'information_schema';
    IF got IS DISTINCT FROM ARRAY['membership','ops','public','security']
        OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname IN ('membership','ops','security') AND nspowner<>own)
        OR NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='public' AND nspowner='pg_database_owner'::regrole)
    THEN RAISE EXCEPTION 'role manifest: schema inventory'; END IF;

    FOR s IN SELECT * FROM (VALUES
        ('security',ARRAY['cephas_activator:USAGE','cephas_approver:USAGE','cephas_issuer:USAGE','cephas_registry_admin:USAGE','cephas_retirer:USAGE','scoped_runtime:USAGE']::text[]),
        ('ops',ARRAY['scoped_runtime:USAGE']::text[]),
        ('membership',ARRAY['cephas_membership:USAGE']::text[]),
        ('public',ARRAY[]::text[])
    ) AS schemas(name,grants) LOOP
        SELECT COALESCE(array_agg(x.grantee::regrole::text||':'||x.privilege_type ORDER BY
            (x.grantee::regrole::text||':'||x.privilege_type) COLLATE "C"),ARRAY[]::text[]) INTO got
        FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) x
        WHERE n.nspname=s.name AND x.grantee<>n.nspowner;
        IF got IS DISTINCT FROM s.grants OR EXISTS (
            SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) x
            WHERE n.nspname=s.name AND x.grantee<>n.nspowner
                AND (x.grantor<>n.nspowner OR x.is_grantable))
        THEN RAISE EXCEPTION 'role manifest: schema ACL'; END IF;
    END LOOP;

    -- No alternate user objects in the currently empty public/membership schemas.
    IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('public','membership'))
        OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname IN ('public','membership'))
        OR EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
            WHERE n.nspname IN ('public','membership'))
        OR EXISTS (SELECT 1 FROM pg_foreign_server)
        OR EXISTS (SELECT 1 FROM pg_event_trigger)
        OR EXISTS (SELECT 1 FROM pg_largeobject_metadata)
        OR EXISTS (SELECT 1 FROM pg_extension WHERE extname<>'plpgsql')
    THEN RAISE EXCEPTION 'role manifest: alternate access objects'; END IF;

    -- Future-object privileges: account for default ACLs that are absent from the catalog.
    FOR s IN SELECT * FROM (VALUES ('r'::"char",'r'::"char"),('s'::"char",'S'::"char"),
        ('f'::"char",'f'::"char"),('T'::"char",'T'::"char")) AS types(default_type,catalog_type) LOOP
        IF EXISTS (SELECT 1 FROM aclexplode(COALESCE(
            (SELECT defaclacl FROM pg_default_acl WHERE defaclrole=own AND defaclnamespace=0
                AND defaclobjtype=s.catalog_type),acldefault(s.default_type,own))) x
            WHERE x.grantee<>own)
        THEN RAISE EXCEPTION 'role manifest: owner default privileges'; END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) x
        WHERE d.defaclrole IN (SELECT oid FROM pg_roles WHERE rolname=ANY(expected_names))
            AND x.grantee<>d.defaclrole)
    THEN RAISE EXCEPTION 'role manifest: unexpected default grants'; END IF;

    FOR r IN SELECT oid,rolname FROM pg_roles WHERE rolname=ANY(expected_names)
        AND rolname NOT IN ('cephas_owner','scoped_runtime') LOOP
        IF NOT has_database_privilege(r.oid,current_database(),'CONNECT')
            OR has_database_privilege(r.oid,current_database(),'CREATE,TEMP')
            OR has_schema_privilege(r.oid,'public','USAGE,CREATE')
            OR has_schema_privilege(r.oid,'security','CREATE')
            OR has_schema_privilege(r.oid,'ops','CREATE')
            OR has_schema_privilege(r.oid,'membership','CREATE')
        THEN RAISE EXCEPTION 'role manifest: effective database/schema privilege'; END IF;
        IF r.rolname=ANY(scope_names) THEN
            IF NOT has_table_privilege(r.oid,'ops.scoped_entity','SELECT')
                OR NOT has_table_privilege(r.oid,'ops.scoped_association','SELECT')
                OR has_table_privilege(r.oid,'security.binding_approval','SELECT')
                OR has_table_privilege(r.oid,'security.role_issuance','SELECT')
                OR has_function_privilege(r.oid,'security.guard_binding_update()','EXECUTE')
                OR has_table_privilege(r.oid,'ops.scoped_entity','TRUNCATE,REFERENCES,TRIGGER')
                OR has_table_privilege(r.oid,'ops.scoped_association','TRUNCATE,REFERENCES,TRIGGER')
            THEN RAISE EXCEPTION 'role manifest: effective runtime privilege'; END IF;
        ELSE
            IF has_schema_privilege(r.oid,'ops','USAGE')
                OR has_table_privilege(r.oid,'ops.scoped_entity','SELECT,INSERT,UPDATE,DELETE')
                OR has_table_privilege(r.oid,'ops.scoped_association','SELECT,INSERT,UPDATE,DELETE')
            THEN RAISE EXCEPTION 'role manifest: control role operational access'; END IF;
        END IF;
    END LOOP;
END
$verify$;
ROLLBACK;
