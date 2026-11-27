-- Narrow post-0006 administrative access-path checks, disposable PG16 only.
BEGIN;
SET LOCAL search_path=pg_catalog;
DO $check$
DECLARE
    executor oid := 'cephas_membership_executor'::regrole;
    admin_id oid := 'cephas_membership_admin'::regrole;
    owner_id oid := 'cephas_owner'::regrole;
    r record;
BEGIN
    IF current_database()<>'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
    THEN RAISE EXCEPTION 'membership admin manifest: environment'; END IF;
    IF (SELECT count(*) FROM pg_roles WHERE oid IN (executor,admin_id)
        AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole
        AND NOT rolreplication AND NOT rolinherit
        AND rolcanlogin=(oid=admin_id) AND rolconnlimit=CASE WHEN oid=admin_id THEN 1 ELSE -1 END)<>2
        OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member IN (executor,admin_id)
            OR roleid IN (executor,admin_id))
        OR has_database_privilege(executor,current_database(),'CONNECT')
        OR NOT has_database_privilege(admin_id,current_database(),'CONNECT')
        OR has_database_privilege(admin_id,current_database(),'CREATE,TEMP')
    THEN RAISE EXCEPTION 'membership admin manifest: role isolation'; END IF;
    IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='membership')<>6
        OR (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='membership' AND p.prosecdef AND p.proowner=executor
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND p.oid IN ('membership.enrol(text,text,text,uuid,uuid,bigint,text)'::regprocedure,
                'membership.change_state(uuid,bigint,boolean,text)'::regprocedure))<>2
        OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='membership' AND NOT p.prosecdef
                AND (p.proowner<>owner_id OR p.proacl IS NULL
                    OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) x WHERE x.grantee<>owner_id)))
    THEN RAISE EXCEPTION 'membership admin manifest: function inventory'; END IF;
    FOR r IN SELECT p.oid,p.proacl FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='membership' AND p.prosecdef LOOP
        IF (SELECT count(*) FROM aclexplode(r.proacl) x
            WHERE x.grantee=admin_id AND x.privilege_type='EXECUTE' AND NOT x.is_grantable)<>1
            OR EXISTS (SELECT 1 FROM aclexplode(r.proacl) x
                WHERE x.grantee NOT IN (executor,admin_id) OR (x.grantee=admin_id AND x.is_grantable))
        THEN RAISE EXCEPTION 'membership admin manifest: function ACL'; END IF;
    END LOOP;
    IF has_any_column_privilege(admin_id,'membership.subject_scope','SELECT,INSERT,UPDATE,REFERENCES')
        OR has_table_privilege(admin_id,'membership.subject_scope','DELETE,TRUNCATE,TRIGGER')
        OR has_any_column_privilege(admin_id,'membership.change_audit','SELECT,INSERT,UPDATE,REFERENCES')
        OR has_table_privilege(admin_id,'membership.change_audit','DELETE,TRUNCATE,TRIGGER')
        OR has_schema_privilege(executor,'membership','CREATE')
        OR has_schema_privilege(admin_id,'membership','CREATE')
        OR has_table_privilege(executor,'membership.subject_scope','DELETE,TRUNCATE,TRIGGER')
        OR has_table_privilege(executor,'membership.change_audit','SELECT,UPDATE,DELETE,TRUNCATE,TRIGGER')
        OR has_column_privilege(executor,'membership.subject_scope','generation','UPDATE')
        OR has_column_privilege(executor,'membership.subject_scope','revision','UPDATE')
        OR has_column_privilege(executor,'membership.subject_scope','previous_generation','UPDATE')
    THEN RAISE EXCEPTION 'membership admin manifest: direct access privileges'; END IF;
    IF (SELECT count(*) FROM pg_class WHERE oid IN ('membership.subject_scope'::regclass,
        'membership.change_audit'::regclass) AND relowner=owner_id AND relrowsecurity
        AND relforcerowsecurity AND relkind='r')<>2
        OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid IN ('membership.subject_scope'::regclass,
            'membership.change_audit'::regclass) AND tgenabled<>'O')
    THEN RAISE EXCEPTION 'membership admin manifest: RLS or trigger drift'; END IF;
END
$check$;
ROLLBACK;
