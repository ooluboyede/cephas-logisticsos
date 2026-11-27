-- Reviewed expected operational catalog for expanded 0004 schema; privileged disposable CI verifier.
-- The independently specified expected expression is compiled by PostgreSQL in a
-- transaction on the SAME relation. Roll back the temporary comparison policy.
-- Never execute this verifier against a serving database.
BEGIN;
SET LOCAL search_path=pg_catalog;
DO $check$
DECLARE
    t oid := 'ops.scoped_association'::regclass;
    owner_id oid := 'cephas_owner'::regrole;
    runtime_id oid := 'scoped_runtime'::regrole;
    r record;
    got text[];
BEGIN
    IF current_database() <> 'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
    THEN RAISE EXCEPTION 'manifest: wrong environment'; END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='ops' AND nspowner=owner_id)
        OR NOT EXISTS (SELECT 1 FROM pg_class WHERE oid=t AND relkind='r' AND relpersistence='p'
            AND relowner=owner_id AND relrowsecurity AND relforcerowsecurity AND NOT relispartition)
        OR EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid=t OR inhparent=t)
    THEN RAISE EXCEPTION 'manifest: relation ownership, kind or RLS'; END IF;
    SELECT array_agg(c.relname::text ORDER BY c.relname COLLATE "C") INTO got
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops';
    IF got IS DISTINCT FROM ARRAY['scoped_association','scoped_association_pkey','scoped_association_source_idx','scoped_association_target_idx','scoped_entity','scoped_entity_pkey']
        OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='ops')
    THEN RAISE EXCEPTION 'manifest: unexpected operational objects'; END IF;

    SELECT array_agg(attname::text||':'||atttypid::regtype::text||':'||attnotnull::text
        ORDER BY attnum) INTO got FROM pg_attribute WHERE attrelid=t AND attnum>0;
    IF got IS DISTINCT FROM ARRAY['tenant_id:security.identifier:true',
        'business_unit_id:security.identifier:true','association_id:security.identifier:true','source_entity_id:security.identifier:true',
        'target_entity_id:security.identifier:true','payload:text:true']
        OR EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=t AND attnum>0
            AND (attisdropped OR atthasdef OR attidentity<>'' OR attgenerated<>''
                 OR atttypmod<>-1 OR (attnum<=5 AND attcollation<>'pg_catalog."C"'::regcollation)))
    THEN RAISE EXCEPTION 'manifest: column definition'; END IF;

    IF (SELECT count(*) FROM pg_constraint WHERE conrelid=t)<>3
        OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=t AND contype='p'
            AND conname='scoped_association_pkey' AND conkey=ARRAY[1,2,3]::smallint[]
            AND convalidated AND NOT condeferrable)
        OR (SELECT count(*) FROM pg_constraint WHERE conrelid=t AND contype='f'
            AND confrelid='ops.scoped_entity'::regclass AND confkey=ARRAY[1,2,3]::smallint[]
            AND convalidated AND NOT condeferrable
            AND confmatchtype='s' AND confupdtype='a' AND confdeltype='a'
            AND ((conname='scoped_association_source_fk' AND conkey=ARRAY[1,2,4]::smallint[])
                OR (conname='scoped_association_target_fk' AND conkey=ARRAY[1,2,5]::smallint[])))<>2
        OR (SELECT count(*) FROM pg_index WHERE indrelid=t)<>3
        OR (SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
            WHERE i.indrelid=t AND i.indisvalid AND i.indisready AND i.indislive
            AND i.indnkeyatts=3 AND i.indnatts=3 AND i.indexprs IS NULL AND i.indpred IS NULL
            AND ((c.relname='scoped_association_pkey' AND i.indisprimary AND i.indisunique
                    AND i.indkey::text='1 2 3')
                OR (c.relname='scoped_association_source_idx' AND NOT i.indisunique
                    AND i.indkey::text='1 2 4')
                OR (c.relname='scoped_association_target_idx' AND NOT i.indisunique
                    AND i.indkey::text='1 2 5')))<>3
        OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=t
            AND (NOT tgisinternal OR tgenabled<>'O'))
        OR EXISTS (SELECT 1 FROM pg_rewrite WHERE ev_class=t)
    THEN RAISE EXCEPTION 'manifest: constraints, indexes or alternate paths'; END IF;

    -- Compare explicit ACLs, excluding the owner, not merely a few effective grants.
    SELECT array_agg(grantee::regrole::text||':'||privilege_type||':'||is_grantable::text
        ORDER BY grantee::regrole::text,privilege_type) INTO got
    FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl)
    WHERE c.oid=t AND grantee<>owner_id;
    IF got IS DISTINCT FROM ARRAY['scoped_runtime:DELETE:false',
        'scoped_runtime:INSERT:false','scoped_runtime:SELECT:false']
    THEN RAISE EXCEPTION 'manifest: table ACL'; END IF;
    SELECT array_agg(a.attname::text||':'||x.grantee::regrole::text||':'||x.privilege_type
        ||':'||x.is_grantable::text ORDER BY a.attnum,x.grantee::regrole::text,x.privilege_type)
        INTO got FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x
        WHERE a.attrelid=t AND a.attnum>0;
    IF got IS DISTINCT FROM ARRAY['payload:scoped_runtime:UPDATE:false']
    THEN RAISE EXCEPTION 'manifest: column ACL'; END IF;
    SELECT array_agg(grantee::regrole::text||':'||privilege_type||':'||is_grantable::text
        ORDER BY grantee::regrole::text,privilege_type) INTO got
    FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl)
    WHERE n.nspname='ops' AND grantee<>owner_id;
    IF got IS DISTINCT FROM ARRAY['scoped_runtime:USAGE:false']
    THEN RAISE EXCEPTION 'manifest: schema ACL'; END IF;
    IF EXISTS (SELECT 1 FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) x
        WHERE d.defaclrole=owner_id AND x.grantee<>owner_id)
        OR NOT EXISTS (SELECT 1 FROM pg_default_acl WHERE defaclrole=owner_id
            AND defaclnamespace=0 AND defaclobjtype='f')
        OR NOT EXISTS (SELECT 1 FROM pg_default_acl WHERE defaclrole=owner_id
            AND defaclnamespace=0 AND defaclobjtype='T')
    THEN RAISE EXCEPTION 'manifest: default ACL'; END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member=runtime_id)
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE oid=runtime_id AND NOT rolcanlogin
            AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb
            AND NOT rolreplication AND NOT rolinherit)
    THEN RAISE EXCEPTION 'manifest: runtime group'; END IF;
    FOR r IN SELECT * FROM pg_roles WHERE rolname IN
        ('cephas_test_assoc_1','cephas_test_assoc_2','cephas_test_assoc_3') LOOP
        IF r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication
            OR r.rolinherit OR r.rolconnlimit<>4
            OR (SELECT count(*) FROM pg_auth_members WHERE member=r.oid)<>1
            OR NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid AND roleid=runtime_id
                AND inherit_option AND NOT set_option AND NOT admin_option)
            OR EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid=r.oid)
            OR has_table_privilege(r.oid,t,'TRUNCATE,REFERENCES,TRIGGER')
            OR has_column_privilege(r.oid,t,'tenant_id','UPDATE')
            OR has_column_privilege(r.oid,t,'business_unit_id','UPDATE')
            OR has_column_privilege(r.oid,t,'association_id','UPDATE')
            OR has_column_privilege(r.oid,t,'source_entity_id','UPDATE')
            OR has_column_privilege(r.oid,t,'target_entity_id','UPDATE')
            OR has_schema_privilege(r.oid,'ops','CREATE')
            OR has_database_privilege(r.oid,current_database(),'TEMP')
        THEN RAISE EXCEPTION 'manifest: scope role or effective privileges'; END IF;
    END LOOP;
    IF (SELECT count(*) FROM pg_roles WHERE rolname IN
        ('cephas_test_assoc_1','cephas_test_assoc_2','cephas_test_assoc_3'))<>3
    THEN RAISE EXCEPTION 'manifest: missing fixture role'; END IF;

    IF (SELECT count(*) FROM pg_policy WHERE polrelid=t)<>5
        OR EXISTS (
            SELECT 1 FROM (VALUES
                ('scoped_association_guard','*',false,ARRAY[0::oid],true,true),
                ('scoped_association_select','r',true,ARRAY[runtime_id],true,false),
                ('scoped_association_insert','a',true,ARRAY[runtime_id],false,true),
                ('scoped_association_update','w',true,ARRAY[runtime_id],true,true),
                ('scoped_association_delete','d',true,ARRAY[runtime_id],true,false)
            ) AS e(name,cmd,permissive,roles,has_using,has_check)
            LEFT JOIN pg_policy p ON p.polrelid=t AND p.polname=e.name
            WHERE p.oid IS NULL OR p.polcmd::text<>e.cmd OR p.polpermissive<>e.permissive
                OR p.polroles<>e.roles OR (p.polqual IS NOT NULL)<>e.has_using
                OR (p.polwithcheck IS NOT NULL)<>e.has_check
        )
    THEN RAISE EXCEPTION 'manifest: policy inventory or metadata'; END IF;
END
$check$;

CREATE POLICY manifest_expected ON ops.scoped_association AS RESTRICTIVE FOR ALL TO PUBLIC
    USING (COALESCE(
    char_length(current_setting('cephas.subject_id',true)) BETWEEN 1 AND 128
    AND (current_setting('cephas.subject_id',true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (current_setting('cephas.subject_id',true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND char_length(current_setting('cephas.tenant_id',true)) BETWEEN 1 AND 128
    AND (current_setting('cephas.tenant_id',true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (current_setting('cephas.tenant_id',true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND char_length(current_setting('cephas.business_unit_id',true)) BETWEEN 1 AND 128
    AND (current_setting('cephas.business_unit_id',true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (current_setting('cephas.business_unit_id',true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_association.tenant_id = current_setting('cephas.tenant_id',true) COLLATE pg_catalog."C"
    AND scoped_association.business_unit_id = current_setting('cephas.business_unit_id',true) COLLATE pg_catalog."C"
    AND EXISTS (SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name=SESSION_USER AND b.state='active'
          AND b.tenant_id=scoped_association.tenant_id AND b.business_unit_id=scoped_association.business_unit_id),
    false)) WITH CHECK (COALESCE(
    char_length(current_setting('cephas.subject_id',true)) BETWEEN 1 AND 128
    AND (current_setting('cephas.subject_id',true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (current_setting('cephas.subject_id',true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND char_length(current_setting('cephas.tenant_id',true)) BETWEEN 1 AND 128
    AND (current_setting('cephas.tenant_id',true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (current_setting('cephas.tenant_id',true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND char_length(current_setting('cephas.business_unit_id',true)) BETWEEN 1 AND 128
    AND (current_setting('cephas.business_unit_id',true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (current_setting('cephas.business_unit_id',true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_association.tenant_id = current_setting('cephas.tenant_id',true) COLLATE pg_catalog."C"
    AND scoped_association.business_unit_id = current_setting('cephas.business_unit_id',true) COLLATE pg_catalog."C"
    AND EXISTS (SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name=SESSION_USER AND b.state='active'
          AND b.tenant_id=scoped_association.tenant_id AND b.business_unit_id=scoped_association.business_unit_id),
    false));
DO $expressions$
DECLARE
    t oid := 'ops.scoped_association'::regclass;
    expected_using text;
    expected_check text;
BEGIN
    SELECT pg_get_expr(polqual,t),pg_get_expr(polwithcheck,t)
    INTO STRICT expected_using,expected_check FROM pg_policy
    WHERE polrelid=t AND polname='manifest_expected';
    IF EXISTS (SELECT 1 FROM pg_policy WHERE polrelid=t AND polname<>'manifest_expected'
        AND ((polqual IS NOT NULL AND pg_get_expr(polqual,t) IS DISTINCT FROM expected_using)
          OR (polwithcheck IS NOT NULL AND pg_get_expr(polwithcheck,t) IS DISTINCT FROM expected_check)))
    THEN RAISE EXCEPTION 'manifest: normalized policy expression'; END IF;
END
$expressions$;
ROLLBACK;
