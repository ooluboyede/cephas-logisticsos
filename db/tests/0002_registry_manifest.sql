-- Disposable CI verifier: expected registry policy definitions are fixed in source,
-- not obtained from the live catalog. Comparison policies are rolled back.
BEGIN;
SET LOCAL search_path=pg_catalog;
DO $check$
DECLARE
    own oid := 'cephas_owner'::regrole;
    got text[];
BEGIN
    IF current_database()<>'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
    THEN RAISE EXCEPTION 'registry manifest: environment'; END IF;
    SELECT array_agg(c.relname::text ORDER BY c.relname COLLATE "C") INTO got
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='security' AND c.relkind<>'i';
    IF got IS DISTINCT FROM ARRAY['binding_approval','business_unit','role_issuance','scope_binding','tenant']
        OR (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='security' AND c.relkind='r' AND c.relowner=own
                AND c.relrowsecurity AND c.relforcerowsecurity AND NOT c.relispartition
                AND c.relpersistence='p')<>5
        OR EXISTS (SELECT 1 FROM pg_inherits i JOIN pg_class c ON c.oid IN (i.inhrelid,i.inhparent)
            JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='security')
    THEN RAISE EXCEPTION 'registry manifest: relation inventory or RLS'; END IF;
    SELECT array_agg(attname::text||':'||atttypid::regtype::text||':'||attnotnull::text ORDER BY attnum)
      INTO got FROM pg_attribute WHERE attrelid='security.tenant'::regclass AND attnum>0;
    IF got IS DISTINCT FROM ARRAY['tenant_id:security.identifier:true']::text[]
    THEN RAISE EXCEPTION 'registry manifest: columns'; END IF;
    SELECT array_agg(attname::text||':'||atttypid::regtype::text||':'||attnotnull::text ORDER BY attnum)
      INTO got FROM pg_attribute WHERE attrelid='security.business_unit'::regclass AND attnum>0;
    IF got IS DISTINCT FROM ARRAY['tenant_id:security.identifier:true','business_unit_id:security.identifier:true']::text[]
    THEN RAISE EXCEPTION 'registry manifest: columns'; END IF;
    SELECT array_agg(attname::text||':'||atttypid::regtype::text||':'||attnotnull::text ORDER BY attnum)
      INTO got FROM pg_attribute WHERE attrelid='security.binding_approval'::regclass AND attnum>0;
    IF got IS DISTINCT FROM ARRAY['approval_id:uuid:true','deployment_id:security.identifier:true','role_name:name:true','role_oid:oid:true','generation:uuid:true','tenant_id:security.identifier:true','business_unit_id:security.identifier:true','approver_subject:security.identifier:true','second_approver_subject:security.identifier:true','change_ref:security.identifier:true','approval_evidence_sha256:text:true','approved_at:timestamp with time zone:true','expires_at:timestamp with time zone:true']::text[]
    THEN RAISE EXCEPTION 'registry manifest: columns'; END IF;
    SELECT array_agg(attname::text||':'||atttypid::regtype::text||':'||attnotnull::text ORDER BY attnum)
      INTO got FROM pg_attribute WHERE attrelid='security.role_issuance'::regclass AND attnum>0;
    IF got IS DISTINCT FROM ARRAY['role_name:name:true','generation:uuid:true','role_oid:oid:true','approval_id:uuid:true','deployment_id:security.identifier:true','tenant_id:security.identifier:true','business_unit_id:security.identifier:true','issued_at:timestamp with time zone:true']::text[]
    THEN RAISE EXCEPTION 'registry manifest: columns'; END IF;
    SELECT array_agg(attname::text||':'||atttypid::regtype::text||':'||attnotnull::text ORDER BY attnum)
      INTO got FROM pg_attribute WHERE attrelid='security.scope_binding'::regclass AND attnum>0;
    IF got IS DISTINCT FROM ARRAY['role_name:name:true','role_oid:oid:true','generation:uuid:true','tenant_id:security.identifier:true','business_unit_id:security.identifier:true','state:text:true','created_at:timestamp with time zone:true','retired_at:timestamp with time zone:false']::text[]
    THEN RAISE EXCEPTION 'registry manifest: columns'; END IF;
    IF EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='security' AND c.relkind='r'
        AND a.attnum>0 AND (a.attisdropped OR a.attidentity<>'' OR a.attgenerated<>''
            OR (a.atttypid='security.identifier'::regtype AND a.attcollation<>'pg_catalog."C"'::regcollation)))
    THEN RAISE EXCEPTION 'registry manifest: column attributes'; END IF;

    -- Check the exact column order and target relation for every primary/unique/FK.
    WITH key_rows AS (
        SELECT c.relname::text||':'||k.contype::text||':'||
            (SELECT string_agg(a.attname::text,',' ORDER BY u.ord)
                FROM unnest(k.conkey) WITH ORDINALITY u(num,ord)
                JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=u.num)||
            CASE WHEN k.contype='f' THEN ':'||target.relname::text||':'||
                (SELECT string_agg(a.attname::text,',' ORDER BY u.ord)
                    FROM unnest(k.confkey) WITH ORDINALITY u(num,ord)
                    JOIN pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=u.num)
                ELSE '' END AS item
        FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_class target ON target.oid=k.confrelid
        WHERE n.nspname='security' AND k.contype IN ('p','u','f')
    )
    SELECT array_agg(item ORDER BY item COLLATE "C") INTO got FROM key_rows;
    IF got IS DISTINCT FROM ARRAY['binding_approval:f:tenant_id,business_unit_id:business_unit:tenant_id,business_unit_id',
        'binding_approval:p:approval_id',
        'binding_approval:u:approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id',
        'binding_approval:u:change_ref',
        'binding_approval:u:generation',
        'binding_approval:u:role_name',
        'business_unit:f:tenant_id:tenant:tenant_id',
        'business_unit:p:tenant_id,business_unit_id',
        'role_issuance:f:approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id:binding_approval:approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id',
        'role_issuance:p:role_name',
        'role_issuance:u:approval_id',
        'role_issuance:u:generation',
        'role_issuance:u:role_name,role_oid,generation,tenant_id,business_unit_id',
        'scope_binding:f:role_name,role_oid,generation,tenant_id,business_unit_id:role_issuance:role_name,role_oid,generation,tenant_id,business_unit_id',
        'scope_binding:f:tenant_id,business_unit_id:business_unit:tenant_id,business_unit_id',
        'scope_binding:p:role_name',
        'scope_binding:u:generation',
        'tenant:p:tenant_id']
        OR EXISTS (SELECT 1 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='security'
            AND (NOT k.convalidated OR k.condeferrable OR
                (k.contype='f' AND (k.confmatchtype<>'s' OR k.confupdtype<>'a' OR k.confdeltype<>'a'
                    OR NOT EXISTS (SELECT 1 FROM pg_class f JOIN pg_namespace fn ON fn.oid=f.relnamespace
                        WHERE f.oid=k.confrelid AND fn.nspname='security')))))
    THEN RAISE EXCEPTION 'registry manifest: keys'; END IF;

    SELECT array_agg(c.relname::text||':'||a.attname::text||':'||pg_get_expr(d.adbin,d.adrelid)
        ORDER BY (c.relname::text||':'||a.attname::text) COLLATE "C") INTO got
    FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum
    WHERE n.nspname='security';
    IF got IS DISTINCT FROM ARRAY['binding_approval:approved_at:statement_timestamp()',
        'role_issuance:issued_at:statement_timestamp()','scope_binding:created_at:statement_timestamp()',
        'scope_binding:state:''pending''::text']
    THEN RAISE EXCEPTION 'registry manifest: defaults'; END IF;
    IF (SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='security')<>15
        OR EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='security'
            AND (NOT i.indisunique OR NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive
                OR i.indexprs IS NOT NULL))
        OR (SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
            WHERE i.indrelid='security.scope_binding'::regclass AND i.indpred IS NOT NULL
            AND ((c.relname='scope_binding_live_scope' AND i.indkey::text='4 5')
              OR (c.relname='scope_binding_live_oid' AND i.indkey::text='2')))<>2
    THEN RAISE EXCEPTION 'registry manifest: indexes'; END IF;

    SELECT array_agg(c.relname::text||':'||x.grantee::regrole::text||':'||x.privilege_type
        ORDER BY (c.relname::text||':'||x.grantee::regrole::text||':'||x.privilege_type) COLLATE "C") INTO got
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) x
    WHERE n.nspname='security' AND c.relkind='r' AND x.grantee<>own;
    IF got IS DISTINCT FROM ARRAY['binding_approval:cephas_activator:SELECT','binding_approval:cephas_issuer:SELECT','business_unit:cephas_registry_admin:INSERT','business_unit:cephas_registry_admin:SELECT','role_issuance:cephas_activator:SELECT','role_issuance:cephas_issuer:SELECT','scope_binding:cephas_activator:SELECT','scope_binding:cephas_issuer:SELECT','scope_binding:cephas_retirer:SELECT','tenant:cephas_registry_admin:INSERT','tenant:cephas_registry_admin:SELECT']::text[]
        OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            CROSS JOIN LATERAL aclexplode(c.relacl) x WHERE n.nspname='security'
            AND x.grantee<>own AND (x.grantor<>own OR x.is_grantable))
    THEN RAISE EXCEPTION 'registry manifest: table ACL'; END IF;
    SELECT array_agg(c.relname::text||':'||a.attname::text||':'||x.grantee::regrole::text||':'||x.privilege_type
        ORDER BY (c.relname::text||':'||a.attname::text||':'||x.grantee::regrole::text||':'||x.privilege_type) COLLATE "C") INTO got
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE n.nspname='security' AND a.attnum>0;
    IF got IS DISTINCT FROM ARRAY['binding_approval:approval_evidence_sha256:cephas_approver:INSERT','binding_approval:approval_id:cephas_approver:INSERT','binding_approval:approver_subject:cephas_approver:INSERT','binding_approval:business_unit_id:cephas_approver:INSERT','binding_approval:change_ref:cephas_approver:INSERT','binding_approval:deployment_id:cephas_approver:INSERT','binding_approval:expires_at:cephas_approver:INSERT','binding_approval:generation:cephas_approver:INSERT','binding_approval:role_name:cephas_approver:INSERT','binding_approval:role_oid:cephas_approver:INSERT','binding_approval:second_approver_subject:cephas_approver:INSERT','binding_approval:tenant_id:cephas_approver:INSERT','role_issuance:approval_id:cephas_issuer:INSERT','role_issuance:business_unit_id:cephas_issuer:INSERT','role_issuance:deployment_id:cephas_issuer:INSERT','role_issuance:generation:cephas_issuer:INSERT','role_issuance:role_name:cephas_issuer:INSERT','role_issuance:role_oid:cephas_issuer:INSERT','role_issuance:tenant_id:cephas_issuer:INSERT','scope_binding:business_unit_id:cephas_issuer:INSERT','scope_binding:business_unit_id:scoped_runtime:SELECT','scope_binding:generation:cephas_issuer:INSERT','scope_binding:role_name:cephas_issuer:INSERT','scope_binding:role_name:scoped_runtime:SELECT','scope_binding:role_oid:cephas_issuer:INSERT','scope_binding:role_oid:scoped_runtime:SELECT','scope_binding:state:cephas_activator:UPDATE','scope_binding:state:cephas_retirer:UPDATE','scope_binding:state:scoped_runtime:SELECT','scope_binding:tenant_id:cephas_issuer:INSERT','scope_binding:tenant_id:scoped_runtime:SELECT']::text[]
        OR EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(a.attacl) x
            WHERE n.nspname='security' AND (x.grantor<>own OR x.is_grantable))
    THEN RAISE EXCEPTION 'registry manifest: column ACL'; END IF;

    SELECT array_agg(x.grantee::regrole::text||':'||x.privilege_type ORDER BY
        (x.grantee::regrole::text||':'||x.privilege_type) COLLATE "C") INTO got
    FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) x
    WHERE n.nspname='security' AND x.grantee<>own;
    IF got IS DISTINCT FROM ARRAY['cephas_activator:USAGE','cephas_approver:USAGE','cephas_issuer:USAGE','cephas_registry_admin:USAGE','cephas_retirer:USAGE','scoped_runtime:USAGE']::text[]
        OR NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='security' AND nspowner=own)
        OR EXISTS (SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) x
            WHERE n.nspname='security' AND x.grantee<>own AND (x.grantor<>own OR x.is_grantable))
    THEN RAISE EXCEPTION 'registry manifest: schema ACL'; END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE oid='security.identifier'::regtype
        AND typtype='d' AND typowner=own AND typbasetype='text'::regtype
        AND typcollation='pg_catalog."C"'::regcollation AND typdefault IS NULL)
        OR (SELECT count(*) FROM pg_constraint WHERE contypid='security.identifier'::regtype
            AND contype='c' AND convalidated)<>1
    THEN RAISE EXCEPTION 'registry manifest: domain structure'; END IF;
    SELECT array_agg(x.grantee::regrole::text||':'||x.privilege_type ORDER BY
        (x.grantee::regrole::text||':'||x.privilege_type) COLLATE "C") INTO got
    FROM pg_type t CROSS JOIN LATERAL aclexplode(t.typacl) x
    WHERE t.oid='security.identifier'::regtype AND x.grantee<>own;
    IF got IS DISTINCT FROM ARRAY['cephas_activator:USAGE','cephas_approver:USAGE','cephas_issuer:USAGE','cephas_registry_admin:USAGE','cephas_retirer:USAGE','scoped_runtime:USAGE']::text[]
    THEN RAISE EXCEPTION 'registry manifest: domain ACL'; END IF;

    SELECT array_agg(p.proname::text ORDER BY p.proname COLLATE "C") INTO got FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='security';
    IF got IS DISTINCT FROM ARRAY['guard_binding_update','reject_registry_mutation']
        OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='security' AND (p.proowner<>own OR p.prosecdef OR p.pronargs<>0
                OR p.prorettype<>'trigger'::regtype OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']
                OR p.prolang<>(SELECT oid FROM pg_language WHERE lanname='plpgsql')
                OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) x WHERE x.grantee<>own)
                OR p.proacl IS NULL))
    THEN RAISE EXCEPTION 'registry manifest: routine security'; END IF;
    IF (SELECT prosrc FROM pg_proc WHERE oid='security.reject_registry_mutation()'::regprocedure) IS DISTINCT FROM $body$
BEGIN
    RAISE EXCEPTION 'immutable registry record' USING ERRCODE='42501';
END
$body$
    THEN RAISE EXCEPTION 'registry manifest: routine body'; END IF;
    IF (SELECT prosrc FROM pg_proc WHERE oid='security.guard_binding_update()'::regprocedure) IS DISTINCT FROM $body$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'binding removal prohibited' USING ERRCODE='42501';
    END IF;
    IF ROW(OLD.role_name,OLD.role_oid,OLD.generation,OLD.tenant_id,OLD.business_unit_id,OLD.created_at)
        IS DISTINCT FROM
        ROW(NEW.role_name,NEW.role_oid,NEW.generation,NEW.tenant_id,NEW.business_unit_id,NEW.created_at)
        OR NOT ((OLD.state='pending' AND NEW.state='active')
            OR (OLD.state IN ('pending','active') AND NEW.state='retired'))
    THEN RAISE EXCEPTION 'invalid binding transition' USING ERRCODE='42501'; END IF;
    IF NEW.state='retired' THEN NEW.retired_at := statement_timestamp(); END IF;
    RETURN NEW;
END
$body$
    THEN RAISE EXCEPTION 'registry manifest: routine body'; END IF;
    SELECT array_agg(c.relname::text||':'||t.tgname::text||':'||p.proname::text||':'||t.tgtype::text
        ORDER BY (c.relname::text||':'||t.tgname::text) COLLATE "C") INTO got
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_proc p ON p.oid=t.tgfoid WHERE n.nspname='security' AND NOT t.tgisinternal;
    IF got IS DISTINCT FROM ARRAY[
        'binding_approval:approval_immutable:reject_registry_mutation:27',
        'binding_approval:approval_no_truncate:reject_registry_mutation:34',
        'role_issuance:issuance_immutable:reject_registry_mutation:27',
        'role_issuance:issuance_no_truncate:reject_registry_mutation:34',
        'scope_binding:binding_no_truncate:reject_registry_mutation:34',
        'scope_binding:binding_transition:guard_binding_update:27']
        OR EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='security'
            AND (t.tgenabled<>'O' OR (NOT t.tgisinternal AND (t.tgqual IS NOT NULL OR t.tgnargs<>0))))
    THEN RAISE EXCEPTION 'registry manifest: trigger configuration'; END IF;
    IF (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='security')<>19
    THEN RAISE EXCEPTION 'registry manifest: policy inventory'; END IF;
END
$check$;

CREATE DOMAIN security.manifest_identifier AS text COLLATE pg_catalog."C"
    CHECK (char_length(VALUE) BETWEEN 1 AND 128 AND VALUE ~ '^[A-Za-z0-9]'
        AND VALUE !~ '[^A-Za-z0-9._:-]');
DO $domain$
BEGIN
    IF (SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE contypid='security.identifier'::regtype)
        IS DISTINCT FROM (SELECT pg_get_constraintdef(oid) FROM pg_constraint
            WHERE contypid='security.manifest_identifier'::regtype)
    THEN RAISE EXCEPTION 'registry manifest: domain expression'; END IF;
END
$domain$;
CREATE POLICY manifest_registry_admin_select ON security.tenant AS PERMISSIVE FOR SELECT TO cephas_registry_admin USING (true);
CREATE POLICY manifest_registry_admin_insert ON security.tenant AS PERMISSIVE FOR INSERT TO cephas_registry_admin WITH CHECK (true);
CREATE POLICY manifest_registry_admin_select ON security.business_unit AS PERMISSIVE FOR SELECT TO cephas_registry_admin USING (true);
CREATE POLICY manifest_registry_admin_insert ON security.business_unit AS PERMISSIVE FOR INSERT TO cephas_registry_admin WITH CHECK (true);
CREATE POLICY manifest_approval_read ON security.binding_approval AS PERMISSIVE FOR SELECT TO cephas_issuer,cephas_activator USING (true);
CREATE POLICY manifest_issuance_read ON security.role_issuance AS PERMISSIVE FOR SELECT TO cephas_issuer,cephas_activator USING (true);
CREATE POLICY manifest_binding_control_read ON security.scope_binding AS PERMISSIVE FOR SELECT TO cephas_issuer,cephas_activator,cephas_retirer USING (true);
CREATE POLICY manifest_approval_create_permissive ON security.binding_approval AS PERMISSIVE FOR INSERT TO cephas_approver WITH CHECK (binding_approval.deployment_id='t02-test-deployment' AND binding_approval.approved_at<=statement_timestamp() AND binding_approval.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=binding_approval.role_name AND r.oid=binding_approval.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit));
CREATE POLICY manifest_approval_create_restrictive ON security.binding_approval AS RESTRICTIVE FOR INSERT TO cephas_approver WITH CHECK (binding_approval.deployment_id='t02-test-deployment' AND binding_approval.approved_at<=statement_timestamp() AND binding_approval.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=binding_approval.role_name AND r.oid=binding_approval.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit));
CREATE POLICY manifest_issuance_create_permissive ON security.role_issuance AS PERMISSIVE FOR INSERT TO cephas_issuer WITH CHECK (EXISTS (SELECT 1 FROM security.binding_approval AS a WHERE a.approval_id=role_issuance.approval_id AND a.deployment_id=role_issuance.deployment_id AND a.role_name=role_issuance.role_name AND a.role_oid=role_issuance.role_oid AND a.generation=role_issuance.generation AND a.tenant_id=role_issuance.tenant_id AND a.business_unit_id=role_issuance.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY manifest_issuance_create_restrictive ON security.role_issuance AS RESTRICTIVE FOR INSERT TO cephas_issuer WITH CHECK (EXISTS (SELECT 1 FROM security.binding_approval AS a WHERE a.approval_id=role_issuance.approval_id AND a.deployment_id=role_issuance.deployment_id AND a.role_name=role_issuance.role_name AND a.role_oid=role_issuance.role_oid AND a.generation=role_issuance.generation AND a.tenant_id=role_issuance.tenant_id AND a.business_unit_id=role_issuance.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY manifest_binding_create_permissive ON security.scope_binding AS PERMISSIVE FOR INSERT TO cephas_issuer WITH CHECK (state='pending' AND retired_at IS NULL AND EXISTS (SELECT 1 FROM security.role_issuance AS i JOIN security.binding_approval AS a ON a.approval_id=i.approval_id AND a.deployment_id=i.deployment_id AND a.role_name=i.role_name AND a.role_oid=i.role_oid AND a.generation=i.generation AND a.tenant_id=i.tenant_id AND a.business_unit_id=i.business_unit_id WHERE i.role_name=scope_binding.role_name AND i.role_oid=scope_binding.role_oid AND i.generation=scope_binding.generation AND i.tenant_id=scope_binding.tenant_id AND i.business_unit_id=scope_binding.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY manifest_binding_create_restrictive ON security.scope_binding AS RESTRICTIVE FOR INSERT TO cephas_issuer WITH CHECK (state='pending' AND retired_at IS NULL AND EXISTS (SELECT 1 FROM security.role_issuance AS i JOIN security.binding_approval AS a ON a.approval_id=i.approval_id AND a.deployment_id=i.deployment_id AND a.role_name=i.role_name AND a.role_oid=i.role_oid AND a.generation=i.generation AND a.tenant_id=i.tenant_id AND a.business_unit_id=i.business_unit_id WHERE i.role_name=scope_binding.role_name AND i.role_oid=scope_binding.role_oid AND i.generation=scope_binding.generation AND i.tenant_id=scope_binding.tenant_id AND i.business_unit_id=scope_binding.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY manifest_binding_activate_permissive ON security.scope_binding AS PERMISSIVE FOR UPDATE TO cephas_activator USING (state='pending') WITH CHECK (state='active' AND retired_at IS NULL AND EXISTS (SELECT 1 FROM security.role_issuance AS i JOIN security.binding_approval AS a ON a.approval_id=i.approval_id AND a.deployment_id=i.deployment_id AND a.role_name=i.role_name AND a.role_oid=i.role_oid AND a.generation=i.generation AND a.tenant_id=i.tenant_id AND a.business_unit_id=i.business_unit_id WHERE i.role_name=scope_binding.role_name AND i.role_oid=scope_binding.role_oid AND i.generation=scope_binding.generation AND i.tenant_id=scope_binding.tenant_id AND i.business_unit_id=scope_binding.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY manifest_binding_activate_restrictive ON security.scope_binding AS RESTRICTIVE FOR UPDATE TO cephas_activator USING (state='pending') WITH CHECK (state='active' AND retired_at IS NULL AND EXISTS (SELECT 1 FROM security.role_issuance AS i JOIN security.binding_approval AS a ON a.approval_id=i.approval_id AND a.deployment_id=i.deployment_id AND a.role_name=i.role_name AND a.role_oid=i.role_oid AND a.generation=i.generation AND a.tenant_id=i.tenant_id AND a.business_unit_id=i.business_unit_id WHERE i.role_name=scope_binding.role_name AND i.role_oid=scope_binding.role_oid AND i.generation=scope_binding.generation AND i.tenant_id=scope_binding.tenant_id AND i.business_unit_id=scope_binding.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY manifest_binding_retire_permissive ON security.scope_binding AS PERMISSIVE FOR UPDATE TO cephas_retirer USING (state IN ('pending','active')) WITH CHECK (state='retired' AND retired_at IS NOT NULL);
CREATE POLICY manifest_binding_retire_restrictive ON security.scope_binding AS RESTRICTIVE FOR UPDATE TO cephas_retirer USING (state IN ('pending','active')) WITH CHECK (state='retired' AND retired_at IS NOT NULL);
CREATE POLICY manifest_binding_runtime_read ON security.scope_binding AS PERMISSIVE FOR SELECT TO scoped_runtime USING (role_name=SESSION_USER AND state='active' AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=scope_binding.role_name AND r.oid=scope_binding.role_oid AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit));
CREATE POLICY manifest_binding_runtime_invariant ON security.scope_binding AS RESTRICTIVE FOR ALL TO scoped_runtime USING (role_name=SESSION_USER AND state='active' AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=scope_binding.role_name AND r.oid=scope_binding.role_oid AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)) WITH CHECK (false);
DO $policies$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_policy expected
        JOIN pg_class c ON c.oid=expected.polrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_policy actual ON actual.polrelid=expected.polrelid
            AND actual.polname=substring(expected.polname::text FROM 10)
        WHERE n.nspname='security' AND left(expected.polname::text,9)='manifest_'
            AND (actual.oid IS NULL OR actual.polcmd<>expected.polcmd
                OR actual.polpermissive<>expected.polpermissive
                OR actual.polroles<>expected.polroles
                OR pg_get_expr(actual.polqual,actual.polrelid) IS DISTINCT FROM
                   pg_get_expr(expected.polqual,expected.polrelid)
                OR pg_get_expr(actual.polwithcheck,actual.polrelid) IS DISTINCT FROM
                   pg_get_expr(expected.polwithcheck,expected.polrelid))
    ) THEN RAISE EXCEPTION 'registry manifest: policy expression or metadata'; END IF;
END
$policies$;
ROLLBACK;
