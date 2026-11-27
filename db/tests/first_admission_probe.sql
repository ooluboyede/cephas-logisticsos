-- Disposable privileged first-admission probe, not a runtime authorization function.
-- Run in a fresh connection to the known test primary, with exact externally supplied tuple.
-- True is necessary, NOT sufficient for route admission (ledger, approval authenticity,
-- infrastructure fencing and atomic enable-time comparison remain outside this probe).
SELECT count(*) = 1
FROM security.scope_binding AS b
JOIN security.role_issuance AS i
    ON (i.role_name,i.role_oid,i.generation,i.tenant_id,i.business_unit_id)
     = (b.role_name,b.role_oid,b.generation,b.tenant_id,b.business_unit_id)
JOIN security.binding_approval AS a
    ON (a.approval_id,a.deployment_id,a.role_name,a.role_oid,a.generation,a.tenant_id,a.business_unit_id)
     = (i.approval_id,i.deployment_id,i.role_name,i.role_oid,i.generation,i.tenant_id,i.business_unit_id)
JOIN pg_catalog.pg_roles AS r ON r.oid=b.role_oid AND r.rolname=b.role_name
JOIN pg_catalog.pg_roles AS g ON g.rolname='scoped_runtime'
WHERE current_database()='cephas_t02_test'
    AND current_setting('server_version_num')::integer BETWEEN 160000 AND 169999
    AND current_setting('transaction_isolation')='read committed'
    AND NOT pg_catalog.pg_is_in_recovery()
    AND a.deployment_id=:'deployment'
    AND b.role_name=:'role_name'
    AND b.role_oid=:'role_oid'::oid
    AND b.generation=:'generation'::uuid
    AND b.tenant_id=:'tenant'
    AND b.business_unit_id=:'unit'
    AND a.approval_id=:'approval_id'::uuid
    AND a.approval_evidence_sha256=:'evidence_sha256'
    AND b.state='active'
    AND a.approved_at<=clock_timestamp() AND a.expires_at>clock_timestamp()
    AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
    AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication
    AND NOT r.rolinherit AND r.rolconnlimit=4
    AND NOT g.rolcanlogin AND NOT g.rolsuper AND NOT g.rolbypassrls
    AND NOT g.rolcreatedb AND NOT g.rolcreaterole AND NOT g.rolreplication AND NOT g.rolinherit
    AND (SELECT count(*) FROM pg_catalog.pg_auth_members AS m WHERE m.member=r.oid)=1
    AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS m
                WHERE m.member=r.oid AND m.roleid=g.oid
                    AND m.inherit_option AND NOT m.set_option AND NOT m.admin_option)
    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS m WHERE m.member=g.oid)
    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS m WHERE m.roleid=r.oid);
