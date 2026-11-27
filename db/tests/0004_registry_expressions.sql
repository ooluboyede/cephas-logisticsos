-- Fixed expected registry CHECK and partial-index predicates. Disposable PG16 only.
BEGIN;
SET LOCAL search_path=pg_catalog;
DO $guard$
BEGIN
    IF current_database()<>'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
    THEN RAISE EXCEPTION 'expanded manifest: environment'; END IF;
END
$guard$;
-- Compile expected expressions on their actual relations and compare normalized multisets.
ALTER TABLE security.binding_approval ADD CONSTRAINT manifest_deploy CHECK (deployment_id='t02-test-deployment') NOT VALID;
ALTER TABLE security.binding_approval ADD CONSTRAINT manifest_digest CHECK (char_length(approval_evidence_sha256)=64 AND approval_evidence_sha256 !~ '[^0-9a-f]') NOT VALID;
ALTER TABLE security.binding_approval ADD CONSTRAINT manifest_subject CHECK (approver_subject<>second_approver_subject) NOT VALID;
ALTER TABLE security.binding_approval ADD CONSTRAINT manifest_expiry CHECK (expires_at>approved_at) NOT VALID;
ALTER TABLE security.role_issuance ADD CONSTRAINT manifest_deploy CHECK (deployment_id='t02-test-deployment') NOT VALID;
ALTER TABLE security.scope_binding ADD CONSTRAINT manifest_state CHECK (state IN ('pending','active','retired')) NOT VALID;
ALTER TABLE security.scope_binding ADD CONSTRAINT manifest_retirement CHECK ((state='retired')=(retired_at IS NOT NULL)) NOT VALID;
DO $checks$
DECLARE
    target regclass;
    expected text[];
    actual text[];
BEGIN
    FOR target IN SELECT unnest(ARRAY['security.binding_approval'::regclass,
        'security.role_issuance'::regclass,'security.scope_binding'::regclass,
        'security.tenant'::regclass,'security.business_unit'::regclass]) LOOP
        SELECT array_agg(pg_get_expr(conbin,conrelid) ORDER BY pg_get_expr(conbin,conrelid) COLLATE "C")
            INTO expected FROM pg_constraint WHERE conrelid=target AND contype='c'
            AND left(conname::text,9)='manifest_';
        SELECT array_agg(pg_get_expr(conbin,conrelid) ORDER BY pg_get_expr(conbin,conrelid) COLLATE "C")
            INTO actual FROM pg_constraint WHERE conrelid=target AND contype='c'
            AND left(conname::text,9)<>'manifest_';
        IF actual IS DISTINCT FROM expected
        THEN RAISE EXCEPTION 'expanded manifest: registry CHECK expressions'; END IF;
    END LOOP;
END
$checks$;
CREATE UNIQUE INDEX manifest_scope_idx ON security.scope_binding (tenant_id,business_unit_id)
    WHERE state IN ('pending','active');
CREATE UNIQUE INDEX manifest_oid_idx ON security.scope_binding (role_oid)
    WHERE state IN ('pending','active');
DO $indexes$
DECLARE
    pair record;
BEGIN
    FOR pair IN SELECT * FROM (VALUES
        ('security.scope_binding_live_scope'::regclass,'security.manifest_scope_idx'::regclass),
        ('security.scope_binding_live_oid'::regclass,'security.manifest_oid_idx'::regclass)
    ) AS pairs(actual,expected) LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_index a CROSS JOIN pg_index e
            WHERE a.indexrelid=pair.actual AND e.indexrelid=pair.expected
            AND a.indrelid=e.indrelid AND a.indkey=e.indkey
            AND a.indisunique AND a.indisvalid AND a.indisready AND a.indislive
            AND a.indnkeyatts=e.indnkeyatts AND a.indnatts=e.indnatts
            AND a.indclass=e.indclass AND a.indcollation=e.indcollation
            AND a.indoption=e.indoption AND a.indexprs IS NULL
            AND pg_get_expr(a.indpred,a.indrelid) IS NOT DISTINCT FROM pg_get_expr(e.indpred,e.indrelid))
        THEN RAISE EXCEPTION 'expanded manifest: partial-index predicate'; END IF;
    END LOOP;
END
$indexes$;
ROLLBACK;
