-- T-02.2C: registry database component only. Disposable PG16 fixture.
BEGIN;
SET LOCAL search_path = pg_catalog;
DO $guard$
BEGIN
    IF current_database() <> 'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper)
    THEN RAISE EXCEPTION 'T02 requires disposable PG16 bootstrap'; END IF;
END
$guard$;
SET LOCAL ROLE cephas_owner;
CREATE TABLE security.binding_approval (
    approval_id uuid PRIMARY KEY,
    deployment_id security.identifier NOT NULL CHECK (deployment_id = 't02-test-deployment'),
    role_name name NOT NULL UNIQUE,
    role_oid oid NOT NULL,
    generation uuid NOT NULL UNIQUE,
    tenant_id security.identifier NOT NULL,
    business_unit_id security.identifier NOT NULL,
    approver_subject security.identifier NOT NULL,
    second_approver_subject security.identifier NOT NULL,
    change_ref security.identifier NOT NULL UNIQUE,
    approval_evidence_sha256 text COLLATE pg_catalog."C" NOT NULL
        CHECK (char_length(approval_evidence_sha256)=64 AND approval_evidence_sha256 !~ '[^0-9a-f]'),
    approved_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (approver_subject <> second_approver_subject),
    CHECK (expires_at > approved_at),
    FOREIGN KEY (tenant_id,business_unit_id) REFERENCES security.business_unit,
    UNIQUE (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id)
);
CREATE TABLE security.role_issuance (
    role_name name PRIMARY KEY,
    generation uuid NOT NULL UNIQUE,
    role_oid oid NOT NULL,
    approval_id uuid NOT NULL UNIQUE,
    deployment_id security.identifier NOT NULL CHECK (deployment_id = 't02-test-deployment'),
    tenant_id security.identifier NOT NULL,
    business_unit_id security.identifier NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    FOREIGN KEY (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id)
        REFERENCES security.binding_approval
        (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id),
    UNIQUE (role_name,role_oid,generation,tenant_id,business_unit_id)
);
CREATE TABLE security.scope_binding (
    role_name name PRIMARY KEY,
    role_oid oid NOT NULL,
    generation uuid NOT NULL UNIQUE,
    tenant_id security.identifier NOT NULL,
    business_unit_id security.identifier NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','active','retired')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    retired_at timestamptz,
    CHECK ((state='retired') = (retired_at IS NOT NULL)),
    FOREIGN KEY (role_name,role_oid,generation,tenant_id,business_unit_id)
        REFERENCES security.role_issuance (role_name,role_oid,generation,tenant_id,business_unit_id),
    FOREIGN KEY (tenant_id,business_unit_id) REFERENCES security.business_unit
);
CREATE UNIQUE INDEX scope_binding_live_scope ON security.scope_binding (tenant_id,business_unit_id)
    WHERE state IN ('pending','active');
CREATE UNIQUE INDEX scope_binding_live_oid ON security.scope_binding (role_oid)
    WHERE state IN ('pending','active');

CREATE FUNCTION security.reject_registry_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
    RAISE EXCEPTION 'immutable registry record' USING ERRCODE='42501';
END
$fn$;
CREATE FUNCTION security.guard_binding_update() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
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
$fn$;
CREATE TRIGGER approval_immutable BEFORE UPDATE OR DELETE ON security.binding_approval
    FOR EACH ROW EXECUTE FUNCTION security.reject_registry_mutation();
CREATE TRIGGER issuance_immutable BEFORE UPDATE OR DELETE ON security.role_issuance
    FOR EACH ROW EXECUTE FUNCTION security.reject_registry_mutation();
CREATE TRIGGER binding_transition BEFORE UPDATE OR DELETE ON security.scope_binding
    FOR EACH ROW EXECUTE FUNCTION security.guard_binding_update();
CREATE TRIGGER approval_no_truncate BEFORE TRUNCATE ON security.binding_approval
    FOR EACH STATEMENT EXECUTE FUNCTION security.reject_registry_mutation();
CREATE TRIGGER issuance_no_truncate BEFORE TRUNCATE ON security.role_issuance
    FOR EACH STATEMENT EXECUTE FUNCTION security.reject_registry_mutation();
CREATE TRIGGER binding_no_truncate BEFORE TRUNCATE ON security.scope_binding
    FOR EACH STATEMENT EXECUTE FUNCTION security.reject_registry_mutation();
ALTER TABLE security.binding_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.binding_approval FORCE ROW LEVEL SECURITY;
ALTER TABLE security.role_issuance ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.role_issuance FORCE ROW LEVEL SECURITY;
ALTER TABLE security.scope_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.scope_binding FORCE ROW LEVEL SECURITY;

GRANT INSERT (approval_id,deployment_id,role_name,role_oid,generation,tenant_id,business_unit_id,
    approver_subject,second_approver_subject,change_ref,approval_evidence_sha256,expires_at)
    ON security.binding_approval TO cephas_approver;
GRANT SELECT ON security.binding_approval TO cephas_issuer,cephas_activator;
GRANT INSERT (role_name,generation,role_oid,approval_id,deployment_id,tenant_id,business_unit_id)
    ON security.role_issuance TO cephas_issuer;
GRANT SELECT ON security.role_issuance TO cephas_issuer,cephas_activator;
GRANT INSERT (role_name,role_oid,generation,tenant_id,business_unit_id)
    ON security.scope_binding TO cephas_issuer;
GRANT SELECT ON security.scope_binding TO cephas_issuer,cephas_activator,cephas_retirer;
GRANT UPDATE (state) ON security.scope_binding TO cephas_activator,cephas_retirer;
GRANT SELECT (role_name,role_oid,tenant_id,business_unit_id,state)
    ON security.scope_binding TO scoped_runtime;
CREATE POLICY approval_read ON security.binding_approval FOR SELECT TO cephas_issuer,cephas_activator USING (true);
CREATE POLICY issuance_read ON security.role_issuance FOR SELECT TO cephas_issuer,cephas_activator USING (true);
CREATE POLICY binding_control_read ON security.scope_binding FOR SELECT TO cephas_issuer,cephas_activator,cephas_retirer USING (true);
CREATE POLICY approval_create_permissive ON security.binding_approval AS PERMISSIVE FOR INSERT TO cephas_approver WITH CHECK (binding_approval.deployment_id='t02-test-deployment' AND binding_approval.approved_at<=statement_timestamp() AND binding_approval.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=binding_approval.role_name AND r.oid=binding_approval.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit));
CREATE POLICY approval_create_restrictive ON security.binding_approval AS RESTRICTIVE FOR INSERT TO cephas_approver WITH CHECK (binding_approval.deployment_id='t02-test-deployment' AND binding_approval.approved_at<=statement_timestamp() AND binding_approval.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=binding_approval.role_name AND r.oid=binding_approval.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit));
CREATE POLICY issuance_create_permissive ON security.role_issuance AS PERMISSIVE FOR INSERT TO cephas_issuer WITH CHECK (EXISTS (SELECT 1 FROM security.binding_approval AS a WHERE a.approval_id=role_issuance.approval_id AND a.deployment_id=role_issuance.deployment_id AND a.role_name=role_issuance.role_name AND a.role_oid=role_issuance.role_oid AND a.generation=role_issuance.generation AND a.tenant_id=role_issuance.tenant_id AND a.business_unit_id=role_issuance.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY issuance_create_restrictive ON security.role_issuance AS RESTRICTIVE FOR INSERT TO cephas_issuer WITH CHECK (EXISTS (SELECT 1 FROM security.binding_approval AS a WHERE a.approval_id=role_issuance.approval_id AND a.deployment_id=role_issuance.deployment_id AND a.role_name=role_issuance.role_name AND a.role_oid=role_issuance.role_oid AND a.generation=role_issuance.generation AND a.tenant_id=role_issuance.tenant_id AND a.business_unit_id=role_issuance.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY binding_create_permissive ON security.scope_binding AS PERMISSIVE FOR INSERT TO cephas_issuer WITH CHECK (state='pending' AND retired_at IS NULL AND EXISTS (SELECT 1 FROM security.role_issuance AS i JOIN security.binding_approval AS a ON a.approval_id=i.approval_id AND a.deployment_id=i.deployment_id AND a.role_name=i.role_name AND a.role_oid=i.role_oid AND a.generation=i.generation AND a.tenant_id=i.tenant_id AND a.business_unit_id=i.business_unit_id WHERE i.role_name=scope_binding.role_name AND i.role_oid=scope_binding.role_oid AND i.generation=scope_binding.generation AND i.tenant_id=scope_binding.tenant_id AND i.business_unit_id=scope_binding.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY binding_create_restrictive ON security.scope_binding AS RESTRICTIVE FOR INSERT TO cephas_issuer WITH CHECK (state='pending' AND retired_at IS NULL AND EXISTS (SELECT 1 FROM security.role_issuance AS i JOIN security.binding_approval AS a ON a.approval_id=i.approval_id AND a.deployment_id=i.deployment_id AND a.role_name=i.role_name AND a.role_oid=i.role_oid AND a.generation=i.generation AND a.tenant_id=i.tenant_id AND a.business_unit_id=i.business_unit_id WHERE i.role_name=scope_binding.role_name AND i.role_oid=scope_binding.role_oid AND i.generation=scope_binding.generation AND i.tenant_id=scope_binding.tenant_id AND i.business_unit_id=scope_binding.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY binding_activate_permissive ON security.scope_binding AS PERMISSIVE FOR UPDATE TO cephas_activator USING (state='pending') WITH CHECK (state='active' AND retired_at IS NULL AND EXISTS (SELECT 1 FROM security.role_issuance AS i JOIN security.binding_approval AS a ON a.approval_id=i.approval_id AND a.deployment_id=i.deployment_id AND a.role_name=i.role_name AND a.role_oid=i.role_oid AND a.generation=i.generation AND a.tenant_id=i.tenant_id AND a.business_unit_id=i.business_unit_id WHERE i.role_name=scope_binding.role_name AND i.role_oid=scope_binding.role_oid AND i.generation=scope_binding.generation AND i.tenant_id=scope_binding.tenant_id AND i.business_unit_id=scope_binding.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY binding_activate_restrictive ON security.scope_binding AS RESTRICTIVE FOR UPDATE TO cephas_activator USING (state='pending') WITH CHECK (state='active' AND retired_at IS NULL AND EXISTS (SELECT 1 FROM security.role_issuance AS i JOIN security.binding_approval AS a ON a.approval_id=i.approval_id AND a.deployment_id=i.deployment_id AND a.role_name=i.role_name AND a.role_oid=i.role_oid AND a.generation=i.generation AND a.tenant_id=i.tenant_id AND a.business_unit_id=i.business_unit_id WHERE i.role_name=scope_binding.role_name AND i.role_oid=scope_binding.role_oid AND i.generation=scope_binding.generation AND i.tenant_id=scope_binding.tenant_id AND i.business_unit_id=scope_binding.business_unit_id AND a.deployment_id='t02-test-deployment' AND a.approved_at<=statement_timestamp() AND a.expires_at>statement_timestamp() AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=a.role_name AND r.oid=a.role_oid AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)));
CREATE POLICY binding_retire_permissive ON security.scope_binding AS PERMISSIVE FOR UPDATE TO cephas_retirer USING (state IN ('pending','active')) WITH CHECK (state='retired' AND retired_at IS NOT NULL);
CREATE POLICY binding_retire_restrictive ON security.scope_binding AS RESTRICTIVE FOR UPDATE TO cephas_retirer USING (state IN ('pending','active')) WITH CHECK (state='retired' AND retired_at IS NOT NULL);
CREATE POLICY binding_runtime_read ON security.scope_binding FOR SELECT TO scoped_runtime USING (role_name=SESSION_USER AND state='active' AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=scope_binding.role_name AND r.oid=scope_binding.role_oid AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit));
CREATE POLICY binding_runtime_invariant ON security.scope_binding AS RESTRICTIVE FOR ALL TO scoped_runtime USING (role_name=SESSION_USER AND state='active' AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname=scope_binding.role_name AND r.oid=scope_binding.role_oid AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolinherit)) WITH CHECK (false);
RESET ROLE;
COMMIT;
