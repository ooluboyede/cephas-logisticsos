-- T-02.2E.1A: disposable PG16 membership registry, not production identity integration.
BEGIN;
SET LOCAL search_path=pg_catalog;
DO $guard$
BEGIN
    IF current_database()<>'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
    THEN RAISE EXCEPTION 'T02 requires disposable PG16 bootstrap'; END IF;
END
$guard$;
SET LOCAL ROLE cephas_owner;
CREATE TABLE membership.subject_scope (
    subject_id security.identifier NOT NULL,
    tenant_id security.identifier NOT NULL,
    business_unit_id security.identifier NOT NULL,
    generation uuid NOT NULL UNIQUE,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
    active boolean NOT NULL DEFAULT true,
    change_ref security.identifier NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (subject_id,tenant_id,business_unit_id),
    FOREIGN KEY (tenant_id,business_unit_id) REFERENCES security.business_unit
);
CREATE TABLE membership.change_audit (
    generation uuid NOT NULL REFERENCES membership.subject_scope(generation),
    revision bigint NOT NULL CHECK (revision>0),
    subject_id security.identifier NOT NULL,
    tenant_id security.identifier NOT NULL,
    business_unit_id security.identifier NOT NULL,
    active boolean NOT NULL,
    change_ref security.identifier NOT NULL UNIQUE,
    actor name NOT NULL,
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (generation,revision)
);
ALTER TABLE membership.subject_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE membership.subject_scope FORCE ROW LEVEL SECURITY;
ALTER TABLE membership.change_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE membership.change_audit FORCE ROW LEVEL SECURITY;
-- Initial controlled administrative path: migration login SET ROLE owner.
-- No new independently authenticated administrative login or SECURITY DEFINER routine.
CREATE POLICY member_owner_read ON membership.subject_scope FOR SELECT TO cephas_owner USING (true);
CREATE POLICY member_owner_insert ON membership.subject_scope FOR INSERT TO cephas_owner WITH CHECK (true);
CREATE POLICY member_owner_update ON membership.subject_scope FOR UPDATE TO cephas_owner USING (true) WITH CHECK (true);
CREATE POLICY member_lookup ON membership.subject_scope FOR SELECT TO cephas_membership USING (true);
CREATE POLICY audit_owner_read ON membership.change_audit FOR SELECT TO cephas_owner USING (true);
CREATE POLICY audit_owner_insert ON membership.change_audit FOR INSERT TO cephas_owner WITH CHECK (true);
GRANT SELECT (subject_id,tenant_id,business_unit_id,generation,revision,active)
    ON membership.subject_scope TO cephas_membership;

CREATE FUNCTION membership.guard_subject_scope() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.active IS DISTINCT FROM true
        THEN RAISE EXCEPTION 'invalid initial membership' USING ERRCODE='42501'; END IF;
    ELSIF TG_OP='UPDATE' THEN
        IF ROW(NEW.subject_id,NEW.tenant_id,NEW.business_unit_id,NEW.generation)
            IS DISTINCT FROM ROW(OLD.subject_id,OLD.tenant_id,OLD.business_unit_id,OLD.generation)
            OR NEW.revision IS DISTINCT FROM OLD.revision
            OR NEW.changed_at IS DISTINCT FROM OLD.changed_at
            OR NEW.change_ref=OLD.change_ref
            OR NOT OLD.active
            OR OLD.revision=9223372036854775807
        THEN RAISE EXCEPTION 'invalid membership transition' USING ERRCODE='42501'; END IF;
        NEW.revision := OLD.revision+1;
    ELSE
        RAISE EXCEPTION 'membership removal prohibited' USING ERRCODE='42501';
    END IF;
    NEW.changed_at := statement_timestamp();
    RETURN NEW;
END
$fn$;
CREATE FUNCTION membership.record_change() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
    INSERT INTO membership.change_audit
        (generation,revision,subject_id,tenant_id,business_unit_id,active,change_ref,actor,changed_at)
    VALUES (NEW.generation,NEW.revision,NEW.subject_id,NEW.tenant_id,NEW.business_unit_id,
        NEW.active,NEW.change_ref,SESSION_USER,NEW.changed_at);
    RETURN NEW;
END
$fn$;
CREATE FUNCTION membership.reject_removal() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
    RAISE EXCEPTION 'immutable membership audit or removal' USING ERRCODE='42501';
END
$fn$;
CREATE TRIGGER member_transition BEFORE INSERT OR UPDATE OR DELETE ON membership.subject_scope
    FOR EACH ROW EXECUTE FUNCTION membership.guard_subject_scope();
CREATE TRIGGER member_audit AFTER INSERT OR UPDATE ON membership.subject_scope
    FOR EACH ROW EXECUTE FUNCTION membership.record_change();
CREATE TRIGGER member_no_truncate BEFORE TRUNCATE ON membership.subject_scope
    FOR EACH STATEMENT EXECUTE FUNCTION membership.reject_removal();
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON membership.change_audit
    FOR EACH ROW EXECUTE FUNCTION membership.reject_removal();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON membership.change_audit
    FOR EACH STATEMENT EXECUTE FUNCTION membership.reject_removal();
RESET ROLE;
COMMIT;
