-- T-02.2E.1B: disposable PG16 protected membership change path only.
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
CREATE ROLE cephas_membership_admin LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    NOREPLICATION NOINHERIT CONNECTION LIMIT 1 PASSWORD NULL;
CREATE ROLE cephas_membership_executor NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    NOREPLICATION NOINHERIT;
GRANT CONNECT ON DATABASE cephas_t02_test TO cephas_membership_admin;
SET LOCAL ROLE cephas_owner;
GRANT USAGE ON SCHEMA membership TO cephas_membership_admin,cephas_membership_executor;
GRANT USAGE ON SCHEMA security TO cephas_membership_executor;
GRANT USAGE ON DOMAIN security.identifier TO cephas_membership_executor;
ALTER TABLE membership.subject_scope ADD COLUMN previous_generation uuid UNIQUE;
ALTER TABLE membership.subject_scope DROP CONSTRAINT subject_scope_pkey;
ALTER TABLE membership.subject_scope ADD PRIMARY KEY (subject_id,tenant_id,business_unit_id,generation);
ALTER TABLE membership.subject_scope ADD CONSTRAINT member_previous_fk
    FOREIGN KEY (subject_id,tenant_id,business_unit_id,previous_generation)
    REFERENCES membership.subject_scope (subject_id,tenant_id,business_unit_id,generation);
ALTER TABLE membership.subject_scope ADD CONSTRAINT member_not_self
    CHECK (previous_generation IS DISTINCT FROM generation);
-- Preserve one permanent root and at most one active incarnation per scope.
CREATE UNIQUE INDEX member_root_scope ON membership.subject_scope (subject_id,tenant_id,business_unit_id)
    WHERE previous_generation IS NULL;
CREATE UNIQUE INDEX member_active_scope ON membership.subject_scope (subject_id,tenant_id,business_unit_id)
    WHERE active;
-- Reserve the last revision for deactivation; never strand an active max-revision row.
ALTER TABLE membership.subject_scope ADD CONSTRAINT member_revision_reserve
    CHECK (NOT active OR revision<9223372036854775807);

DROP POLICY member_owner_insert ON membership.subject_scope;
DROP POLICY member_owner_update ON membership.subject_scope;
DROP POLICY audit_owner_insert ON membership.change_audit;
CREATE POLICY member_executor_read ON membership.subject_scope FOR SELECT TO cephas_membership_executor USING (true);
CREATE POLICY member_executor_insert ON membership.subject_scope FOR INSERT TO cephas_membership_executor
    WITH CHECK (active AND revision=1);
CREATE POLICY member_executor_update ON membership.subject_scope FOR UPDATE TO cephas_membership_executor
    USING (active) WITH CHECK (true);
CREATE POLICY audit_executor_insert ON membership.change_audit FOR INSERT TO cephas_membership_executor
    WITH CHECK (actor=SESSION_USER AND SESSION_USER='cephas_membership_admin');
GRANT SELECT ON membership.subject_scope TO cephas_membership_executor;
GRANT INSERT (subject_id,tenant_id,business_unit_id,generation,previous_generation,change_ref)
    ON membership.subject_scope TO cephas_membership_executor;
GRANT UPDATE (active,change_ref) ON membership.subject_scope TO cephas_membership_executor;
GRANT INSERT ON membership.change_audit TO cephas_membership_executor;

CREATE FUNCTION membership.guard_predecessor() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
    IF NEW.previous_generation IS DISTINCT FROM OLD.previous_generation
    THEN RAISE EXCEPTION 'immutable membership predecessor' USING ERRCODE='42501'; END IF;
    RETURN NEW;
END
$fn$;
CREATE TRIGGER member_predecessor_immutable BEFORE UPDATE ON membership.subject_scope
    FOR EACH ROW EXECUTE FUNCTION membership.guard_predecessor();

CREATE FUNCTION membership.enrol(
    p_subject text,p_tenant text,p_unit text,p_generation uuid,
    p_previous uuid,p_expected_revision bigint,p_change text
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
    prior membership.subject_scope%ROWTYPE;
    result bigint;
BEGIN
    IF SESSION_USER<>'cephas_membership_admin' OR pg_is_in_recovery()
        OR current_setting('transaction_isolation')<>'read committed'
        OR p_generation IS NULL OR p_subject IS NULL OR p_tenant IS NULL
        OR p_unit IS NULL OR p_change IS NULL
        OR (p_previous IS NULL)<>(p_expected_revision IS NULL)
        OR p_generation=p_previous
    THEN RAISE EXCEPTION 'membership enrolment denied' USING ERRCODE='42501'; END IF;
    IF p_previous IS NOT NULL THEN
        -- Predecessor is terminal and immutable. Unique successor and active/root indexes
        -- serialize competing inserts even if both read the same predecessor.
        SELECT * INTO prior FROM membership.subject_scope
        WHERE generation=p_previous AND subject_id=p_subject
            AND tenant_id=p_tenant AND business_unit_id=p_unit;
        IF NOT FOUND OR prior.active OR prior.revision IS DISTINCT FROM p_expected_revision
        THEN RAISE EXCEPTION 'membership predecessor denied' USING ERRCODE='42501'; END IF;
        IF EXISTS (SELECT 1 FROM membership.subject_scope WHERE previous_generation=p_previous)
        THEN RAISE EXCEPTION 'membership predecessor already consumed' USING ERRCODE='42501'; END IF;
    END IF;
    INSERT INTO membership.subject_scope
        (subject_id,tenant_id,business_unit_id,generation,previous_generation,change_ref)
    VALUES (p_subject,p_tenant,p_unit,p_generation,p_previous,p_change)
    RETURNING revision INTO result;
    RETURN result;
END
$fn$;

CREATE FUNCTION membership.change_state(
    p_generation uuid,p_expected_revision bigint,p_active boolean,p_change text
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
    result bigint;
BEGIN
    IF SESSION_USER<>'cephas_membership_admin' OR pg_is_in_recovery()
        OR current_setting('transaction_isolation')<>'read committed'
        OR p_generation IS NULL OR p_expected_revision IS NULL
        OR p_expected_revision<=0 OR p_active IS NULL OR p_change IS NULL
        OR (p_active AND p_expected_revision>=9223372036854775806)
    THEN RAISE EXCEPTION 'membership change denied' USING ERRCODE='42501'; END IF;
    UPDATE membership.subject_scope SET active=p_active,change_ref=p_change
    WHERE generation=p_generation AND revision=p_expected_revision AND active
    RETURNING revision INTO result;
    IF NOT FOUND
    THEN RAISE EXCEPTION 'membership change denied' USING ERRCODE='42501'; END IF;
    RETURN result;
END
$fn$;
RESET ROLE;
-- Bootstrap transfers only these two entry points to a restricted non-login principal.
ALTER FUNCTION membership.enrol(text,text,text,uuid,uuid,bigint,text) OWNER TO cephas_membership_executor;
ALTER FUNCTION membership.change_state(uuid,bigint,boolean,text) OWNER TO cephas_membership_executor;
REVOKE ALL ON FUNCTION membership.enrol(text,text,text,uuid,uuid,bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION membership.change_state(uuid,bigint,boolean,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION membership.enrol(text,text,text,uuid,uuid,bigint,text) TO cephas_membership_admin;
GRANT EXECUTE ON FUNCTION membership.change_state(uuid,bigint,boolean,text) TO cephas_membership_admin;
COMMIT;
