-- T-02.2D.1: minimal operational table, disposable PostgreSQL 16 only.
BEGIN;
SET LOCAL search_path = pg_catalog;
DO $guard$
BEGIN
    IF current_database() <> 'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
    THEN RAISE EXCEPTION 'T02 requires disposable PG16 bootstrap'; END IF;
END
$guard$;
SET LOCAL ROLE cephas_owner;
CREATE TABLE ops.scoped_entity (
    tenant_id security.identifier NOT NULL,
    business_unit_id security.identifier NOT NULL,
    entity_id security.identifier NOT NULL,
    payload text NOT NULL,
    PRIMARY KEY (tenant_id,business_unit_id,entity_id),
    FOREIGN KEY (tenant_id,business_unit_id) REFERENCES security.business_unit
);
ALTER TABLE ops.scoped_entity ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.scoped_entity FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, DELETE ON ops.scoped_entity TO scoped_runtime;
GRANT UPDATE (payload) ON ops.scoped_entity TO scoped_runtime;
CREATE POLICY scoped_entity_guard ON ops.scoped_entity AS RESTRICTIVE FOR ALL TO PUBLIC
    USING (COALESCE(
    pg_catalog.char_length(pg_catalog.current_setting('cephas.subject_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.tenant_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.business_unit_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_entity.tenant_id = pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C"
    AND scoped_entity.business_unit_id = pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C"
    AND EXISTS (
        SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name = SESSION_USER AND b.state = 'active'
            AND b.tenant_id = scoped_entity.tenant_id
            AND b.business_unit_id = scoped_entity.business_unit_id
    ), false))
    WITH CHECK (COALESCE(
    pg_catalog.char_length(pg_catalog.current_setting('cephas.subject_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.tenant_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.business_unit_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_entity.tenant_id = pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C"
    AND scoped_entity.business_unit_id = pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C"
    AND EXISTS (
        SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name = SESSION_USER AND b.state = 'active'
            AND b.tenant_id = scoped_entity.tenant_id
            AND b.business_unit_id = scoped_entity.business_unit_id
    ), false));
CREATE POLICY scoped_entity_select ON ops.scoped_entity FOR SELECT TO scoped_runtime
    USING (COALESCE(
    pg_catalog.char_length(pg_catalog.current_setting('cephas.subject_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.tenant_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.business_unit_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_entity.tenant_id = pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C"
    AND scoped_entity.business_unit_id = pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C"
    AND EXISTS (
        SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name = SESSION_USER AND b.state = 'active'
            AND b.tenant_id = scoped_entity.tenant_id
            AND b.business_unit_id = scoped_entity.business_unit_id
    ), false));
CREATE POLICY scoped_entity_insert ON ops.scoped_entity FOR INSERT TO scoped_runtime
    WITH CHECK (COALESCE(
    pg_catalog.char_length(pg_catalog.current_setting('cephas.subject_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.tenant_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.business_unit_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_entity.tenant_id = pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C"
    AND scoped_entity.business_unit_id = pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C"
    AND EXISTS (
        SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name = SESSION_USER AND b.state = 'active'
            AND b.tenant_id = scoped_entity.tenant_id
            AND b.business_unit_id = scoped_entity.business_unit_id
    ), false));
CREATE POLICY scoped_entity_update ON ops.scoped_entity FOR UPDATE TO scoped_runtime
    USING (COALESCE(
    pg_catalog.char_length(pg_catalog.current_setting('cephas.subject_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.tenant_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.business_unit_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_entity.tenant_id = pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C"
    AND scoped_entity.business_unit_id = pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C"
    AND EXISTS (
        SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name = SESSION_USER AND b.state = 'active'
            AND b.tenant_id = scoped_entity.tenant_id
            AND b.business_unit_id = scoped_entity.business_unit_id
    ), false))
    WITH CHECK (COALESCE(
    pg_catalog.char_length(pg_catalog.current_setting('cephas.subject_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.tenant_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.business_unit_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_entity.tenant_id = pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C"
    AND scoped_entity.business_unit_id = pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C"
    AND EXISTS (
        SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name = SESSION_USER AND b.state = 'active'
            AND b.tenant_id = scoped_entity.tenant_id
            AND b.business_unit_id = scoped_entity.business_unit_id
    ), false));
CREATE POLICY scoped_entity_delete ON ops.scoped_entity FOR DELETE TO scoped_runtime
    USING (COALESCE(
    pg_catalog.char_length(pg_catalog.current_setting('cephas.subject_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.subject_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.tenant_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND     pg_catalog.char_length(pg_catalog.current_setting('cephas.business_unit_id', true)) BETWEEN 1 AND 128
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") ~ '^[A-Za-z0-9]'
    AND (pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C") !~ '[^A-Za-z0-9._:-]'
    AND scoped_entity.tenant_id = pg_catalog.current_setting('cephas.tenant_id', true) COLLATE pg_catalog."C"
    AND scoped_entity.business_unit_id = pg_catalog.current_setting('cephas.business_unit_id', true) COLLATE pg_catalog."C"
    AND EXISTS (
        SELECT 1 FROM security.scope_binding AS b
        WHERE b.role_name = SESSION_USER AND b.state = 'active'
            AND b.tenant_id = scoped_entity.tenant_id
            AND b.business_unit_id = scoped_entity.business_unit_id
    ), false));
RESET ROLE;
COMMIT;
