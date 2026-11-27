-- T-02.2B / 0001: disposable engineering cluster only, never production.
-- Run with psql -X -v ON_ERROR_STOP=1 as the isolated bootstrap administrator.
BEGIN;
SET LOCAL search_path = pg_catalog;
DO $guard$
BEGIN
    IF current_database() <> 'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper)
    THEN
        RAISE EXCEPTION 'T02 requires a disposable PG16 cephas_t02_test database and bootstrap administrator';
    END IF;
END
$guard$;

CREATE ROLE cephas_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
CREATE ROLE scoped_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
CREATE ROLE cephas_migration LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4 PASSWORD NULL;
CREATE ROLE cephas_membership LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 8 PASSWORD NULL;
CREATE ROLE cephas_registry_admin LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 1 PASSWORD NULL;
CREATE ROLE cephas_approver LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 1 PASSWORD NULL;
CREATE ROLE cephas_issuer LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 1 PASSWORD NULL;
CREATE ROLE cephas_activator LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 1 PASSWORD NULL;
CREATE ROLE cephas_retirer LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 1 PASSWORD NULL;

GRANT cephas_owner TO cephas_migration WITH INHERIT FALSE;
GRANT cephas_owner TO cephas_migration WITH SET TRUE;
GRANT cephas_owner TO cephas_migration WITH ADMIN FALSE;

REVOKE ALL ON DATABASE cephas_t02_test FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE cephas_t02_test TO scoped_runtime, cephas_migration,
    cephas_membership, cephas_registry_admin, cephas_approver, cephas_issuer,
    cephas_activator, cephas_retirer;

CREATE SCHEMA security AUTHORIZATION cephas_owner;
CREATE SCHEMA ops AUTHORIZATION cephas_owner;
CREATE SCHEMA membership AUTHORIZATION cephas_owner;
SET LOCAL ROLE cephas_owner;
SET LOCAL search_path = pg_catalog;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE USAGE ON TYPES FROM PUBLIC;
REVOKE ALL ON SCHEMA security, ops, membership FROM PUBLIC;
GRANT USAGE ON SCHEMA security TO scoped_runtime, cephas_registry_admin,
    cephas_approver, cephas_issuer, cephas_activator, cephas_retirer;
GRANT USAGE ON SCHEMA ops TO scoped_runtime;
GRANT USAGE ON SCHEMA membership TO cephas_membership;

CREATE DOMAIN security.identifier AS text COLLATE pg_catalog."C"
    CHECK (char_length(VALUE) BETWEEN 1 AND 128
        AND VALUE ~ '^[A-Za-z0-9]'
        AND VALUE !~ '[^A-Za-z0-9._:-]');
GRANT USAGE ON DOMAIN security.identifier TO cephas_registry_admin,
    cephas_approver, cephas_issuer, cephas_activator, cephas_retirer, scoped_runtime;
CREATE TABLE security.tenant (
    tenant_id security.identifier PRIMARY KEY
);
CREATE TABLE security.business_unit (
    tenant_id security.identifier NOT NULL,
    business_unit_id security.identifier NOT NULL,
    PRIMARY KEY (tenant_id, business_unit_id),
    FOREIGN KEY (tenant_id) REFERENCES security.tenant (tenant_id)
);
ALTER TABLE security.tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.tenant FORCE ROW LEVEL SECURITY;
ALTER TABLE security.business_unit ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.business_unit FORCE ROW LEVEL SECURITY;
CREATE POLICY registry_admin_select ON security.tenant
    FOR SELECT TO cephas_registry_admin USING (true);
CREATE POLICY registry_admin_insert ON security.tenant
    FOR INSERT TO cephas_registry_admin WITH CHECK (true);
CREATE POLICY registry_admin_select ON security.business_unit
    FOR SELECT TO cephas_registry_admin USING (true);
CREATE POLICY registry_admin_insert ON security.business_unit
    FOR INSERT TO cephas_registry_admin WITH CHECK (true);
GRANT SELECT, INSERT ON security.tenant, security.business_unit TO cephas_registry_admin;
-- No scoped operational tables, bindings, lifecycle grants or runtime data access yet.
RESET ROLE;
COMMIT;
