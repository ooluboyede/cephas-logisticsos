-- Test-only fixture; never run as a customer provisioning operation.
BEGIN;
SET LOCAL search_path = pg_catalog;
SET LOCAL password_encryption = 'scram-sha-256';
ALTER ROLE cephas_registry_admin PASSWORD :'pw_registry';
ALTER ROLE cephas_migration PASSWORD :'pw_migration';
CREATE ROLE cephas_test_scope_a1 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4 PASSWORD :'pw_a1';
CREATE ROLE cephas_test_scope_a2 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4 PASSWORD :'pw_a2';
CREATE ROLE cephas_test_scope_b1 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT CONNECTION LIMIT 4 PASSWORD :'pw_b1';
GRANT scoped_runtime TO cephas_test_scope_a1, cephas_test_scope_a2, cephas_test_scope_b1 WITH SET FALSE;
GRANT scoped_runtime TO cephas_test_scope_a1, cephas_test_scope_a2, cephas_test_scope_b1 WITH INHERIT TRUE;
GRANT scoped_runtime TO cephas_test_scope_a1, cephas_test_scope_a2, cephas_test_scope_b1 WITH ADMIN FALSE;
COMMIT;
