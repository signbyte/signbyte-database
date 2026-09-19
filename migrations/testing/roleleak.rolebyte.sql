-- Role-leak acceptance for the `rolebyte` location: the membership register's EXECUTE-only
-- role reaches tenants, members, roles, assignments and the history ONLY through the
-- SECURITY DEFINER procedures — never a direct table read or write, and never another
-- schema's tables — and the other service roles cannot read the register's tables either.
-- The history table adds the append-only guarantee at the GRANT boundary: even the owner
-- role of the location cannot rewrite or delete an event directly.
--
-- Run as the owner (POSTGRES_USER) against a database that applied `rolebyte` and
-- `identity` (both e-signing shapes, the fabrication platform, the hosted workflow product):
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/roleleak.rolebyte.sql
-- Expected: no ROLE LEAK exception raised (a final PASS row).

-- Reusable assertion: <role> must NOT be able to run <sql>. Raises ROLE LEAK if it
-- succeeds; swallows the expected insufficient_privilege.
CREATE OR REPLACE FUNCTION pg_temp.deny(p_role text, p_sql text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('SET ROLE %I', p_role);
    BEGIN
        EXECUTE p_sql;
        EXECUTE 'RESET ROLE';
        RAISE EXCEPTION 'ROLE LEAK: % could run: %', p_role, p_sql;
    EXCEPTION
        WHEN insufficient_privilege THEN NULL;  -- expected: denied
    END;
    EXECUTE 'RESET ROLE';
END $$;

DO $$
BEGIN
    -- rolebyte (rolebyte_public): procedures only, no table access ----------
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.tenant');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.user_account');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.role_definition');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.assignment');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.event');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.tenant(id, name) VALUES (''x'', ''x'')');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.user_account(id, tenant_id, subject_key, display_name) '
        || 'VALUES (''x'', ''x'', ''svc:x'', ''x'')');
    -- the history is append-only at the grant boundary, even for the register's own role.
    PERFORM pg_temp.deny('rolebyte_public', 'UPDATE rolebyte.event SET kind = ''x''');
    PERFORM pg_temp.deny('rolebyte_public', 'DELETE FROM rolebyte.event');
    -- cross-silo: the register's role cannot read the identity tables ...
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM identity.person');
    -- ... and the identity role cannot read the register's.
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.user_account');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.tenant');
END $$;

SELECT 'ROLELEAK: PASS — the register role is table-isolated, its history is append-only at the grant boundary, and no other service role reads the register' AS result;
