-- Role-leak acceptance for the `rolebyte` location: the membership register's EXECUTE-only
-- role reaches tenants, members, roles, assignments, a person's own language and the history ONLY through the
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
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.service_permission');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.tenant_role');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.tenant_role_permission');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.tenant_role_assignment');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.user_type');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.user_type_permission');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.user_type(id, tenant_id, name) VALUES (''x'', ''x'', ''x'')');
    PERFORM pg_temp.deny('rolebyte_public', 'UPDATE rolebyte.user_account SET user_type_id = NULL');
    -- the roles a tenant opens with are created only by the procedures that open one.
    -- Calling it would fail on the tables anyway, so the grant itself is what is checked.
    IF has_function_privilege('rolebyte_public', 'rolebyte.seed_roles(text, text, text)', 'EXECUTE') THEN
        RAISE EXCEPTION 'ROLE LEAK: rolebyte_public may run rolebyte.seed_roles';
    END IF;
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.tenant(id, name) VALUES (''x'', ''x'')');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.tenant_role(id, tenant_id, name) VALUES (''x'', ''x'', ''x'')');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.tenant_role_assignment(id, tenant_id, user_id, tenant_role_id) '
        || 'VALUES (''x'', ''x'', ''x'', ''x'')');
    PERFORM pg_temp.deny('rolebyte_public', 'DELETE FROM rolebyte.tenant_role_permission');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.service_permission(id, service_key, feature_key, act, class) '
        || 'VALUES (''x'', ''x'', ''x'', ''x'', ''ordinary'')');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.user_account(id, tenant_id, subject_key, display_name) '
        || 'VALUES (''x'', ''x'', ''svc:x'', ''x'')');
    -- the deployment's list of services, their roles and their permissions is
    -- the deployment's to write: the register's own role runs none of the acts
    -- that write it directly, so no request a tenant can make reaches them. The one
    -- exception is a service's declaration of itself, which the register's role runs
    -- and which is checked further down.
    IF has_function_privilege('rolebyte_public', 'rolebyte.service_register(jsonb, jsonb)', 'EXECUTE')
       OR has_function_privilege('rolebyte_public', 'rolebyte.role_define(jsonb, jsonb)', 'EXECUTE')
       OR has_function_privilege('rolebyte_public', 'rolebyte.permission_declare(jsonb, jsonb)', 'EXECUTE')
       OR has_function_privilege('rolebyte_public', 'rolebyte.permissions_register(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'ROLE LEAK: rolebyte_public may write the deployment''s list of services';
    END IF;
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.service_register(''{"actor":"x","service":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.role_define(''{"actor":"x","service":"x","group":"x","level":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.permission_declare(''{"actor":"x","service":"x","permission":{}}''::jsonb, NULL::jsonb)');
    -- a service's own declaration of itself is the one registration the register's
    -- role runs, for a request a service makes; no other service's role runs it, and
    -- nobody reads or writes the table of declarations directly.
    IF NOT has_function_privilege('rolebyte_public', 'rolebyte.service_declare(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'the register''s role must run rolebyte.service_declare';
    END IF;
    IF has_function_privilege('authbyte_public', 'rolebyte.service_declare(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'ROLE LEAK: another service''s role may run rolebyte.service_declare';
    END IF;
    PERFORM pg_temp.deny('authbyte_public',
        'CALL rolebyte.service_declare(''{"actor":"svc:x","allowed":[],"section":{"services":[]}}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.service_declaration');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.service_declaration(service_key, declared_by) VALUES (''x'', ''svc:x'')');
    PERFORM pg_temp.deny('rolebyte_public', 'UPDATE rolebyte.service_declaration SET last_declared_at = now()');
    PERFORM pg_temp.deny('rolebyte_public', 'DELETE FROM rolebyte.service_declaration');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.service_declaration');
    -- what a workspace is, its members may read.
    IF NOT has_function_privilege('rolebyte_public', 'rolebyte.tenant_get(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'the register''s role must run rolebyte.tenant_get';
    END IF;
    -- a person's own language: read and set through its two procedures only, which
    -- the register's role runs and no other role does (nothing is left to PUBLIC).
    IF NOT has_function_privilege('rolebyte_public', 'rolebyte.person_language_get(jsonb, jsonb)', 'EXECUTE')
       OR NOT has_function_privilege('rolebyte_public', 'rolebyte.person_language_set(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'the register''s role must run rolebyte.person_language_get and rolebyte.person_language_set';
    END IF;
    IF has_function_privilege('authbyte_public', 'rolebyte.person_language_get(jsonb, jsonb)', 'EXECUTE')
       OR has_function_privilege('authbyte_public', 'rolebyte.person_language_set(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'ROLE LEAK: another service''s role may run a person''s language procedures';
    END IF;
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.person_setting');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.person_setting(subject_key, language) VALUES (''sub:x'', ''en'')');
    PERFORM pg_temp.deny('rolebyte_public', 'UPDATE rolebyte.person_setting SET language = NULL');
    PERFORM pg_temp.deny('rolebyte_public', 'DELETE FROM rolebyte.person_setting');
    -- what a tenant has is the operator's to write: the register's own role can neither
    -- read nor write the table, nor run the procedures that do.
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.tenant_entitlement');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.tenant_entitlement(id, tenant_id, service_key) VALUES (''x'', ''x'', ''x'')');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.entitlement_grant(''{"actor":"x","tenantId":"x","service":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.entitlement_revoke(''{"actor":"x","tenantId":"x","service":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.entitlement_list(''{"tenantId":"x"}''::jsonb, NULL::jsonb)');
    -- who administers a tenant is the operator's way back: the register's own role can
    -- run none of those acts, nor read or write the remembered seed. Only the seed
    -- itself, applied from the service's own environment, is the service's to run.
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.tenant_open(''{"actor":"x","name":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.tenant_seed_roles(''{"actor":"x","tenantId":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.administrator_set(''{"actor":"x","tenantId":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.administrator_unset(''{"actor":"x","tenantId":"x","userId":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.tenant_overview(''{}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.administrator_seed');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.administrator_seed(tenant_id, subject_key) VALUES (''x'', ''x'')');
    -- the history is append-only at the grant boundary, even for the register's own role.
    PERFORM pg_temp.deny('rolebyte_public', 'UPDATE rolebyte.event SET kind = ''x''');
    PERFORM pg_temp.deny('rolebyte_public', 'DELETE FROM rolebyte.event');
    -- cross-silo: the register's role cannot read the identity tables ...
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM identity.person');
    -- ... and the identity role cannot read the register's.
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.user_account');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.tenant');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.service_permission');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.tenant_role');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.tenant_role_assignment');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.tenant_entitlement');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.administrator_seed');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.user_type');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.person_setting');
END $$;

SELECT 'ROLELEAK: PASS — the register role is table-isolated, its history is append-only at the grant boundary, and no other service role reads the register' AS result;

-- The one-time bootstrap door runs as the register's own role and puts the
-- register's own rung on the list — and nothing a caller names with it.
DO $$
DECLARE
    v jsonb;
BEGIN
    SET ROLE rolebyte_public;
    CALL rolebyte.own_rung_register('{"actor":"door","service":"intruder","group":"intruder","level":"admin"}'::jsonb, v);
    RESET ROLE;
    IF v->>'result' IS DISTINCT FROM 'success'
       OR NOT EXISTS (SELECT 1 FROM rolebyte.role_definition
                       WHERE service_key = 'rolebyte' AND role_group = 'membership' AND role_level = 'admin')
       OR EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'intruder')
       OR EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE role_group = 'intruder') THEN
        RAISE EXCEPTION 'ROLE LEAK: own_rung_register wrote more than the register''s own rung: %', v;
    END IF;
    RAISE NOTICE 'roleleak.rolebyte: the door''s own rung, and nothing else';
END $$;

-- A service's declaration runs as the register's own role and writes only the keys
-- the caller was granted: a key outside the list is refused and nothing is written.
DO $$
DECLARE
    v      jsonb;
    before bigint;
BEGIN
    SELECT (SELECT count(*) FROM rolebyte.service) + (SELECT count(*) FROM rolebyte.event)
           + (SELECT count(*) FROM rolebyte.service_declaration) INTO before;
    SET ROLE rolebyte_public;
    CALL rolebyte.service_declare('{"actor":"svc:leak-test","allowed":["leak-granted"],
        "section":{"services":[{"key":"leak-granted"},{"key":"leak-intruder"}]}}'::jsonb, v);
    RESET ROLE;
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'membership:forbidden'
       OR EXISTS (SELECT 1 FROM rolebyte.service WHERE key IN ('leak-granted', 'leak-intruder'))
       OR (SELECT (SELECT count(*) FROM rolebyte.service) + (SELECT count(*) FROM rolebyte.event)
                  + (SELECT count(*) FROM rolebyte.service_declaration)) IS DISTINCT FROM before THEN
        RAISE EXCEPTION 'ROLE LEAK: a declaration naming a key outside the granted list was not refused whole: %', v;
    END IF;
    RAISE NOTICE 'roleleak.rolebyte: a declaration writes only what the caller was granted';
END $$;

-- The deployment's own company and its administrators are written only through their
-- procedures: the register's role can neither read nor write the two tables, runs the
-- five procedures it is given, and no other service's role runs them.
DO $$
DECLARE
    v_proc text;
BEGIN
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.deployment');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.deployment(company_tenant_id) VALUES (''x'')');
    PERFORM pg_temp.deny('rolebyte_public', 'UPDATE rolebyte.deployment SET company_tenant_id = ''x''');
    PERFORM pg_temp.deny('rolebyte_public', 'DELETE FROM rolebyte.deployment');
    PERFORM pg_temp.deny('rolebyte_public', 'SELECT count(*) FROM rolebyte.deployment_admin');
    PERFORM pg_temp.deny('rolebyte_public',
        'INSERT INTO rolebyte.deployment_admin(user_id, added_by, added_from) VALUES (''x'', ''x'', ''settings'')');
    PERFORM pg_temp.deny('rolebyte_public', 'UPDATE rolebyte.deployment_admin SET added_by = ''x''');
    PERFORM pg_temp.deny('rolebyte_public', 'DELETE FROM rolebyte.deployment_admin');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.deployment');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM rolebyte.deployment_admin');

    FOREACH v_proc IN ARRAY ARRAY['deployment_company_mark', 'deployment_get', 'deployment_admin_add',
                                  'deployment_admin_remove', 'deployment_admin_list'] LOOP
        IF NOT has_function_privilege('rolebyte_public', format('rolebyte.%s(jsonb, jsonb)', v_proc), 'EXECUTE') THEN
            RAISE EXCEPTION 'the register''s role must run rolebyte.%', v_proc;
        END IF;
        IF has_function_privilege('authbyte_public', format('rolebyte.%s(jsonb, jsonb)', v_proc), 'EXECUTE') THEN
            RAISE EXCEPTION 'ROLE LEAK: another service''s role may run rolebyte.%', v_proc;
        END IF;
        PERFORM pg_temp.deny('authbyte_public',
            format('CALL rolebyte.%s(''{}''::jsonb, NULL::jsonb)', v_proc));
    END LOOP;
    -- Naming the deployment's company is the deployment's own act, run as the
    -- location's owner: the register's role (which marks a company only when it is
    -- the only one) and every other service's role are refused it.
    IF has_function_privilege('rolebyte_public', 'rolebyte.deployment_company_set(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'ROLE LEAK: the register''s role may run rolebyte.deployment_company_set';
    END IF;
    IF has_function_privilege('authbyte_public', 'rolebyte.deployment_company_set(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'ROLE LEAK: another service''s role may run rolebyte.deployment_company_set';
    END IF;
    PERFORM pg_temp.deny('rolebyte_public',
        'CALL rolebyte.deployment_company_set(''{"actor":"x","tenantId":"x"}''::jsonb, NULL::jsonb)');
    PERFORM pg_temp.deny('authbyte_public',
        'CALL rolebyte.deployment_company_set(''{"actor":"x","tenantId":"x"}''::jsonb, NULL::jsonb)');
    RAISE NOTICE 'roleleak.rolebyte: the deployment''s tables are the procedures'' alone';
END $$;
