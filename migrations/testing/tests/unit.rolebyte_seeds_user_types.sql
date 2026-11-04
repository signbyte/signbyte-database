-- SQL unit tests for the roles a new tenant starts with, and user types.
--
-- What is worth testing at this level rather than through the service:
--
--   * a service declares which seeded roles hold each permission (`seeds`:
--     worker, manager), only on an ordinary permission of the object plane, and
--     a change is an event;
--   * while no service declares any, a tenant opens with no roles, as before;
--   * once one does, opening a tenant creates Guest (nothing), Worker and Manager
--     holding what the services declared, in the language asked for, and the
--     definitions a placing service reads carry each role's seed;
--   * a user type holds only ordinary tenant-wide permissions; a person holds at
--     most one, recorded with its source, and it reaches their token;
--   * a user type in use, or given by the corporate login, is not deleted;
--   * the corporate-login default is given once, to a person the directory
--     brings in for the first time — never to one claiming an invitation, and
--     changing it never rewrites anybody already in.
--
-- Self-contained, seed-then-assert, one RAISE EXCEPTION per failed assertion.
--
-- Run as the owner:
--   psql "$DSN" -f migrations/testing/tests/unit.rolebyte_seeds_user_types.sql

CREATE OR REPLACE FUNCTION pg_temp.rb(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    RETURN v;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.ok(p_proc text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.rb(p_proc, p_in);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN v->'data';
END $$;

CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.rb(p_proc, p_in);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
END $$;

DO $$
DECLARE
    v        jsonb;
    v_svc    text := 'sdut' || lower(substr(util.generate_ulid(), 20, 6));
    v_perm   jsonb;
    v_ta     text;
    v_tl     text;
    v_t0     text;
    v_admin  text := 'sub:' || util.generate_ulid();
    v_admin2 text := 'sub:' || util.generate_ulid();
    v_anna   text := 'sub:' || util.generate_ulid();
    v_janis  text := 'sub:' || util.generate_ulid();
    v_ilze   text := 'sub:' || util.generate_ulid();
    v_iss    text := 'https://login.example/' || util.generate_ulid();
    v_office text;
    v_field  text;
    v_uanna  text;
    v_scopes jsonb;
BEGIN
    PERFORM pg_temp.ok('service_register', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'displayName', 'Seeds demo'), 'register');

    ----------------------------------------------------------------
    -- 0. A deployment whose services declare no seeds opens its tenants with no
    --    roles: the shipped roles belong to the products that ship them.
    ----------------------------------------------------------------
    IF EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE seeds <> '{}'::text[] AND retired_at IS NULL) THEN
        RAISE EXCEPTION 'precondition: this section needs a database where no service declared a seed';
    END IF;
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'No seeds',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Pēteris Ozols')), 'open with none');
    v_t0 := v->'tenant'->>'id';
    IF jsonb_array_length(v->'roles') IS DISTINCT FROM 0
       OR EXISTS (SELECT 1 FROM rolebyte.tenant_role WHERE tenant_id = v_t0) THEN
        RAISE EXCEPTION 'no service declared a shipped role, so the tenant opens with none: %', v;
    END IF;

    ----------------------------------------------------------------
    -- 1. Declaring seeds.
    ----------------------------------------------------------------
    v_perm := jsonb_build_object('feature', 'task', 'act', 'view', 'description', 'See tasks',
                                 'class', 'ordinary', 'plane', 'object', 'seeds', jsonb_build_array('worker', 'manager'));
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission', v_perm), 'task:view');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'project', 'act', 'edit', 'description', 'Change it', 'class', 'ordinary',
                           'plane', 'object', 'seeds', jsonb_build_array('manager'))), 'project:edit');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'project', 'act', 'create', 'description', 'Register one', 'class', 'ordinary',
                           'plane', 'tenant')), 'project:create');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'setup/kinds', 'act', 'manage', 'description', 'Define kinds',
                           'class', 'tenantConfiguration', 'plane', 'tenant')), 'setup');
    IF (SELECT seeds FROM rolebyte.service_permission WHERE service_key = v_svc AND feature_key = 'task' AND act = 'view')
       IS DISTINCT FROM '{manager,worker}' THEN
        RAISE EXCEPTION 'the seeds are stored, in byte order';
    END IF;

    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'report', 'act', 'run', 'description', 'Run', 'class', 'ordinary', 'plane', 'tenant',
                           'seeds', jsonb_build_array('manager'))), 'membership:invalid', 'a seed on a tenant permission');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'setup/x', 'act', 'manage', 'description', 'X', 'class', 'tenantConfiguration',
                           'plane', 'object', 'seeds', jsonb_build_array('manager'))), 'membership:invalid', 'a seed on setup');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        v_perm || jsonb_build_object('seeds', jsonb_build_array('site manager'))), 'membership:invalid', 'a seed not one word');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        v_perm || jsonb_build_object('seeds', jsonb_build_array('auditor'))), 'membership:invalid', 'a role the register does not ship');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        v_perm || jsonb_build_object('seeds', jsonb_build_array('guest'))), 'membership:invalid', 'Guest, who holds nothing');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        v_perm || jsonb_build_object('seeds', jsonb_build_array('worker', 'worker'))), 'membership:invalid', 'a seed twice');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        v_perm || jsonb_build_object('seeds', 'worker')), 'membership:invalid', 'seeds not a list');

    v := pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        v_perm || jsonb_build_object('seeds', jsonb_build_array('manager'))), 'reseed task:view');
    IF v->>'status' is distinct from 'changed' OR NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'permissionSeeded'
                                                  AND payload->>'permission' = v_svc || '/task:view') THEN
        RAISE EXCEPTION 'a change of seeds is an event: %', v;
    END IF;
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission', v_perm), 'back');

    ----------------------------------------------------------------
    -- 1b. The tenant opened before any seed existed receives the shipped roles
    --     from the operator, holding what was declared since; again, nothing.
    ----------------------------------------------------------------
    v := pg_temp.ok('tenant_seed_roles', jsonb_build_object('actor', 'op:test', 'tenantId', v_t0), 'seed the earlier tenant');
    IF jsonb_array_length(v->'roles') IS DISTINCT FROM 3 OR jsonb_array_length(v->'missing') IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'the three shipped roles, none missing: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.tenant_role r JOIN rolebyte.tenant_role_permission tp ON tp.tenant_role_id = r.id
         JOIN rolebyte.service_permission sp ON sp.id = tp.permission_id
         WHERE r.tenant_id = v_t0 AND r.seed = 'manager' AND sp.service_key = v_svc) IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'its Manager holds what was declared for it';
    END IF;
    v := pg_temp.ok('tenant_seed_roles', jsonb_build_object('actor', 'op:test', 'tenantId', v_t0), 'again');
    IF jsonb_array_length(v->'roles') IS DISTINCT FROM 0 OR jsonb_array_length(v->'kept') IS DISTINCT FROM 3 THEN
        RAISE EXCEPTION 'running it again creates nothing and keeps what is there: %', v;
    END IF;
    PERFORM pg_temp.refused('tenant_seed_roles', jsonb_build_object('actor', 'op:test', 'tenantId', 'no-such-tenant'),
        'tenant:not_found', 'a tenant that does not exist');

    ----------------------------------------------------------------
    -- 2. Opening a tenant: the roles it starts with.
    ----------------------------------------------------------------
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Seeds A',
        'administrator', jsonb_build_object('subjectKey', v_admin, 'displayName', 'Laura Zariņa')), 'open A');
    v_ta := v->'tenant'->>'id';
    IF jsonb_array_length(v->'roles') is distinct from 3 THEN RAISE EXCEPTION 'three roles seeded: %', v; END IF;
    IF (SELECT string_agg(seed || '=' || name, ',' ORDER BY seed) FROM rolebyte.tenant_role WHERE tenant_id = v_ta)
       IS DISTINCT FROM 'guest=Guest,manager=Manager,worker=Worker' THEN
        RAISE EXCEPTION 'Guest, Worker and Manager, in English by default';
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.tenant_role r JOIN rolebyte.tenant_role_permission tp ON tp.tenant_role_id = r.id
                WHERE r.tenant_id = v_ta AND r.seed = 'guest') THEN
        RAISE EXCEPTION 'Guest holds nothing';
    END IF;
    IF (SELECT count(*) FROM rolebyte.tenant_role r JOIN rolebyte.tenant_role_permission tp ON tp.tenant_role_id = r.id
         JOIN rolebyte.service_permission sp ON sp.id = tp.permission_id
         WHERE r.tenant_id = v_ta AND r.seed = 'manager' AND sp.service_key = v_svc) <> 2 THEN
        RAISE EXCEPTION 'the Manager holds what the service declared for it: task:view and project:edit';
    END IF;
    IF (SELECT count(*) FROM rolebyte.tenant_role r JOIN rolebyte.tenant_role_permission tp ON tp.tenant_role_id = r.id
         JOIN rolebyte.service_permission sp ON sp.id = tp.permission_id
         WHERE r.tenant_id = v_ta AND r.seed = 'worker' AND sp.service_key = v_svc) <> 1 THEN
        RAISE EXCEPTION 'the Worker holds task:view only';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'tenantRoleSeeded') is distinct from 3 THEN
        RAISE EXCEPTION 'each seeded role is an event';
    END IF;
    IF (SELECT e.payload->'permissions' FROM rolebyte.event e
         WHERE e.tenant_id = v_ta AND e.kind = 'tenantRoleSeeded' AND e.payload->>'seed' = 'manager')
       IS DISTINCT FROM (SELECT jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act
                                          ORDER BY sp.service_key, sp.feature_key, sp.act)
                           FROM rolebyte.tenant_role r JOIN rolebyte.tenant_role_permission tp ON tp.tenant_role_id = r.id
                           JOIN rolebyte.service_permission sp ON sp.id = tp.permission_id
                          WHERE r.tenant_id = v_ta AND r.seed = 'manager') THEN
        RAISE EXCEPTION 'the seed event carries what the role was given, so the history rebuilds it';
    END IF;
    IF (SELECT e.payload->'permissions' FROM rolebyte.event e
         WHERE e.tenant_id = v_ta AND e.kind = 'tenantRoleSeeded' AND e.payload->>'seed' = 'guest')
       IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'the Guest event says it was given nothing';
    END IF;

    -- A tenant whose own role already has a shipped name keeps it: that one stays missing.
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Seeds own',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Inga Kalēja')), 'open own');
    DELETE FROM rolebyte.tenant_role_permission WHERE tenant_role_id IN
        (SELECT id FROM rolebyte.tenant_role WHERE tenant_id = v->'tenant'->>'id');
    DELETE FROM rolebyte.tenant_role WHERE tenant_id = v->'tenant'->>'id';
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'op:test', 'tenantId', v->'tenant'->>'id',
        'name', 'worker'), 'its own Worker');
    v := pg_temp.ok('tenant_seed_roles', jsonb_build_object('actor', 'op:test', 'tenantId', v->'tenant'->>'id'), 'seed it');
    IF v->'missing' IS DISTINCT FROM '["worker"]'::jsonb OR jsonb_array_length(v->'roles') IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'its own worker is kept, so the shipped Worker stays missing: %', v;
    END IF;

    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Seeds LV', 'language', 'lv',
        'administrator', jsonb_build_object('subjectKey', v_admin2, 'displayName', 'Toms Krūmiņš')), 'open LV');
    v_tl := v->'tenant'->>'id';
    IF (SELECT string_agg(name, ',' ORDER BY seed) FROM rolebyte.tenant_role WHERE tenant_id = v_tl)
       IS DISTINCT FROM 'Viesis,Vadītājs,Darbinieks' THEN
        RAISE EXCEPTION 'the Latvian names for a tenant opened in Latvian';
    END IF;

    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', v_svc), 'entitle A');
    v := pg_temp.ok('tenant_role_definitions', jsonb_build_object('tenantId', v_ta), 'definitions');
    IF (SELECT count(*) FROM jsonb_array_elements(v->'roles') r WHERE r->>'seed' IN ('guest', 'worker', 'manager')) is distinct from 3 THEN
        RAISE EXCEPTION 'the definitions carry each role''s seed: %', v;
    END IF;

    ----------------------------------------------------------------
    -- 3. User types.
    ----------------------------------------------------------------
    PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Sight',
        'permissions', jsonb_build_array(v_svc || '/task:view')), 'membership:invalid', 'a user type never carries sight');
    PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Setup',
        'permissions', jsonb_build_array(v_svc || '/setup/kinds:manage')), 'membership:invalid', 'nor setup');
    PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Mixed',
        'permissions', jsonb_build_array(v_svc || '/project:create', v_svc || '/nothing:here')), 'membership:invalid',
        'one unknown name among good ones');
    PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', '  '),
        'membership:invalid', 'a nameless user type');

    v := pg_temp.ok('user_type_define', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Office',
        'permissions', jsonb_build_array(v_svc || '/project:create')), 'define Office');
    v_office := v->>'id';
    IF v->'permissions' is distinct from jsonb_build_array(v_svc || '/project:create') THEN RAISE EXCEPTION 'Office holds project:create: %', v; END IF;
    IF (SELECT payload->'permissions' FROM rolebyte.event WHERE kind = 'userTypeDefined' AND payload->>'userTypeId' = v_office)
       IS DISTINCT FROM jsonb_build_array(v_svc || '/project:create') THEN
        RAISE EXCEPTION 'the definition''s event carries what it holds, so the history rebuilds it';
    END IF;
    v := pg_temp.ok('user_type_define', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Field'), 'define Field');
    v_field := v->>'id';
    PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'office'),
        'membership:conflict', 'a name taken, in any case');

    -- Anna holds Office, set by the administrator, and it reaches her token.
    v := pg_temp.ok('user_invite', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'subjectKey', v_anna,
        'displayName', 'Anna Kalniņa', 'roles', '[]'::jsonb), 'invite Anna');
    SELECT id INTO v_uanna FROM rolebyte.user_account WHERE tenant_id = v_ta AND subject_key = v_anna;
    UPDATE rolebyte.user_account SET status = 'active' WHERE id = v_uanna;
    v := pg_temp.ok('user_type_assign', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userId', v_uanna,
        'userTypeId', v_office), 'assign Office');
    IF v->>'source' is distinct from 'administrator' THEN RAISE EXCEPTION 'set by an administrator: %', v; END IF;
    v := pg_temp.ok('resolve', jsonb_build_object('subjectKey', v_anna), 'resolve Anna');
    SELECT m->'scopes' INTO v_scopes FROM jsonb_array_elements(v->'memberships') m WHERE m->>'tenantId' = v_ta;
    IF NOT v_scopes ? (v_svc || '/project:create') THEN RAISE EXCEPTION 'her user type reaches her token: %', v; END IF;
    IF v_scopes ? (v_svc || '/task:view') THEN RAISE EXCEPTION 'and gives no sight: %', v; END IF;

    v := pg_temp.ok('user_type_list', jsonb_build_object('tenantId', v_ta), 'list');
    IF (SELECT (t->>'members')::int FROM jsonb_array_elements(v->'userTypes') t WHERE t->>'id' = v_office) is distinct from 1 THEN
        RAISE EXCEPTION 'the list counts who holds each: %', v;
    END IF;

    PERFORM pg_temp.refused('user_type_delete', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userTypeId', v_office),
        'membership:conflict', 'a user type somebody holds');
    v := pg_temp.ok('user_type_update', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userTypeId', v_field,
        'name', 'Field crew', 'permissions', jsonb_build_array(v_svc || '/project:create')), 'update Field');
    IF v->>'name' is distinct from 'Field crew' OR jsonb_array_length(v->'permissions') is distinct from 1 THEN RAISE EXCEPTION 'renamed and ticked: %', v; END IF;
    IF (SELECT payload->>'name' || ' ' || (payload->'permissions')::text FROM rolebyte.event
         WHERE kind = 'userTypeChanged' AND payload->>'userTypeId' = v_field)
       IS DISTINCT FROM 'Field crew ' || jsonb_build_array(v_svc || '/project:create')::text THEN
        RAISE EXCEPTION 'the change''s event carries the user type as it now is';
    END IF;
    PERFORM pg_temp.refused('user_type_update', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userTypeId', v_field,
        'name', 'Office'), 'membership:conflict', 'renamed onto a taken name');
    PERFORM pg_temp.refused('user_type_assign', jsonb_build_object('actor', v_admin, 'tenantId', v_tl, 'userId', v_uanna,
        'userTypeId', v_office), 'membership:not_found', 'a member of another tenant');

    ----------------------------------------------------------------
    -- 4. The corporate-login default.
    ----------------------------------------------------------------
    PERFORM pg_temp.ok('directory_attach', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'issuer', v_iss), 'attach');
    v := pg_temp.ok('corporate_login_default_get', jsonb_build_object('tenantId', v_ta), 'get empty');
    IF v->>'userTypeId' is distinct from '' THEN RAISE EXCEPTION 'empty until set: %', v; END IF;

    -- Empty: Jānis arrives with the workspace's own default.
    PERFORM pg_temp.ok('directory_admit', jsonb_build_object('actor', 'idp', 'subjectKey', v_janis, 'issuer', v_iss,
        'displayName', 'Jānis Bērziņš'), 'admit Jānis');
    IF (SELECT user_type_id || '/' || user_type_source FROM rolebyte.user_account WHERE tenant_id = v_ta AND subject_key = v_janis)
       IS DISTINCT FROM (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_ta) || '/workspaceDefault' THEN
        RAISE EXCEPTION 'with no corporate default a newcomer receives the workspace default';
    END IF;

    PERFORM pg_temp.ok('corporate_login_default_set', jsonb_build_object('actor', v_admin, 'tenantId', v_ta,
        'userTypeId', v_field), 'set Field');
    -- Ilze arrives after: she holds Field, from the corporate login.
    PERFORM pg_temp.ok('directory_admit', jsonb_build_object('actor', 'idp', 'subjectKey', v_ilze, 'issuer', v_iss,
        'displayName', 'Ilze Siliņa'), 'admit Ilze');
    IF (SELECT user_type_id || '/' || user_type_source FROM rolebyte.user_account WHERE tenant_id = v_ta AND subject_key = v_ilze)
       IS DISTINCT FROM v_field || '/corporateLoginDefault' THEN
        RAISE EXCEPTION 'a newcomer through the corporate login receives the default, recorded as its source';
    END IF;
    IF (SELECT e.payload->>'userTypeId' || '/' || (e.payload->>'source') FROM rolebyte.event e
          JOIN rolebyte.user_account u ON u.id = e.user_id
         WHERE e.kind = 'userTypeAssigned' AND u.tenant_id = v_ta AND u.subject_key = v_ilze)
       IS DISTINCT FROM v_field || '/corporateLoginDefault' THEN
        RAISE EXCEPTION 'the history says what the corporate login gave her, and that it did';
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.event e JOIN rolebyte.user_account u ON u.id = e.user_id
                WHERE e.kind = 'userTypeAssigned' AND u.tenant_id = v_ta AND u.subject_key = v_janis
                  AND e.payload->>'source' IS DISTINCT FROM 'workspaceDefault') THEN
        RAISE EXCEPTION 'what Jānis was given is recorded as the workspace default, never as the corporate login''s';
    END IF;
    IF (SELECT user_type_id FROM rolebyte.user_account WHERE tenant_id = v_ta AND subject_key = v_janis) IS DISTINCT FROM (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_ta) THEN
        RAISE EXCEPTION 'setting the corporate default never rewrites somebody already in';
    END IF;

    -- An invitation the person claims keeps what the inviter chose.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', v_admin, 'tenantId', v_ta,
        'subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Placeholder', 'roles', '[]'::jsonb), 'another invite');
    v := pg_temp.ok('user_invite', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'subjectKey', v_admin2,
        'displayName', 'Toms Krūmiņš', 'roles', '[]'::jsonb), 'invite Toms');
    PERFORM pg_temp.ok('directory_admit', jsonb_build_object('actor', 'idp', 'subjectKey', v_admin2, 'issuer', v_iss,
        'displayName', 'Toms Krūmiņš'), 'Toms claims his invitation');
    IF (SELECT user_type_id || '/' || user_type_source FROM rolebyte.user_account WHERE tenant_id = v_ta AND subject_key = v_admin2)
       IS DISTINCT FROM (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_ta) || '/workspaceDefault' THEN
        RAISE EXCEPTION 'a claimed invitation keeps what it was given at the invitation, never the corporate login''s';
    END IF;

    PERFORM pg_temp.refused('user_type_delete', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userTypeId', v_field),
        'membership:conflict', 'the corporate login''s user type');
    PERFORM pg_temp.refused('corporate_login_default_set', jsonb_build_object('actor', v_admin, 'tenantId', v_ta,
        'userTypeId', 'no-such-type'), 'membership:invalid', 'a user type the tenant does not have');
    PERFORM pg_temp.ok('corporate_login_default_set', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userTypeId', ''), 'clear');
    UPDATE rolebyte.user_account SET user_type_id = (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_ta), user_type_source = 'workspaceDefault'
     WHERE tenant_id = v_ta AND subject_key = v_ilze;
    PERFORM pg_temp.ok('user_type_delete', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userTypeId', v_field), 'delete Field');
    IF EXISTS (SELECT 1 FROM rolebyte.user_type WHERE id = v_field) THEN RAISE EXCEPTION 'a free user type is deleted'; END IF;

    RAISE NOTICE 'unit.rolebyte_seeds_user_types: ALL PASSED';
END $$;
