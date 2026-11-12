-- Unit test: the deployment's door, the procedures through which the register's own role
-- opens a company, says which products it has, names its administrators and the
-- deployment's, and keeps the catalog of products with the service accounts of each.
--
-- The caller's check is tested once for every procedure of the door, driven from one
-- list, for every reason a caller can fail it: not on the list, on the list with a
-- revoked or an invited account, a member of another company only, the other mode, a
-- service's key and a suspended deployment company; each answers the same
-- `membership:forbidden` sentence and writes nothing. A person taken off the list is
-- refused by the next call. Opening a company is tested whole (every row and history
-- line, the starting roles in both languages, the products, the service accounts),
-- refused late (a refusal after the first write leaves nothing) and refused on every
-- input. Giving and taking a product has its own blocks: the guard in both directions, a
-- product giving two services or one feature, the entitlements an untick takes with it,
-- the accounts that follow, adoption when the catalog is registered, a catalog change,
-- a product removed while a company has it, and needs that form a circle. The
-- administrators of a company and of the deployment, the first run in both modes, the
-- follow of a deployment run on the customer's own machines, the starting roles and the
-- products on offer each have a block too. A service account dropped from a product's list is
-- ended where a ticked product listed it; the local mode's company administrator, an opening whose
-- second product cannot be given, and what is offered (by permissions and by the time of the last
-- declaration) have blocks of their own.
--
-- Not covered here, because it cannot be seen in one transaction: two sessions at once
-- (the deployment's lock serialising two writers).
--
-- The whole test runs in one transaction that is rolled back at the end. It empties
-- the register's tenants and services inside it, and the rollback restores them.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_deployment_door.sql

BEGIN;

-- Calls one register procedure and returns its answer; a raised refusal is its answer too.
CREATE OR REPLACE FUNCTION pg_temp.rb(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    BEGIN
        EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    EXCEPTION
        WHEN sqlstate 'P0001' THEN
            v := sqlerrm::jsonb;
    END;
    RETURN v;
END $$;

-- The call must succeed; returns its data.
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

-- What the tables the door writes hold, as one comparable text.
CREATE OR REPLACE FUNCTION pg_temp.fingerprint() RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.tenant t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.user_account t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.assignment t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.tenant_entitlement t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.tenant_role t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.tenant_product t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.product t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.product_entitlement t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.product_requirement t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.product_account t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.deployment t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.deployment_admin t),
        (SELECT count(*) FROM rolebyte.event)))
$$;

-- The call must be refused with this code, say this (when given), and change nothing.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_says text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text := pg_temp.fingerprint();
BEGIN
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    IF p_says IS NOT NULL AND position(p_says IN coalesce(v->>'message', '')) = 0 THEN
        RAISE EXCEPTION '% must say "%", said "%"', p_why, p_says, v->>'message';
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
END $$;

-- The call must succeed with changed = false and change nothing.
CREATE OR REPLACE FUNCTION pg_temp.unchanged(p_proc text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text := pg_temp.fingerprint();
BEGIN
    v := pg_temp.ok(p_proc, p_in, p_why);
    IF (v->>'changed')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION '% should answer changed false: %', p_why, v;
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% answered changed false but wrote something', p_why;
    END IF;
    RETURN v;
END $$;

-- The same, as a person calls the door on the saas mode.
CREATE OR REPLACE FUNCTION pg_temp.door(p_proc text, p_actor text, p_in jsonb) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.rb(p_proc, jsonb_build_object('actor', p_actor, 'mode', 'saas') || p_in)
$$;

CREATE OR REPLACE FUNCTION pg_temp.dok(p_proc text, p_actor text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.ok(p_proc, jsonb_build_object('actor', p_actor, 'mode', 'saas') || p_in, p_why)
$$;

CREATE OR REPLACE FUNCTION pg_temp.drefused(p_proc text, p_actor text, p_in jsonb, p_code text, p_says text, p_why text)
RETURNS void
LANGUAGE sql AS $$
    SELECT pg_temp.refused(p_proc, jsonb_build_object('actor', p_actor, 'mode', 'saas') || p_in, p_code, p_says, p_why)
$$;

CREATE OR REPLACE FUNCTION pg_temp.dunchanged(p_proc text, p_actor text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.unchanged(p_proc, jsonb_build_object('actor', p_actor, 'mode', 'saas') || p_in, p_why)
$$;

-- A person's key, a level and the products of the catalog.
CREATE OR REPLACE FUNCTION pg_temp.person() RETURNS text
LANGUAGE sql AS $$ SELECT 'sub:' || util.generate_ulid() $$;

CREATE OR REPLACE FUNCTION pg_temp.lvl(p_service text, p_group text, p_level text) RETURNS jsonb
LANGUAGE sql AS $$ SELECT jsonb_build_object('service', p_service, 'group', p_group, 'level', p_level) $$;

CREATE OR REPLACE FUNCTION pg_temp.acct(p_key text, p_name text, p_roles jsonb) RETURNS jsonb
LANGUAGE sql AS $$ SELECT jsonb_build_object('subjectKey', p_key, 'displayName', p_name, 'roles', p_roles) $$;

CREATE OR REPLACE FUNCTION pg_temp.give(p_service text, p_feature text) RETURNS jsonb
LANGUAGE sql AS $$ SELECT jsonb_build_object('service', p_service, 'feature', p_feature) $$;

CREATE OR REPLACE FUNCTION pg_temp.prod(p_key text, p_name text, p_gives jsonb, p_needs jsonb, p_accounts jsonb) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_build_object('key', p_key, 'displayName', p_name, 'gives', p_gives, 'needs', p_needs,
                              'accounts', p_accounts)
$$;

-- The catalog every block starts from: alpha-pack (all of alpha, three service accounts),
-- beta-pack (all of beta, two accounts, one shared with alpha-pack), alpha-lite (one feature
-- of alpha), alpha-plus (the same feature, and it needs alpha-pack) and duo-pack (two
-- services at once).
CREATE OR REPLACE FUNCTION pg_temp.alpha_pack() RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.prod('alpha-pack', 'Alpha pack', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
        jsonb_build_array(
            pg_temp.acct('svc:alpha-api', 'Alpha API',
                         jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read'), pg_temp.lvl('alpha', 'api', 'write'))),
            pg_temp.acct('svc:alpha-sync', 'Alpha sync', '[]'::jsonb),
            pg_temp.acct('svc:shared', 'Shared', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read')))))
$$;

CREATE OR REPLACE FUNCTION pg_temp.cat1() RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_build_array(
        pg_temp.alpha_pack(),
        pg_temp.prod('beta-pack', 'Beta pack', jsonb_build_array(pg_temp.give('beta', '')), '[]'::jsonb,
            jsonb_build_array(
                pg_temp.acct('svc:beta-api', 'Beta API', jsonb_build_array(pg_temp.lvl('beta', 'api', 'sync'))),
                pg_temp.acct('svc:shared', 'Shared', jsonb_build_array(pg_temp.lvl('beta', 'api', 'sync'))))),
        pg_temp.prod('alpha-lite', 'Alpha lite', jsonb_build_array(pg_temp.give('alpha', 'task')), '[]'::jsonb, '[]'::jsonb),
        pg_temp.prod('alpha-plus', 'Alpha plus', jsonb_build_array(pg_temp.give('alpha', 'task')),
                     jsonb_build_array('alpha-pack'), '[]'::jsonb),
        pg_temp.prod('duo-pack', 'Duo pack', jsonb_build_array(pg_temp.give('gamma', ''), pg_temp.give('delta', '')),
                     '[]'::jsonb, '[]'::jsonb))
$$;

CREATE OR REPLACE FUNCTION pg_temp.reg(p_list jsonb, p_adopt boolean DEFAULT NULL) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.ok('products_register',
        jsonb_strip_nulls(jsonb_build_object('actor', 'fx', 'products', p_list, 'adopt', p_adopt)),
        'register the catalog')
$$;

-- Reading helpers.
CREATE OR REPLACE FUNCTION pg_temp.dep() RETURNS text
LANGUAGE sql AS $$ SELECT company_tenant_id FROM rolebyte.deployment $$;

CREATE OR REPLACE FUNCTION pg_temp.uid(p_tenant text, p_subject text) RETURNS text
LANGUAGE sql AS $$ SELECT id FROM rolebyte.user_account WHERE tenant_id = p_tenant AND subject_key = p_subject $$;

CREATE OR REPLACE FUNCTION pg_temp.status(p_tenant text, p_subject text) RETURNS text
LANGUAGE sql AS $$ SELECT status FROM rolebyte.user_account WHERE tenant_id = p_tenant AND subject_key = p_subject $$;

CREATE OR REPLACE FUNCTION pg_temp.levels(p_tenant text, p_subject text) RETURNS text
LANGUAGE sql AS $$
    SELECT coalesce(string_agg(rd.service_key || ' ' || rd.role_group || ':' || rd.role_level, ', '
                               ORDER BY rd.service_key, rd.role_group, rd.role_level), '')
      FROM rolebyte.user_account u
      JOIN rolebyte.assignment a ON a.user_id = u.id AND a.state = 'granted'
      JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
     WHERE u.tenant_id = p_tenant AND u.subject_key = p_subject
$$;

CREATE OR REPLACE FUNCTION pg_temp.lines(p_kind text, p_tenant text) RETURNS int
LANGUAGE sql AS $$ SELECT count(*)::int FROM rolebyte.event WHERE kind = p_kind AND tenant_id = p_tenant $$;

-- The whole services a company is entitled to, as one text.
CREATE OR REPLACE FUNCTION pg_temp.has_keys(p_tenant text) RETURNS text
LANGUAGE sql AS $$
    SELECT coalesce(string_agg(service_key, ',' ORDER BY service_key), '')
      FROM rolebyte.tenant_entitlement WHERE tenant_id = p_tenant AND state = 'entitled' AND feature_key = ''
$$;

-- Every entitlement in force, features included, as one text.
CREATE OR REPLACE FUNCTION pg_temp.has_rows(p_tenant text) RETURNS text
LANGUAGE sql AS $$
    SELECT coalesce(string_agg(service_key || CASE WHEN feature_key = '' THEN '' ELSE '/' || feature_key END,
                               ',' ORDER BY service_key, feature_key), '')
      FROM rolebyte.tenant_entitlement WHERE tenant_id = p_tenant AND state = 'entitled'
$$;

-- The products a company has, as one text.
CREATE OR REPLACE FUNCTION pg_temp.products(p_tenant text) RETURNS text
LANGUAGE sql AS $$
    SELECT coalesce(string_agg(product_key, ',' ORDER BY product_key), '')
      FROM rolebyte.tenant_product WHERE tenant_id = p_tenant AND state = 'ticked'
$$;

CREATE OR REPLACE FUNCTION pg_temp.role_names(p_tenant text) RETURNS text
LANGUAGE sql AS $$
    SELECT coalesce(string_agg(name, ',' ORDER BY seed), '') FROM rolebyte.tenant_role WHERE tenant_id = p_tenant
$$;

-- What a set of accounts and the levels they hold look like, as one comparable text.
CREATE OR REPLACE FUNCTION pg_temp.snap(p_tenant text, p_subjects text[]) RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT coalesce(string_agg(u::text, ',' ORDER BY u::text), '') FROM rolebyte.user_account u
          WHERE u.tenant_id = p_tenant AND u.subject_key = ANY (p_subjects)),
        (SELECT coalesce(string_agg(a::text, ',' ORDER BY a::text), '') FROM rolebyte.assignment a
           JOIN rolebyte.user_account u ON u.id = a.user_id
          WHERE u.tenant_id = p_tenant AND u.subject_key = ANY (p_subjects))))
$$;

-- A company made the plain way, with no administrator of the deployment's.
CREATE OR REPLACE FUNCTION pg_temp.customer(p_name text) RETURNS text
LANGUAGE sql AS $$
    SELECT pg_temp.ok('tenant_create', jsonb_build_object('actor', 'fx', 'name', p_name), 'a customer company')->>'id'
$$;

-- A person with an account in a company, in the state asked for (invited, active, revoked).
CREATE OR REPLACE FUNCTION pg_temp.member(p_tenant text, p_name text, p_status text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_key text := pg_temp.person();
BEGIN
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', p_tenant,
        'subjectKey', v_key, 'displayName', p_name), 'invite a member');
    IF p_status = 'active' THEN
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'fx', 'subjectKey', v_key), 'activate a member');
    ELSIF p_status = 'revoked' THEN
        UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = p_tenant AND subject_key = v_key;
    END IF;
    RETURN v_key;
END $$;

-- An active member of the deployment's company who is on the list of its administrators.
CREATE OR REPLACE FUNCTION pg_temp.admin() RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_key text := pg_temp.member(pg_temp.dep(), 'Deployment admin', 'active');
BEGIN
    PERFORM pg_temp.ok('deployment_admin_add', jsonb_build_object('actor', 'fx', 'subjectKey', v_key,
        'addedFrom', 'screen'), 'list an administrator');
    RETURN v_key;
END $$;

-- The register with no company but the deployment's own, named as asked, with one
-- listed, active administrator, whose key it answers.
CREATE OR REPLACE FUNCTION pg_temp.world(p_name text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_tenant text := util.generate_ulid();
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_tenant, p_name);
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_tenant),
        'mark the deployment''s company');
    RETURN pg_temp.admin();
END $$;

-- A valid input to company_open, each part replaceable; a part given as SQL NULL is left out.
CREATE OR REPLACE FUNCTION pg_temp.oi(
    p_name jsonb DEFAULT '"Valid Co"'::jsonb,
    p_lang jsonb DEFAULT '"en"'::jsonb,
    p_products jsonb DEFAULT '["alpha-pack"]'::jsonb,
    p_adm  jsonb DEFAULT jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Valid Admin'))
RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_strip_nulls(jsonb_build_object('name', p_name, 'language', p_lang, 'products', p_products,
                                                'administrator', p_adm))
$$;

-- A company opened by the administrator with these products.
CREATE OR REPLACE FUNCTION pg_temp.open_with(p_actor text, p_name text, p_products jsonb) RETURNS text
LANGUAGE sql AS $$
    SELECT pg_temp.dok('company_open', p_actor, pg_temp.oi(to_jsonb(p_name), '"en"', p_products), 'open ' || p_name)
           ->'company'->>'id'
$$;

CREATE OR REPLACE FUNCTION pg_temp.has_set(p_actor text, p_tenant text, p_product text, p_has boolean) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.dok('company_has_set', p_actor, jsonb_build_object('tenantId', p_tenant, 'product', p_product,
        'has', p_has), 'set a product')
$$;

-- The services every block uses, their levels and permissions, and the catalog.
DO $$
DECLARE
    v jsonb;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    TRUNCATE rolebyte.service CASCADE;

    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"alpha","displayName":"Alpha"}', 'register alpha');
    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"beta","displayName":"Beta"}', 'register beta');
    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"gamma","displayName":"Gamma"}', 'register gamma');
    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"delta","displayName":"Delta"}', 'register delta');
    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"eps","displayName":"Epsilon"}', 'register eps');
    PERFORM pg_temp.ok('role_define', '{"actor":"fx","service":"alpha","group":"api","level":"read"}', 'alpha read');
    PERFORM pg_temp.ok('role_define', '{"actor":"fx","service":"alpha","group":"api","level":"write"}', 'alpha write');
    PERFORM pg_temp.ok('role_define', '{"actor":"fx","service":"alpha","group":"membership","level":"admin"}',
        'alpha has its own administrator level');
    PERFORM pg_temp.ok('role_define', '{"actor":"fx","service":"beta","group":"api","level":"sync"}', 'beta sync');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'fx', 'service', 'alpha', 'permission',
        jsonb_build_object('feature', 'task', 'act', 'view', 'description', 'See tasks', 'class', 'ordinary',
                           'plane', 'object', 'seeds', jsonb_build_array('worker', 'manager'))), 'alpha permission');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'fx', 'service', 'beta', 'permission',
        jsonb_build_object('feature', 'item', 'act', 'view', 'description', 'See items', 'class', 'ordinary',
                           'plane', 'object')), 'beta permission');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'fx', 'service', 'gamma', 'permission',
        jsonb_build_object('feature', 'job', 'act', 'view', 'description', 'See jobs', 'class', 'ordinary',
                           'plane', 'object')), 'gamma permission');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'fx', 'service', 'delta', 'permission',
        jsonb_build_object('feature', 'note', 'act', 'view', 'description', 'See notes', 'class', 'ordinary',
                           'plane', 'object')), 'delta permission');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'fx', 'service', 'eps', 'permission',
        jsonb_build_object('feature', 'mark', 'act', 'view', 'description', 'See marks', 'class', 'ordinary',
                           'plane', 'object')), 'eps permission');
    INSERT INTO rolebyte.service_declaration (service_key, declared_by) VALUES ('alpha', 'svc:alpha-decl');

    v := pg_temp.reg(pg_temp.cat1());
    IF (v->>'registered')::int IS DISTINCT FROM 5 OR (v->>'unregistered')::int IS DISTINCT FROM 0
       OR (v->>'adopted')::int IS DISTINCT FROM 0 OR (v->>'companies')::int IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'the first catalog should add five products and touch no company: %', v;
    END IF;
END $$;

-- a. The caller's check, for every reason, from every procedure of the door.
DO $$
DECLARE
    v_admin   text;
    v_dep     text;
    v_cust    text;
    v_plain   text;
    v_revoked text;
    v_invited text;
    v_other   text;
    v_inputs  jsonb;
    v_cases   jsonb;
    v_case    jsonb;
    v_proc    text;
    v_names   text[];
    v_extra   text;
    v         jsonb;
BEGIN
    v_admin := pg_temp.world('Deployment Co');
    v_dep   := pg_temp.dep();
    v_cust  := pg_temp.customer('Customer One');
    v_plain := pg_temp.member(v_dep, 'Plain member', 'active');
    v_revoked := pg_temp.admin();
    UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = v_dep AND subject_key = v_revoked;
    v_invited := pg_temp.member(v_dep, 'Invited member', 'invited');
    PERFORM pg_temp.ok('deployment_admin_add', jsonb_build_object('actor', 'fx', 'subjectKey', v_invited,
        'addedFrom', 'screen'), 'list an invited person');
    v_other := pg_temp.member(v_cust, 'Other company', 'active');
    -- A service's account, active and on the list as if somebody had put it there: still not a person.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_dep,
        'subjectKey', 'svc:listed-client', 'displayName', 'A listed service'), 'a service account in the company');
    UPDATE rolebyte.user_account SET status = 'active' WHERE tenant_id = v_dep AND subject_key = 'svc:listed-client';
    INSERT INTO rolebyte.deployment_admin (user_id, added_by, added_from)
    VALUES (pg_temp.uid(v_dep, 'svc:listed-client'), 'fx', 'screen');

    -- Every procedure of the door, with an input that would do something if the caller were let in.
    v_inputs := jsonb_build_object(
        'deployment_door_check', '{}'::jsonb,
        'company_list', '{}'::jsonb,
        'company_get', jsonb_build_object('tenantId', v_cust),
        'company_administrators', jsonb_build_object('tenantId', v_cust),
        'deployment_products', '{}'::jsonb,
        'deployment_admins', '{}'::jsonb,
        'company_open', pg_temp.oi(),
        'company_has_set', jsonb_build_object('tenantId', v_cust, 'product', 'alpha-pack', 'has', true),
        'company_administrator_set', jsonb_build_object('tenantId', v_cust, 'subjectKey', pg_temp.person(),
                                                        'displayName', 'Probe'),
        'company_administrator_unset', jsonb_build_object('tenantId', v_cust, 'userId', pg_temp.uid(v_cust, v_other)),
        'company_roles_seed', jsonb_build_object('tenantId', v_cust, 'language', 'lv'),
        'company_first_run', jsonb_build_object('name', 'Probe', 'language', 'en'),
        'deployment_admin_grant', jsonb_build_object('subjectKey', v_plain),
        'deployment_admin_revoke', jsonb_build_object('userId', pg_temp.uid(v_dep, v_admin)));

    -- A procedure added to the door later without the check must be added to the list above.
    SELECT array_agg(p.proname::text) INTO v_names
      FROM pg_proc p
     WHERE p.pronamespace = 'rolebyte'::regnamespace AND p.prokind = 'p'
       AND (p.proname LIKE 'company\_%' OR p.proname IN ('deployment_products', 'deployment_admins',
                                                         'deployment_admin_grant', 'deployment_admin_revoke',
                                                         'deployment_door_check'));
    SELECT string_agg(n, ', ') INTO v_extra FROM unnest(v_names) n WHERE NOT (v_inputs ? n);
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'procedures of the door that the caller''s check is not tested on: %', v_extra;
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(v_inputs)) IS DISTINCT FROM 14 THEN
        RAISE EXCEPTION 'the list of the door''s procedures lost one';
    END IF;

    v_cases := jsonb_build_array(
        jsonb_build_object('why', 'not on the list', 'actor', v_plain, 'mode', 'saas'),
        jsonb_build_object('why', 'listed, account revoked', 'actor', v_revoked, 'mode', 'saas'),
        jsonb_build_object('why', 'listed, account invited', 'actor', v_invited, 'mode', 'saas'),
        jsonb_build_object('why', 'a member of another company only', 'actor', v_other, 'mode', 'saas'),
        jsonb_build_object('why', 'the local mode', 'actor', v_admin, 'mode', 'local'),
        jsonb_build_object('why', 'a service''s key', 'actor', 'svc:client', 'mode', 'saas'),
        jsonb_build_object('why', 'a service''s account on the list', 'actor', 'svc:listed-client', 'mode', 'saas'));

    FOR v_proc IN SELECT k FROM jsonb_object_keys(v_inputs) k LOOP
        FOR v_case IN SELECT c FROM jsonb_array_elements(v_cases) c LOOP
            PERFORM pg_temp.refused(v_proc,
                (v_inputs->v_proc) || jsonb_build_object('actor', v_case->>'actor', 'mode', v_case->>'mode'),
                'membership:forbidden', 'not a deployment administrator', v_proc || ' for ' || (v_case->>'why'));
        END LOOP;
    END LOOP;

    -- A suspended deployment company: even its listed administrator is refused.
    UPDATE rolebyte.tenant SET status = 'suspended' WHERE id = v_dep;
    FOR v_proc IN SELECT k FROM jsonb_object_keys(v_inputs) k LOOP
        PERFORM pg_temp.refused(v_proc,
            (v_inputs->v_proc) || jsonb_build_object('actor', v_admin, 'mode', 'saas'),
            'membership:forbidden', 'not a deployment administrator', v_proc || ' for a suspended company');
    END LOOP;
    UPDATE rolebyte.tenant SET status = 'active' WHERE id = v_dep;

    -- The check on its own: let in, it answers an empty object and writes nothing.
    v := pg_temp.dok('deployment_door_check', v_admin, '{}', 'the check by an administrator');
    IF v IS DISTINCT FROM '{}'::jsonb THEN
        RAISE EXCEPTION 'the check answers an empty object: %', v;
    END IF;

    -- No company marked at all.
    DELETE FROM rolebyte.deployment_admin;
    DELETE FROM rolebyte.deployment;
    PERFORM pg_temp.drefused('company_list', v_admin, '{}', 'membership:forbidden', 'not a deployment administrator',
        'no company marked');

    -- A missing actor and a mode that is neither is `invalid`, before the check.
    FOR v_proc IN SELECT k FROM jsonb_object_keys(v_inputs) k LOOP
        PERFORM pg_temp.refused(v_proc, (v_inputs->v_proc) || '{"mode":"saas"}'::jsonb,
            'membership:invalid', NULL, v_proc || ' without an actor');
        PERFORM pg_temp.refused(v_proc, (v_inputs->v_proc) || jsonb_build_object('actor', v_admin, 'mode', 'other'),
            'membership:invalid', NULL, v_proc || ' in another mode');
        PERFORM pg_temp.refused(v_proc, (v_inputs->v_proc) || jsonb_build_object('actor', v_admin),
            'membership:invalid', NULL, v_proc || ' without a mode');
    END LOOP;

    -- The control: the same call by the listed administrator is let in.
    v_admin := pg_temp.world('Deployment Co');
    v := pg_temp.dok('company_list', v_admin, '{}', 'the listed administrator');
    IF jsonb_array_length(v->'companies') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'the listed administrator should see the one company: %', v;
    END IF;
    RAISE NOTICE 'a: the caller''s check, per reason, from every procedure';
END $$;

-- b. A person taken off the list is refused by the very next call.
DO $$
DECLARE
    v_a1 text;
    v_a2 text;
BEGIN
    v_a1 := pg_temp.world('Deployment Co');
    v_a2 := pg_temp.admin();
    PERFORM pg_temp.dok('company_list', v_a2, '{}', 'the second administrator, listed');
    PERFORM pg_temp.dok('deployment_admin_revoke', v_a1, jsonb_build_object('userId', pg_temp.uid(pg_temp.dep(), v_a2)),
        'take the second administrator off');
    PERFORM pg_temp.drefused('company_list', v_a2, '{}', 'membership:forbidden', 'not a deployment administrator',
        'the next call of a person taken off the list');
    PERFORM pg_temp.drefused('company_open', v_a2, pg_temp.oi(), 'membership:forbidden', NULL,
        'opening a company after being taken off the list');
    RAISE NOTICE 'b: taken off the list, refused at once';
END $$;

-- c. Opening a company, whole.
DO $$
DECLARE
    v_admin text;
    v_p     text := pg_temp.person();
    v       jsonb;
    v_t     text;
    v_uid   text;
    v_n     int;
BEGIN
    v_admin := pg_temp.world('Deployment Co');
    v := pg_temp.dok('company_open', v_admin, pg_temp.oi('"  Acme SIA  "', '"lv"', '["alpha-pack","beta-pack"]',
        jsonb_build_object('subjectKey', v_p, 'displayName', ' Anna Ozola ')), 'open a company');
    v_t := v->'company'->>'id';

    IF v->'company'->>'name' IS DISTINCT FROM 'Acme SIA' OR v->'company'->>'status' IS DISTINCT FROM 'active'
       OR v->'company'->>'createdAt' IS NULL THEN
        RAISE EXCEPTION 'the company is answered trimmed, active, with its time: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_t AND name = 'Acme SIA' AND status = 'active'
                      AND default_user_type_id IS NOT NULL) THEN
        RAISE EXCEPTION 'the company row, with its default user type, should exist';
    END IF;
    IF pg_temp.lines('tenantCreated', v_t) IS DISTINCT FROM 1
       OR (SELECT payload->>'name' FROM rolebyte.event WHERE tenant_id = v_t AND kind = 'tenantCreated') IS DISTINCT FROM 'Acme SIA' THEN
        RAISE EXCEPTION 'one tenantCreated line naming the company';
    END IF;

    -- The administrator: invited, named trimmed, holding the rung.
    v_uid := pg_temp.uid(v_t, v_p);
    IF v->'administrator'->>'userId' IS DISTINCT FROM v_uid OR v->'administrator'->>'status' IS DISTINCT FROM 'invited'
       OR pg_temp.status(v_t, v_p) IS DISTINCT FROM 'invited'
       OR (SELECT display_name FROM rolebyte.user_account WHERE id = v_uid) IS DISTINCT FROM 'Anna Ozola'
       OR NOT rolebyte.is_administrator(v_uid)
       OR pg_temp.levels(v_t, v_p) IS DISTINCT FROM 'rolebyte membership:admin' THEN
        RAISE EXCEPTION 'the administrator should be invited, named, and hold the rung: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_t AND user_id = v_uid
           AND kind IN ('userInvited', 'userTypeAssigned', 'roleGranted', 'administratorSetByOperator')) IS DISTINCT FROM 4 THEN
        RAISE EXCEPTION 'the administrator''s four history lines';
    END IF;

    -- The starting roles, named in Latvian.
    IF pg_temp.role_names(v_t) IS DISTINCT FROM 'Viesis,Vadītājs,Darbinieks'
       OR jsonb_array_length(v->'roles') IS DISTINCT FROM 3
       OR pg_temp.lines('tenantRoleSeeded', v_t) IS DISTINCT FROM 3 THEN
        RAISE EXCEPTION 'three starting roles in Latvian, each with its line: % %', pg_temp.role_names(v_t), v->'roles';
    END IF;

    -- The products, what they give, and the service accounts.
    IF v->'products' IS DISTINCT FROM '["alpha-pack","beta-pack"]'::jsonb
       OR pg_temp.products(v_t) IS DISTINCT FROM 'alpha-pack,beta-pack'
       OR pg_temp.has_keys(v_t) IS DISTINCT FROM 'alpha,beta'
       OR pg_temp.lines('productTicked', v_t) IS DISTINCT FROM 2
       OR pg_temp.lines('tenantEntitled', v_t) IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'the two products and their entitlements, each with its line: %', v;
    END IF;
    IF v->'accounts' IS DISTINCT FROM '["svc:alpha-api","svc:alpha-sync","svc:beta-api","svc:shared"]'::jsonb
       OR pg_temp.lines('serviceAccountAdded', v_t) IS DISTINCT FROM 4 THEN
        RAISE EXCEPTION 'four service accounts made members: %', v->'accounts';
    END IF;
    IF pg_temp.status(v_t, 'svc:alpha-api') IS DISTINCT FROM 'active'
       OR pg_temp.status(v_t, 'svc:alpha-sync') IS DISTINCT FROM 'active'
       OR pg_temp.status(v_t, 'svc:beta-api') IS DISTINCT FROM 'active'
       OR pg_temp.status(v_t, 'svc:shared') IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'every service account is an active member';
    END IF;
    IF pg_temp.levels(v_t, 'svc:alpha-api') IS DISTINCT FROM 'alpha api:read, alpha api:write'
       OR pg_temp.levels(v_t, 'svc:alpha-sync') IS DISTINCT FROM ''
       OR pg_temp.levels(v_t, 'svc:beta-api') IS DISTINCT FROM 'beta api:sync'
       OR pg_temp.levels(v_t, 'svc:shared') IS DISTINCT FROM 'alpha api:read, beta api:sync' THEN
        RAISE EXCEPTION 'each service account holds exactly its levels, the shared one the union';
    END IF;
    IF (SELECT display_name FROM rolebyte.user_account WHERE tenant_id = v_t AND subject_key = 'svc:alpha-api') IS DISTINCT FROM 'Alpha API'
       OR (SELECT user_type_id FROM rolebyte.user_account WHERE tenant_id = v_t AND subject_key = 'svc:alpha-api')
          IS DISTINCT FROM (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_t) THEN
        RAISE EXCEPTION 'a service account is named from the list and holds the default user type';
    END IF;
    -- Every line of the open names the caller.
    SELECT count(*) INTO v_n FROM rolebyte.event WHERE tenant_id = v_t AND actor <> v_admin;
    IF v_n IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION '% lines of the open do not name the caller', v_n;
    END IF;

    -- In English the same three roles are named in English.
    v := pg_temp.dok('company_open', v_admin, pg_temp.oi('"English Co"', '"en"', '[]'), 'open in English');
    IF pg_temp.role_names(v->'company'->>'id') IS DISTINCT FROM 'Guest,Manager,Worker' THEN
        RAISE EXCEPTION 'three starting roles in English: %', pg_temp.role_names(v->'company'->>'id');
    END IF;
    RAISE NOTICE 'c: a company opened whole';
END $$;

-- d. A refusal after the first write leaves nothing.
DO $$
DECLARE
    v_admin  text;
    v_fp     text;
    v_raised boolean := false;
    v_msg    text;
    v_out    jsonb;
BEGIN
    v_admin := pg_temp.world('Deployment Co');
    v_fp := pg_temp.fingerprint();
    -- A history line of one kind is refused by the table, after the company, its
    -- administrator, its roles and its product were written.
    ALTER TABLE rolebyte.event ADD CONSTRAINT door_probe CHECK (kind <> 'serviceAccountAdded') NOT VALID;
    BEGIN
        CALL rolebyte.company_open(jsonb_build_object('actor', v_admin, 'mode', 'saas') || pg_temp.oi('"Late Co"'), v_out);
    EXCEPTION
        WHEN sqlstate 'P0001' THEN
            v_raised := true;
            v_msg := sqlerrm;
    END;
    ALTER TABLE rolebyte.event DROP CONSTRAINT door_probe;

    IF NOT v_raised OR v_msg::jsonb->>'code' IS DISTINCT FROM 'membership:error' THEN
        RAISE EXCEPTION 'a late refusal should be raised as a structured error: % %', v_raised, v_msg;
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM v_fp
       OR EXISTS (SELECT 1 FROM rolebyte.tenant WHERE name = 'Late Co') THEN
        RAISE EXCEPTION 'a late refusal must leave no tenant, account, product, entitlement, role or history line';
    END IF;
    -- And the door works again once the probe is gone.
    PERFORM pg_temp.dok('company_open', v_admin, pg_temp.oi('"Late Co"'), 'open after the probe');
    RAISE NOTICE 'd: a late refusal leaves nothing';
END $$;

-- e. Every validation of company_open; each writes nothing.
DO $$
DECLARE
    v_admin text;
BEGIN
    v_admin := pg_temp.world('Deployment Co');

    -- The name's boundaries.
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('""'), 'membership:invalid', NULL, 'an empty name');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"     "'), 'membership:invalid', NULL, 'a name of spaces');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi(NULL), 'membership:invalid', NULL, 'no name');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('5'), 'membership:invalid', NULL, 'a name that is a number');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi(to_jsonb('Bad' || chr(9) || 'name')),
        'membership:invalid', NULL, 'a name with a tab');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi(to_jsonb('Bad' || chr(7))),
        'membership:invalid', NULL, 'a name with a bell');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi(to_jsonb(repeat('x', 201))),
        'membership:invalid', NULL, 'a name of 201 characters');
    PERFORM pg_temp.dok('company_open', v_admin, pg_temp.oi(to_jsonb(repeat('x', 200))), 'a name of 200 characters');
    PERFORM pg_temp.dok('company_open', v_admin, pg_temp.oi('"Y"'), 'a name of one character');
    PERFORM pg_temp.dok('company_open', v_admin, pg_temp.oi(to_jsonb(repeat('z', 100) || '  ')), 'a name that is trimmed to fit');

    -- The language.
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Lang Co"', '"LV"'), 'membership:invalid', NULL, 'LV');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Lang Co"', '"de"'), 'membership:invalid', NULL, 'de');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Lang Co"', NULL), 'membership:invalid', NULL, 'no language');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Lang Co"', '1'), 'membership:invalid', NULL, 'a numeric language');

    -- The products, and the guard.
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Has Co"', '"en"', '["nope"]'),
        'membership:not_found', 'this deployment offers no such product', 'a product nobody registered');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Has Co"', '"en"', '["rolebyte"]'),
        'membership:not_found', 'this deployment offers no such product', 'a service''s key is no product');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Has Co"', '"en"', '["alpha-pack","alpha-pack"]'),
        'membership:invalid', NULL, 'a product twice');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Has Co"', '"en"', '"alpha-pack"'),
        'membership:invalid', NULL, 'products that are not a list');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Has Co"', '"en"', '[1]'),
        'membership:invalid', NULL, 'a product that is not text');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Has Co"', '"en"', '["alpha-plus"]'),
        'membership:conflict', 'this product needs alpha-pack', 'a product whose need is not in the list');
    PERFORM pg_temp.dok('company_open', v_admin, pg_temp.oi('"Plus Co"', '"en"', '["alpha-plus","alpha-pack"]'),
        'a product listed before the one it needs');

    -- The administrator.
    PERFORM pg_temp.drefused('company_open', v_admin,
        pg_temp.oi('"Adm Co"', '"en"', '[]', jsonb_build_object('subjectKey', 'svc:abc', 'displayName', 'A Service')),
        'membership:invalid', NULL, 'a service''s key as administrator');
    PERFORM pg_temp.drefused('company_open', v_admin,
        pg_temp.oi('"Adm Co"', '"en"', '[]', jsonb_build_object('subjectKey', 'sub:abc', 'displayName', 'A Person')),
        'membership:invalid', NULL, 'a key of another shape');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Adm Co"', '"en"', '[]', NULL),
        'membership:invalid', NULL, 'no administrator');
    PERFORM pg_temp.drefused('company_open', v_admin,
        pg_temp.oi('"Adm Co"', '"en"', '[]', jsonb_build_object('subjectKey', pg_temp.person(), 'displayName', '')),
        'membership:invalid', NULL, 'an administrator without a name');
    PERFORM pg_temp.drefused('company_open', v_admin,
        pg_temp.oi('"Adm Co"', '"en"', '[]', jsonb_build_object('subjectKey', pg_temp.person(),
                                                                 'displayName', repeat('n', 201))),
        'membership:invalid', NULL, 'an administrator name of 201 characters');
    PERFORM pg_temp.drefused('company_open', v_admin,
        pg_temp.oi('"Adm Co"', '"en"', '[]', jsonb_build_object('subjectKey', pg_temp.person(),
                                                                 'displayName', 'Bad' || chr(10))),
        'membership:invalid', NULL, 'an administrator name with a line break');

    -- The name is taken, in another letter case.
    PERFORM pg_temp.dok('company_open', v_admin, pg_temp.oi('"Dup Co"'), 'the first of a name');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"DUP co"'),
        'membership:conflict', 'a company of this name already exists', 'a name in another case');
    PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"deployment CO"'),
        'membership:conflict', 'a company of this name already exists', 'the deployment''s own company''s name');

    -- No service has declared itself: checked after the rest, before the name. Rolled back below.
    BEGIN
        TRUNCATE rolebyte.service CASCADE;
        PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Early Co"', '"en"', '[]'),
            'membership:conflict', 'the deployment''s services have not declared themselves yet',
            'no service declared');
        -- the register's own key does not count as a declared service
        PERFORM rolebyte.administrator_rung('fx');
        PERFORM pg_temp.drefused('company_open', v_admin, pg_temp.oi('"Early Co"', '"en"', '[]'),
            'membership:conflict', 'the deployment''s services have not declared themselves yet',
            'only the register''s own key');
        RAISE EXCEPTION 'undo' USING errcode = 'P0002';
    EXCEPTION
        WHEN sqlstate 'P0002' THEN NULL;
    END;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'alpha') THEN
        RAISE EXCEPTION 'the services should be back after the probe';
    END IF;
    RAISE NOTICE 'e: every validation of company_open';
END $$;

-- f. No product at all.
DO $$
DECLARE
    v_admin text;
    v       jsonb;
    v_t     text;
BEGIN
    v_admin := pg_temp.world('Deployment Co');
    v := pg_temp.dok('company_open', v_admin, pg_temp.oi('"Bare Co"', '"en"', NULL), 'open with no product');
    v_t := v->'company'->>'id';
    IF v->'products' IS DISTINCT FROM '[]'::jsonb OR v->'accounts' IS DISTINCT FROM '[]'::jsonb
       OR pg_temp.products(v_t) IS DISTINCT FROM '' OR pg_temp.has_rows(v_t) IS DISTINCT FROM ''
       OR pg_temp.lines('tenantEntitled', v_t) IS DISTINCT FROM 0
       OR (SELECT count(*) FROM rolebyte.user_account WHERE tenant_id = v_t) IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'a company with no product has nothing and no service account: %', v;
    END IF;
    v := pg_temp.dok('company_open', v_admin, pg_temp.oi('"Bare Co Two"', '"en"', '[]'), 'open with an empty list');
    IF v->'products' IS DISTINCT FROM '[]'::jsonb OR v->'accounts' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'an empty list is the same: %', v;
    END IF;
    RAISE NOTICE 'f: no product at all';
END $$;

-- g and h. Giving and taking a product, and the service accounts that follow.
DO $$
DECLARE
    v_admin  text;
    v_c      text;
    v_other  text;
    v        jsonb;
    v_person text := pg_temp.person();
    v_snap   text;
    v_ua     text;
    v_us     text;
BEGIN
    v_admin := pg_temp.world('Deployment Co');
    v_c := pg_temp.open_with(v_admin, 'Customer', '[]');

    -- One account nobody lists, and a person.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_c, 'subjectKey', 'svc:unlisted',
        'displayName', 'Nobody lists me'), 'an unlisted service account');
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_c, 'subjectKey', v_person,
        'displayName', 'A Person', 'roles', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'write'))), 'a person');
    v_snap := pg_temp.snap(v_c, ARRAY['svc:unlisted', v_person]);

    -- g. Give.
    v := pg_temp.has_set(v_admin, v_c, 'alpha-pack', true);
    IF (v->>'changed')::boolean IS DISTINCT FROM true
       OR v->'accounts'->'added' IS DISTINCT FROM '["svc:alpha-api","svc:alpha-sync","svc:shared"]'::jsonb
       OR v->'accounts'->'removed' IS DISTINCT FROM '[]'::jsonb
       OR pg_temp.products(v_c) IS DISTINCT FROM 'alpha-pack' OR pg_temp.has_keys(v_c) IS DISTINCT FROM 'alpha'
       OR pg_temp.lines('productTicked', v_c) IS DISTINCT FROM 1
       OR pg_temp.lines('tenantEntitled', v_c) IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'giving alpha-pack: %', v;
    END IF;
    -- h. The accounts of alpha-pack are active members with their levels; the other product's are not there.
    IF pg_temp.status(v_c, 'svc:alpha-api') IS DISTINCT FROM 'active'
       OR pg_temp.levels(v_c, 'svc:alpha-api') IS DISTINCT FROM 'alpha api:read, alpha api:write'
       OR pg_temp.status(v_c, 'svc:alpha-sync') IS DISTINCT FROM 'active'
       OR pg_temp.levels(v_c, 'svc:shared') IS DISTINCT FROM 'alpha api:read'
       OR pg_temp.status(v_c, 'svc:beta-api') IS NOT NULL THEN
        RAISE EXCEPTION 'the accounts of alpha-pack follow, beta-pack''s are not there';
    END IF;
    v_ua := pg_temp.uid(v_c, 'svc:alpha-api');
    v_us := pg_temp.uid(v_c, 'svc:shared');

    PERFORM pg_temp.dunchanged('company_has_set', v_admin,
        jsonb_build_object('tenantId', v_c, 'product', 'alpha-pack', 'has', true), 'give alpha-pack again');

    -- h. Give beta-pack: its account, an invited one, becomes active; the shared one holds the union.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_c, 'subjectKey', 'svc:beta-api',
        'displayName', 'Waiting'), 'a listed service account already invited');
    v := pg_temp.has_set(v_admin, v_c, 'beta-pack', true);
    IF v->'accounts'->'added' IS DISTINCT FROM '["svc:beta-api"]'::jsonb
       OR pg_temp.status(v_c, 'svc:beta-api') IS DISTINCT FROM 'active'
       OR pg_temp.levels(v_c, 'svc:beta-api') IS DISTINCT FROM 'beta api:sync'
       OR pg_temp.levels(v_c, 'svc:shared') IS DISTINCT FROM 'alpha api:read, beta api:sync' THEN
        RAISE EXCEPTION 'giving beta-pack: % shared holds %', v, pg_temp.levels(v_c, 'svc:shared');
    END IF;

    -- h. Take alpha-pack: its own accounts end, the shared one stays with beta's levels only.
    v := pg_temp.has_set(v_admin, v_c, 'alpha-pack', false);
    IF (v->>'changed')::boolean IS DISTINCT FROM true
       OR v->'accounts'->'removed' IS DISTINCT FROM '["svc:alpha-api","svc:alpha-sync"]'::jsonb
       OR v->'accounts'->'added' IS DISTINCT FROM '[]'::jsonb
       OR pg_temp.products(v_c) IS DISTINCT FROM 'beta-pack' OR pg_temp.has_keys(v_c) IS DISTINCT FROM 'beta'
       OR pg_temp.lines('productUnticked', v_c) IS DISTINCT FROM 1
       OR pg_temp.lines('tenantEntitlementRevoked', v_c) IS DISTINCT FROM 1
       OR pg_temp.status(v_c, 'svc:alpha-api') IS DISTINCT FROM 'revoked'
       OR pg_temp.levels(v_c, 'svc:alpha-api') IS DISTINCT FROM ''
       OR pg_temp.status(v_c, 'svc:alpha-sync') IS DISTINCT FROM 'revoked'
       OR pg_temp.status(v_c, 'svc:shared') IS DISTINCT FROM 'active'
       OR pg_temp.levels(v_c, 'svc:shared') IS DISTINCT FROM 'beta api:sync'
       OR pg_temp.lines('serviceAccountRemoved', v_c) IS DISTINCT FROM 2
       OR pg_temp.lines('userRevoked', v_c) IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'taking alpha-pack: % shared holds %', v, pg_temp.levels(v_c, 'svc:shared');
    END IF;
    PERFORM pg_temp.dunchanged('company_has_set', v_admin,
        jsonb_build_object('tenantId', v_c, 'product', 'alpha-pack', 'has', false), 'take alpha-pack again');

    -- h. Take beta-pack: now the shared one ends too.
    v := pg_temp.has_set(v_admin, v_c, 'beta-pack', false);
    IF v->'accounts'->'removed' IS DISTINCT FROM '["svc:beta-api","svc:shared"]'::jsonb
       OR pg_temp.status(v_c, 'svc:shared') IS DISTINCT FROM 'revoked'
       OR pg_temp.levels(v_c, 'svc:shared') IS DISTINCT FROM ''
       OR pg_temp.status(v_c, 'svc:beta-api') IS DISTINCT FROM 'revoked'
       OR pg_temp.has_rows(v_c) IS DISTINCT FROM '' THEN
        RAISE EXCEPTION 'taking beta-pack ends the rest: %', v;
    END IF;

    -- h. Given again it is the same account, active, with its levels back.
    v := pg_temp.has_set(v_admin, v_c, 'alpha-pack', true);
    IF (v->>'changed')::boolean IS DISTINCT FROM true
       OR v->'accounts'->'added' IS DISTINCT FROM '["svc:alpha-api","svc:alpha-sync","svc:shared"]'::jsonb
       OR pg_temp.uid(v_c, 'svc:alpha-api') IS DISTINCT FROM v_ua OR pg_temp.uid(v_c, 'svc:shared') IS DISTINCT FROM v_us
       OR pg_temp.status(v_c, 'svc:alpha-api') IS DISTINCT FROM 'active'
       OR pg_temp.levels(v_c, 'svc:alpha-api') IS DISTINCT FROM 'alpha api:read, alpha api:write'
       OR pg_temp.levels(v_c, 'svc:shared') IS DISTINCT FROM 'alpha api:read'
       OR pg_temp.lines('productTicked', v_c) IS DISTINCT FROM 3
       OR pg_temp.lines('tenantEntitled', v_c) IS DISTINCT FROM 3 THEN
        RAISE EXCEPTION 'giving alpha-pack again flips it back and reuses the accounts: %', v;
    END IF;

    -- h. What nobody lists, and a person, were never touched.
    IF pg_temp.snap(v_c, ARRAY['svc:unlisted', v_person]) IS DISTINCT FROM v_snap THEN
        RAISE EXCEPTION 'an unlisted service account and a person must be left as they were';
    END IF;

    -- g. The refusals.
    PERFORM pg_temp.drefused('company_has_set', v_admin,
        jsonb_build_object('tenantId', v_c, 'product', 'nope', 'has', true), 'membership:not_found',
        'this deployment offers no such product', 'give a product nobody registered');
    PERFORM pg_temp.drefused('company_has_set', v_admin,
        jsonb_build_object('tenantId', v_c, 'product', 'alpha', 'has', true), 'membership:not_found',
        'this deployment offers no such product', 'a service''s key is no product');
    PERFORM pg_temp.drefused('company_has_set', v_admin,
        jsonb_build_object('tenantId', pg_temp.person(), 'product', 'alpha-pack', 'has', true), 'membership:not_found',
        'no such company', 'give to an unknown company');
    PERFORM pg_temp.drefused('company_has_set', v_admin,
        jsonb_build_object('tenantId', pg_temp.person(), 'product', 'alpha-pack', 'has', false), 'membership:not_found',
        'no such company', 'take from an unknown company');
    PERFORM pg_temp.drefused('company_has_set', v_admin,
        jsonb_build_object('tenantId', v_c, 'product', 'alpha-pack', 'has', 'yes'), 'membership:invalid', NULL,
        'has that is not a boolean');
    PERFORM pg_temp.drefused('company_has_set', v_admin,
        jsonb_build_object('tenantId', v_c, 'product', 'alpha-pack'), 'membership:invalid', NULL, 'has left out');
    PERFORM pg_temp.drefused('company_has_set', v_admin,
        jsonb_build_object('product', 'alpha-pack', 'has', true), 'membership:invalid', NULL, 'no company named');

    -- g. Taking what was never given: a fresh company that never had beta-pack.
    v_other := pg_temp.open_with(v_admin, 'Never Had', '["alpha-pack"]');
    PERFORM pg_temp.drefused('company_has_set', v_admin,
        jsonb_build_object('tenantId', v_other, 'product', 'beta-pack', 'has', false), 'membership:not_found',
        'the company was never given this', 'take what was never given');
    v := pg_temp.dunchanged('company_has_set', v_admin,
        jsonb_build_object('tenantId', v_other, 'product', 'alpha-pack', 'has', true), 'give what it has already');
    RAISE NOTICE 'g, h: a product given and taken, the accounts that follow';
END $$;

-- i. The catalog.
DO $$
DECLARE
    v_admin text;
    v_c1    text;
    v_c2    text;
    v_c3    text;
    v       jsonb;
    v_list  jsonb;
    v_bad   jsonb;
    v_msg   text;
BEGIN
    v_admin := pg_temp.world('Deployment Co');
    v_c1 := pg_temp.open_with(v_admin, 'One', '["alpha-pack"]');
    v_c2 := pg_temp.open_with(v_admin, 'Two', '["alpha-pack","beta-pack"]');
    v_c3 := pg_temp.open_with(v_admin, 'Three', '["beta-pack"]');

    -- A longer catalog: an account more under alpha-pack and a product more; the two companies that have alpha-pack follow.
    v_list := jsonb_set(pg_temp.cat1(), '{0,accounts}', (pg_temp.cat1()->0->'accounts') ||
        jsonb_build_array(pg_temp.acct('svc:alpha-new', 'Alpha new', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read')))))
        || jsonb_build_array(pg_temp.prod('temp-pack', 'Temporary', jsonb_build_array(pg_temp.give('gamma', '')),
                                          '[]'::jsonb, '[]'::jsonb));
    v := pg_temp.reg(v_list);
    IF (v->>'registered')::int IS DISTINCT FROM 2 OR (v->>'unregistered')::int IS DISTINCT FROM 0
       OR (v->>'companies')::int IS DISTINCT FROM 2
       OR pg_temp.status(v_c1, 'svc:alpha-new') IS DISTINCT FROM 'active'
       OR pg_temp.levels(v_c2, 'svc:alpha-new') IS DISTINCT FROM 'alpha api:read'
       OR pg_temp.status(v_c3, 'svc:alpha-new') IS NOT NULL
       OR (SELECT count(*) FROM rolebyte.product) IS DISTINCT FROM 6
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'productRegistered' AND tenant_id IS NULL
              AND actor = 'fx' AND payload = '{"product":"alpha-pack"}') IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'a longer catalog: %', v;
    END IF;

    -- A shorter catalog: the new account and the new product are gone from it and an account loses a level.
    v_list := jsonb_set(pg_temp.cat1(), '{0,accounts,0,roles}', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read')));
    v := pg_temp.reg(v_list);
    IF (v->>'registered')::int IS DISTINCT FROM 1 OR (v->>'unregistered')::int IS DISTINCT FROM 1
       OR (v->>'companies')::int IS DISTINCT FROM 2
       OR pg_temp.levels(v_c1, 'svc:alpha-api') IS DISTINCT FROM 'alpha api:read'
       OR pg_temp.levels(v_c2, 'svc:alpha-api') IS DISTINCT FROM 'alpha api:read'
       OR (SELECT count(*) FROM rolebyte.product) IS DISTINCT FROM 5
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'productUnregistered' AND tenant_id IS NULL
              AND payload = '{"product":"temp-pack"}') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'a shorter catalog: %', v;
    END IF;
    -- An account that a product ticked for a company listed, and no list names any more, is ended
    -- in every company that has the product; the accounts still listed stay as they were.
    IF pg_temp.status(v_c1, 'svc:alpha-new') IS DISTINCT FROM 'revoked'
       OR pg_temp.levels(v_c1, 'svc:alpha-new') IS DISTINCT FROM ''
       OR pg_temp.status(v_c2, 'svc:alpha-new') IS DISTINCT FROM 'revoked'
       OR pg_temp.levels(v_c2, 'svc:alpha-new') IS DISTINCT FROM ''
       OR pg_temp.status(v_c3, 'svc:alpha-new') IS NOT NULL
       OR pg_temp.lines('serviceAccountRemoved', v_c1) IS DISTINCT FROM 1
       OR pg_temp.lines('serviceAccountRemoved', v_c2) IS DISTINCT FROM 1
       OR pg_temp.status(v_c1, 'svc:alpha-api') IS DISTINCT FROM 'active'
       OR pg_temp.status(v_c2, 'svc:alpha-api') IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'an account that left every list is ended where a ticked product listed it';
    END IF;

    -- The same catalog again changes nothing, in the catalog or in any company.
    v := pg_temp.reg(v_list);
    IF (v->>'registered')::int IS DISTINCT FROM 0 OR (v->>'unregistered')::int IS DISTINCT FROM 0
       OR (v->>'adopted')::int IS DISTINCT FROM 0 OR (v->>'companies')::int IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'the same catalog again: %', v;
    END IF;
    -- A rename is a change.
    v := pg_temp.reg(jsonb_set(v_list, '{2,displayName}', '"Alpha lite renamed"'));
    IF (v->>'registered')::int IS DISTINCT FROM 1 OR (v->>'unregistered')::int IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'a rename: %', v;
    END IF;
    v := pg_temp.reg(v_list);

    -- Each invalid product is refused whole, naming its position and never its key, with the catalog as it was.
    INSERT INTO rolebyte.role_definition (id, service_key, role_group, role_level)
    VALUES (util.generate_ulid(), 'alpha', 'deployment', 'probe');
    FOREACH v_bad IN ARRAY ARRAY[
        pg_temp.prod('Bad Key', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', '', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', 'X', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('nope', '')), '[]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('rolebyte', '')), '[]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', 'nothing')), '[]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', 'task'), pg_temp.give('alpha', 'task')),
                     '[]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '["ghost"]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '["x1"]'::jsonb, '[]'::jsonb),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('sub:' || util.generate_ulid(), 'X', '[]'::jsonb))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:', 'X', '[]'::jsonb))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:assistant-secretkey', 'X', '[]'::jsonb))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:x', '', '[]'::jsonb))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:x', 'Bad' || chr(9), '[]'::jsonb))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:x', 'X', '"read"'::jsonb))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:x', 'X', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'missing'))))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:x', 'X', jsonb_build_array(pg_temp.lvl('rolebyte', 'membership', 'admin'))))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:x', 'X', jsonb_build_array(pg_temp.lvl('alpha', 'membership', 'admin'))))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:x', 'X', jsonb_build_array(pg_temp.lvl('alpha', 'deployment', 'probe'))))),
        pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
                     jsonb_build_array(pg_temp.acct('svc:x', 'X', '[]'::jsonb), pg_temp.acct('svc:x', 'Y', '[]'::jsonb))),
        '"not an object"'::jsonb
    ] LOOP
        PERFORM pg_temp.refused('products_register',
            jsonb_build_object('actor', 'fx', 'products', v_list || jsonb_build_array(v_bad)),
            'membership:invalid', 'product 6', 'an invalid sixth product ' || left(v_bad::text, 70));
    END LOOP;
    PERFORM pg_temp.refused('products_register',
        jsonb_build_object('actor', 'fx', 'products', v_list || jsonb_build_array(v_list->0)),
        'membership:invalid', 'product 6 is listed twice', 'a product listed twice');
    -- Needs that form a circle.
    PERFORM pg_temp.refused('products_register',
        jsonb_build_object('actor', 'fx', 'products', v_list || jsonb_build_array(
            pg_temp.prod('c1', 'C1', jsonb_build_array(pg_temp.give('alpha', '')), '["c2"]'::jsonb, '[]'::jsonb),
            pg_temp.prod('c2', 'C2', jsonb_build_array(pg_temp.give('alpha', '')), '["c1"]'::jsonb, '[]'::jsonb))),
        'membership:invalid', 'circle', 'needs that form a circle');
    PERFORM pg_temp.refused('products_register', '{"actor":"fx"}', 'membership:invalid', NULL, 'no list');
    PERFORM pg_temp.refused('products_register', '{"actor":"fx","products":"x"}', 'membership:invalid', NULL,
        'a list that is not a list');
    PERFORM pg_temp.refused('products_register', jsonb_build_object('products', v_list),
        'membership:invalid', NULL, 'no actor');
    v := pg_temp.rb('products_register', jsonb_build_object('actor', 'fx', 'products', v_list ||
        jsonb_build_array(pg_temp.prod('x1', 'X', jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
            jsonb_build_array(pg_temp.acct('svc:assistant-secretkey', 'X', '[]'::jsonb))))));
    IF position('secretkey' IN v->>'message') > 0 THEN
        RAISE EXCEPTION 'a refusal must not repeat the key: %', v;
    END IF;
    -- Put the catalog back as every block starts from it.
    PERFORM pg_temp.reg(pg_temp.cat1());
    RAISE NOTICE 'i: the catalog, longer, shorter, refused';
END $$;

-- i2. A service account that a product listed and the list no longer names: ended where a ticked
-- product listed it, kept where another ticked product still lists it, and no other account touched.
DO $$
DECLARE
    v_admin   text;
    v_c1      text;
    v_c2      text;
    v_c4      text;
    v_c5      text;
    v         jsonb;
    v_with    jsonb;
    v_without jsonb;
    v_late    jsonb;
    v_snap_c1 text;
    v_snap_c4 text;
    v_before  text;
BEGIN
    v_admin := pg_temp.world('Deployment Co');
    v_c1 := pg_temp.open_with(v_admin, 'One', '["alpha-pack"]');
    v_c2 := pg_temp.open_with(v_admin, 'Two', '["alpha-pack","beta-pack"]');
    v_c4 := pg_temp.customer('No ticks');

    -- alpha-pack lists svc:gone as well; the second list leaves out svc:gone and svc:shared
    -- (which beta-pack still lists).
    v_with := jsonb_set(pg_temp.cat1(), '{0,accounts}', (pg_temp.cat1()->0->'accounts') ||
        jsonb_build_array(pg_temp.acct('svc:gone', 'Gone', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read')))));
    v_without := jsonb_set(pg_temp.cat1(), '{0,accounts}', (pg_temp.cat1()->0->'accounts') - 2);

    v := pg_temp.reg(v_with);
    IF (v->>'registered')::int IS DISTINCT FROM 1 OR (v->>'companies')::int IS DISTINCT FROM 2
       OR pg_temp.status(v_c1, 'svc:gone') IS DISTINCT FROM 'active'
       OR pg_temp.status(v_c2, 'svc:gone') IS DISTINCT FROM 'active'
       OR pg_temp.levels(v_c2, 'svc:shared') IS DISTINCT FROM 'alpha api:read, beta api:sync' THEN
        RAISE EXCEPTION 'the list that names svc:gone: %', v;
    END IF;

    -- An account made by hand in a company with a ticked product, and one with the same key as a
    -- listed account in a company with no ticked product: neither is touched by the entry below.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_c1, 'subjectKey', 'svc:handmade',
        'displayName', 'By hand', 'roles', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read'))), 'a hand-made account');
    UPDATE rolebyte.user_account SET status = 'active' WHERE tenant_id = v_c1 AND subject_key = 'svc:handmade';
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_c4, 'subjectKey', 'svc:gone',
        'displayName', 'Gone, by hand', 'roles', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read'))),
        'an account of the same key in a company with no ticked product');
    UPDATE rolebyte.user_account SET status = 'active' WHERE tenant_id = v_c4 AND subject_key = 'svc:gone';
    v_snap_c1 := pg_temp.snap(v_c1, ARRAY['svc:handmade']);
    v_snap_c4 := pg_temp.snap(v_c4, ARRAY['svc:gone']);

    v := pg_temp.reg(v_without);
    IF (v->>'registered')::int IS DISTINCT FROM 1 OR (v->>'unregistered')::int IS DISTINCT FROM 0
       OR (v->>'adopted')::int IS DISTINCT FROM 0 OR (v->>'companies')::int IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'the list that drops two accounts: %', v;
    END IF;
    -- svc:gone is ended in both companies that have alpha-pack.
    IF pg_temp.status(v_c1, 'svc:gone') IS DISTINCT FROM 'revoked' OR pg_temp.levels(v_c1, 'svc:gone') IS DISTINCT FROM ''
       OR pg_temp.status(v_c2, 'svc:gone') IS DISTINCT FROM 'revoked' OR pg_temp.levels(v_c2, 'svc:gone') IS DISTINCT FROM ''
       OR pg_temp.lines('userRevoked', v_c1) IS DISTINCT FROM 2 OR pg_temp.lines('userRevoked', v_c2) IS DISTINCT FROM 1
       OR pg_temp.lines('serviceAccountRemoved', v_c1) IS DISTINCT FROM 2
       OR pg_temp.lines('serviceAccountRemoved', v_c2) IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'a dropped account is ended in every company that has its product';
    END IF;
    -- svc:shared is ended where only alpha-pack listed it, and stays, with beta-pack's levels only,
    -- where beta-pack is ticked as well.
    IF pg_temp.status(v_c1, 'svc:shared') IS DISTINCT FROM 'revoked' OR pg_temp.levels(v_c1, 'svc:shared') IS DISTINCT FROM ''
       OR pg_temp.status(v_c2, 'svc:shared') IS DISTINCT FROM 'active'
       OR pg_temp.levels(v_c2, 'svc:shared') IS DISTINCT FROM 'beta api:sync' THEN
        RAISE EXCEPTION 'an account another ticked product still lists stays with that product''s levels only';
    END IF;
    -- What is still listed, an account made by hand and a company with no ticked product are as they were.
    IF pg_temp.status(v_c1, 'svc:alpha-api') IS DISTINCT FROM 'active'
       OR pg_temp.status(v_c1, 'svc:alpha-sync') IS DISTINCT FROM 'active'
       OR pg_temp.snap(v_c1, ARRAY['svc:handmade']) IS DISTINCT FROM v_snap_c1
       OR pg_temp.snap(v_c4, ARRAY['svc:gone']) IS DISTINCT FROM v_snap_c4
       OR pg_temp.status(v_c4, 'svc:gone') IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'listed accounts, an account made by hand and a company with no ticks are left as they are';
    END IF;

    -- The same list again changes nothing.
    v_before := pg_temp.fingerprint();
    v := pg_temp.reg(v_without);
    IF (v->>'registered')::int IS DISTINCT FROM 0 OR (v->>'unregistered')::int IS DISTINCT FROM 0
       OR (v->>'adopted')::int IS DISTINCT FROM 0 OR (v->>'companies')::int IS DISTINCT FROM 0
       OR pg_temp.fingerprint() IS DISTINCT FROM v_before THEN
        RAISE EXCEPTION 'the same list again: %', v;
    END IF;

    -- For an account whose key is on a list the list decides: an account a company made by hand under
    -- a key that no list names is left alone, but once a list names the key under a product this company
    -- does not have, the company's follow ends it; a company with no ticked product is never followed.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_c1, 'subjectKey', 'svc:late',
        'displayName', 'Made by hand', 'roles', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read'))), 'a hand-made account');
    UPDATE rolebyte.user_account SET status = 'active' WHERE tenant_id = v_c1 AND subject_key = 'svc:late';
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_c4, 'subjectKey', 'svc:late',
        'displayName', 'Made by hand', 'roles', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'read'))), 'the same key by hand');
    UPDATE rolebyte.user_account SET status = 'active' WHERE tenant_id = v_c4 AND subject_key = 'svc:late';
    v_snap_c1 := pg_temp.snap(v_c1, ARRAY['svc:late']);
    v_snap_c4 := pg_temp.snap(v_c4, ARRAY['svc:late']);
    PERFORM pg_temp.reg(v_without);
    IF pg_temp.snap(v_c1, ARRAY['svc:late']) IS DISTINCT FROM v_snap_c1
       OR pg_temp.snap(v_c4, ARRAY['svc:late']) IS DISTINCT FROM v_snap_c4 THEN
        RAISE EXCEPTION 'an entry that does not name the key leaves the hand-made accounts as they are';
    END IF;
    v_late := jsonb_set(v_without, '{1,accounts}', (v_without->1->'accounts') ||
        jsonb_build_array(pg_temp.acct('svc:late', 'Late', jsonb_build_array(pg_temp.lvl('beta', 'api', 'sync')))));
    v := pg_temp.reg(v_late);
    IF (v->>'registered')::int IS DISTINCT FROM 1 OR (v->>'companies')::int IS DISTINCT FROM 2
       OR pg_temp.status(v_c1, 'svc:late') IS DISTINCT FROM 'revoked'
       OR pg_temp.levels(v_c1, 'svc:late') IS DISTINCT FROM ''
       OR pg_temp.lines('userRevoked', v_c1) IS DISTINCT FROM 3
       OR pg_temp.lines('serviceAccountRemoved', v_c1) IS DISTINCT FROM 3
       OR pg_temp.status(v_c2, 'svc:late') IS DISTINCT FROM 'active'
       OR pg_temp.snap(v_c4, ARRAY['svc:late']) IS DISTINCT FROM v_snap_c4 THEN
        RAISE EXCEPTION 'a listed key ends the account a company made by hand, only where it is followed: %', v;
    END IF;
    v_before := pg_temp.fingerprint();
    v := pg_temp.reg(v_late);
    IF (v->>'registered')::int IS DISTINCT FROM 0 OR (v->>'companies')::int IS DISTINCT FROM 0
       OR pg_temp.fingerprint() IS DISTINCT FROM v_before THEN
        RAISE EXCEPTION 'the same entry again: %', v;
    END IF;

    -- A dropped account that is a company's last administrator: the whole entry is refused and
    -- the list stays as it was; made right, the same entry is accepted.
    PERFORM pg_temp.reg(v_with);
    v_c5 := pg_temp.open_with(v_admin, 'Last', '["alpha-pack"]');
    PERFORM pg_temp.ok('role_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_c5,
        'userId', pg_temp.uid(v_c5, 'svc:gone'), 'service', 'rolebyte', 'group', 'membership', 'level', 'admin'),
        'a rung given to the account that is to be dropped');
    UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = v_c5 AND NOT subject_key LIKE 'svc:%';
    PERFORM pg_temp.refused('products_register', jsonb_build_object('actor', 'fx', 'products', v_without),
        'membership:conflict', 'a company keeps at least one administrator',
        'a list that drops a company''s last administrator');
    IF NOT EXISTS (SELECT 1 FROM rolebyte.product_account WHERE product_key = 'alpha-pack' AND subject_key = 'svc:gone')
       OR pg_temp.status(v_c1, 'svc:gone') IS DISTINCT FROM 'active'
       OR pg_temp.status(v_c5, 'svc:gone') IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'a refused entry leaves the list and every company as they were';
    END IF;
    UPDATE rolebyte.user_account SET status = 'active' WHERE tenant_id = v_c5 AND NOT subject_key LIKE 'svc:%';
    v := pg_temp.reg(v_without);
    IF (v->>'companies')::int IS DISTINCT FROM 3
       OR pg_temp.status(v_c5, 'svc:gone') IS DISTINCT FROM 'revoked'
       OR pg_temp.status(v_c1, 'svc:gone') IS DISTINCT FROM 'revoked'
       OR EXISTS (SELECT 1 FROM rolebyte.product_account WHERE subject_key = 'svc:gone') THEN
        RAISE EXCEPTION 'the same entry with another administrator in the company: %', v;
    END IF;

    -- Put the catalog back as every block starts from it.
    PERFORM pg_temp.reg(pg_temp.cat1());
    RAISE NOTICE 'i2: a service account dropped from a product''s list';
END $$;

-- j and k. The administrators of a company, and the two fixed sentences.
DO $$
DECLARE
    v_admin  text;
    v_dep    text;
    v_c      text;
    v_first  text := pg_temp.person();
    v_new    text := pg_temp.person();
    v_member text;
    v_gone   text;
    v_plain  text;
    v_dadmin text;
    v        jsonb;
    v_direct jsonb;
BEGIN
    v_admin := pg_temp.world('Deployment Co');
    v_dep := pg_temp.dep();
    v_c := pg_temp.dok('company_open', v_admin, pg_temp.oi('"Customer"', '"en"', '[]',
        jsonb_build_object('subjectKey', v_first, 'displayName', 'First Admin')), 'open a customer')->'company'->>'id';

    v := pg_temp.dok('company_administrator_set', v_admin, jsonb_build_object('tenantId', v_c, 'subjectKey', v_new,
        'displayName', 'New Admin'), 'set for a non-member');
    IF (v->>'invited')::boolean IS DISTINCT FROM true OR (v->>'changed')::boolean IS DISTINCT FROM true
       OR v->>'tenantId' IS DISTINCT FROM v_c OR v->>'userId' IS DISTINCT FROM pg_temp.uid(v_c, v_new)
       OR pg_temp.status(v_c, v_new) IS DISTINCT FROM 'invited'
       OR NOT rolebyte.is_administrator(pg_temp.uid(v_c, v_new))
       OR pg_temp.lines('administratorSetByOperator', v_c) IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'set for a non-member: %', v;
    END IF;

    v_member := pg_temp.member(v_c, 'A Member', 'active');
    v := pg_temp.dok('company_administrator_set', v_admin, jsonb_build_object('tenantId', v_c, 'subjectKey', v_member),
        'set for a member');
    IF (v->>'invited')::boolean IS DISTINCT FROM false OR (v->>'changed')::boolean IS DISTINCT FROM true
       OR NOT rolebyte.is_administrator(pg_temp.uid(v_c, v_member))
       OR pg_temp.lines('administratorSetByOperator', v_c) IS DISTINCT FROM 3 THEN
        RAISE EXCEPTION 'set for a member: %', v;
    END IF;

    v := pg_temp.dunchanged('company_administrator_set', v_admin, jsonb_build_object('tenantId', v_c,
        'subjectKey', v_member), 'set for an administrator');
    IF (v->>'invited')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'set for an administrator invites nobody: %', v;
    END IF;

    -- A removed member: refused with a sentence that names nobody.
    v_gone := pg_temp.member(v_c, 'Gone Person', 'revoked');
    PERFORM pg_temp.drefused('company_administrator_set', v_admin, jsonb_build_object('tenantId', v_c,
        'subjectKey', v_gone), 'membership:conflict', 'this person no longer has access to the company',
        'set for a removed member');
    v := pg_temp.door('company_administrator_set', v_admin, jsonb_build_object('tenantId', v_c, 'subjectKey', v_gone));
    IF position('Gone' IN v->>'message') > 0 OR position(v_gone IN v->>'message') > 0 THEN
        RAISE EXCEPTION 'the refusal for a removed member names the person: %', v;
    END IF;
    PERFORM pg_temp.drefused('company_administrator_set', v_admin, jsonb_build_object('tenantId', v_c,
        'subjectKey', 'svc:client', 'displayName', 'A service'), 'membership:invalid', NULL, 'set for a service');
    PERFORM pg_temp.drefused('company_administrator_set', v_admin, jsonb_build_object('tenantId', v_c,
        'subjectKey', pg_temp.person()), 'membership:invalid', 'displayName is required', 'set for a stranger with no name');
    PERFORM pg_temp.drefused('company_administrator_set', v_admin, jsonb_build_object('tenantId', v_c,
        'subjectKey', pg_temp.person(), 'displayName', repeat('n', 201)), 'membership:invalid', NULL, 'set with a long name');
    PERFORM pg_temp.drefused('company_administrator_set', v_admin, jsonb_build_object('tenantId', pg_temp.person(),
        'subjectKey', pg_temp.person(), 'displayName', 'X'), 'membership:not_found', 'no such company', 'set in an unknown company');
    PERFORM pg_temp.drefused('company_administrator_set', v_admin, jsonb_build_object('subjectKey', pg_temp.person(),
        'displayName', 'X'), 'membership:invalid', NULL, 'set with no company');

    -- k. The administrators of the company, a revoked account not among them.
    v := pg_temp.dok('company_administrators', v_admin, jsonb_build_object('tenantId', v_c), 'list the administrators');
    IF jsonb_array_length(v->'administrators') IS DISTINCT FROM 3
       OR v->'administrators'->0->>'displayName' IS DISTINCT FROM 'A Member'
       OR v->'administrators'->1->>'displayName' IS DISTINCT FROM 'First Admin'
       OR v->'administrators'->2->>'displayName' IS DISTINCT FROM 'New Admin'
       OR v->'administrators'->2->>'subjectKey' IS DISTINCT FROM v_new
       OR v->'administrators'->2->>'status' IS DISTINCT FROM 'invited'
       OR v->'administrators'->0->>'userId' IS DISTINCT FROM pg_temp.uid(v_c, v_member)
       OR NOT (v->'administrators'->0 ? 'lastSignedInOn') THEN
        RAISE EXCEPTION 'the administrators: %', v;
    END IF;
    UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = v_c AND subject_key = v_new;
    v := pg_temp.dok('company_administrators', v_admin, jsonb_build_object('tenantId', v_c), 'list again');
    IF jsonb_array_length(v->'administrators') IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'a revoked account is not listed as an administrator: %', v;
    END IF;
    PERFORM pg_temp.drefused('company_administrators', v_admin, jsonb_build_object('tenantId', pg_temp.person()),
        'membership:not_found', NULL, 'the administrators of an unknown company');
    PERFORM pg_temp.drefused('company_administrators', v_admin, '{}', 'membership:invalid', NULL,
        'the administrators of no company');
    UPDATE rolebyte.user_account SET status = 'invited' WHERE tenant_id = v_c AND subject_key = v_new;

    -- Unset: another administrator stays; a member who is none is unchanged; the last is refused with a fixed sentence.
    v_plain := pg_temp.member(v_c, 'Plain', 'active');
    PERFORM pg_temp.dunchanged('company_administrator_unset', v_admin, jsonb_build_object('tenantId', v_c,
        'userId', pg_temp.uid(v_c, v_plain)), 'unset for a non-administrator');
    PERFORM pg_temp.drefused('company_administrator_unset', v_admin, jsonb_build_object('tenantId', v_c,
        'userId', pg_temp.uid(v_dep, v_admin)), 'membership:not_found', NULL, 'unset for another company''s account');
    PERFORM pg_temp.drefused('company_administrator_unset', v_admin, jsonb_build_object('tenantId', v_c),
        'membership:invalid', NULL, 'unset with no account');
    v := pg_temp.dok('company_administrator_unset', v_admin, jsonb_build_object('tenantId', v_c,
        'userId', pg_temp.uid(v_c, v_new)), 'unset one');
    IF (v->>'changed')::boolean IS DISTINCT FROM true OR rolebyte.is_administrator(pg_temp.uid(v_c, v_new))
       OR pg_temp.lines('administratorUnsetByOperator', v_c) IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'unset one: %', v;
    END IF;
    PERFORM pg_temp.dunchanged('company_administrator_unset', v_admin, jsonb_build_object('tenantId', v_c,
        'userId', pg_temp.uid(v_c, v_new)), 'unset again');
    PERFORM pg_temp.dok('company_administrator_unset', v_admin, jsonb_build_object('tenantId', v_c,
        'userId', pg_temp.uid(v_c, v_member)), 'unset another');
    PERFORM pg_temp.drefused('company_administrator_unset', v_admin, jsonb_build_object('tenantId', v_c,
        'userId', pg_temp.uid(v_c, v_first)), 'membership:conflict', 'a company keeps at least one administrator',
        'unset the last one');
    v := pg_temp.door('company_administrator_unset', v_admin, jsonb_build_object('tenantId', v_c,
        'userId', pg_temp.uid(v_c, v_first)));
    IF position('First' IN v->>'message') > 0 THEN
        RAISE EXCEPTION 'the refusal for the last administrator names the person: %', v;
    END IF;
    IF NOT rolebyte.is_administrator(pg_temp.uid(v_c, v_first)) THEN
        RAISE EXCEPTION 'the last administrator keeps the rung';
    END IF;

    -- k. The deployment's administrators, as deployment_admin_list answers them, a revoked account not among them.
    v_dadmin := pg_temp.admin();
    v := pg_temp.dok('deployment_admins', v_admin, '{}', 'list the deployment''s administrators');
    CALL rolebyte.deployment_admin_list('{}'::jsonb, v_direct);
    IF v IS DISTINCT FROM v_direct->'data' OR jsonb_array_length(v->'admins') IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'the deployment''s administrators are what deployment_admin_list answers: %', v;
    END IF;
    UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = v_dep AND subject_key = v_dadmin;
    v := pg_temp.dok('deployment_admins', v_admin, '{}', 'list again');
    CALL rolebyte.deployment_admin_list('{}'::jsonb, v_direct);
    IF jsonb_array_length(v->'admins') IS DISTINCT FROM 1 OR v IS DISTINCT FROM v_direct->'data'
       OR v->'admins'->0->>'subjectKey' IS DISTINCT FROM v_admin THEN
        RAISE EXCEPTION 'a revoked account is not listed among the deployment''s administrators: %', v;
    END IF;
    RAISE NOTICE 'j, k: the administrators of a company and of the deployment';
END $$;

-- l. The deployment's administrators: grant and revoke, and the last active one.
DO $$
DECLARE
    v_a       text;
    v_dep     text;
    v_member  text;
    v_invited text;
    v_gone    text;
    v         jsonb;
    v_b       text;
BEGIN
    v_a := pg_temp.world('Deployment Co');
    v_dep := pg_temp.dep();
    v_b := pg_temp.admin();
    v_member := pg_temp.member(v_dep, 'Active member', 'active');
    v_invited := pg_temp.member(v_dep, 'Invited member', 'invited');
    v_gone := pg_temp.member(v_dep, 'Removed member', 'revoked');

    v := pg_temp.dok('deployment_admin_grant', v_a, jsonb_build_object('subjectKey', v_member), 'grant to a member');
    IF (v->>'changed')::boolean IS DISTINCT FROM true OR v->>'userId' IS DISTINCT FROM pg_temp.uid(v_dep, v_member)
       OR NOT EXISTS (SELECT 1 FROM rolebyte.deployment_admin WHERE user_id = pg_temp.uid(v_dep, v_member)
                         AND added_from = 'screen' AND added_by = v_a)
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentAdminAdded' AND actor = v_a
              AND user_id = pg_temp.uid(v_dep, v_member) AND payload->>'addedFrom' = 'screen') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'grant to a member: %', v;
    END IF;
    v := pg_temp.dok('deployment_admin_grant', v_a, jsonb_build_object('subjectKey', v_invited), 'grant to an invited member');
    IF (v->>'changed')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'grant to an invited member: %', v;
    END IF;
    PERFORM pg_temp.drefused('deployment_admin_grant', v_a, jsonb_build_object('subjectKey', pg_temp.person()),
        'membership:not_found', NULL, 'grant to a non-member');
    PERFORM pg_temp.drefused('deployment_admin_grant', v_a, jsonb_build_object('subjectKey', v_gone),
        'membership:conflict', NULL, 'grant to a removed member');
    PERFORM pg_temp.drefused('deployment_admin_grant', v_a, jsonb_build_object('subjectKey', 'svc:client'),
        'membership:invalid', NULL, 'grant to a service');
    PERFORM pg_temp.drefused('deployment_admin_grant', v_a, '{}', 'membership:invalid', NULL, 'grant to nobody');
    PERFORM pg_temp.dunchanged('deployment_admin_grant', v_a, jsonb_build_object('subjectKey', v_member),
        'grant to one already listed');

    -- Revoke: another; one who is not listed; oneself with others left.
    v := pg_temp.dok('deployment_admin_revoke', v_a, jsonb_build_object('userId', pg_temp.uid(v_dep, v_b)),
        'revoke another');
    IF (v->>'changed')::boolean IS DISTINCT FROM true OR v->>'subjectKey' IS DISTINCT FROM v_b
       OR v->>'userId' IS DISTINCT FROM pg_temp.uid(v_dep, v_b)
       OR EXISTS (SELECT 1 FROM rolebyte.deployment_admin WHERE user_id = pg_temp.uid(v_dep, v_b))
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentAdminRemoved' AND actor = v_a
              AND user_id = pg_temp.uid(v_dep, v_b)) IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'revoke another: %', v;
    END IF;
    PERFORM pg_temp.drefused('deployment_admin_revoke', v_a, jsonb_build_object('userId', pg_temp.uid(v_dep, v_b)),
        'membership:not_found', NULL, 'revoke one who is not listed');
    PERFORM pg_temp.drefused('deployment_admin_revoke', v_a, '{}', 'membership:invalid', NULL, 'revoke nobody');

    v := pg_temp.dok('deployment_admin_revoke', v_a, jsonb_build_object('userId', pg_temp.uid(v_dep, v_a)),
        'revoke oneself with others left');
    IF (v->>'changed')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'revoke oneself: %', v;
    END IF;
    PERFORM pg_temp.drefused('company_list', v_a, '{}', 'membership:forbidden', 'not a deployment administrator',
        'the caller''s next call after revoking oneself');

    -- Two listed remain: the active member and the invited one. The invited one is no
    -- administrator yet, so the active member is the last, and cannot be removed.
    PERFORM pg_temp.drefused('deployment_admin_revoke', v_member, jsonb_build_object('userId', pg_temp.uid(v_dep, v_member)),
        'membership:conflict', 'the last deployment administrator cannot be removed',
        'revoke the last active one while an invited one is listed');
    PERFORM pg_temp.dok('deployment_admin_revoke', v_member, jsonb_build_object('userId', pg_temp.uid(v_dep, v_invited)),
        'revoke the invited one');
    PERFORM pg_temp.drefused('deployment_admin_revoke', v_member, jsonb_build_object('userId', pg_temp.uid(v_dep, v_member)),
        'membership:conflict', 'the last deployment administrator cannot be removed', 'revoke the last one');
    IF NOT EXISTS (SELECT 1 FROM rolebyte.deployment_admin WHERE user_id = pg_temp.uid(v_dep, v_member)) THEN
        RAISE EXCEPTION 'the last deployment administrator stays on the list';
    END IF;
    RAISE NOTICE 'l: grant and revoke of the deployment''s administrators';
END $$;

-- m. The first run.
DO $$
DECLARE
    v_a      text;
    v_dep    text;
    v        jsonb;
    v_local  text;
    v_member text;
BEGIN
    -- On saas: named, the roles in Latvian, no product.
    v_a := pg_temp.world('');
    v_dep := pg_temp.dep();
    PERFORM pg_temp.drefused('company_first_run', v_a, '{"name":"","language":"lv"}', 'membership:invalid', NULL, 'an empty name');
    PERFORM pg_temp.drefused('company_first_run', v_a, '{"name":"Pirmā","language":"LV"}', 'membership:invalid', NULL, 'a bad language');
    PERFORM pg_temp.drefused('company_first_run', v_a, '{"name":"Pirmā"}', 'membership:invalid', NULL, 'no language');
    v := pg_temp.dok('company_first_run', v_a, '{"name":"  Pirmā sabiedrība ","language":"lv"}', 'the first run on saas');
    IF v->'company' IS DISTINCT FROM jsonb_build_object('id', v_dep, 'name', 'Pirmā sabiedrība')
       OR (SELECT name FROM rolebyte.tenant WHERE id = v_dep) IS DISTINCT FROM 'Pirmā sabiedrība'
       OR pg_temp.role_names(v_dep) IS DISTINCT FROM 'Viesis,Vadītājs,Darbinieks'
       OR jsonb_array_length(v->'roles') IS DISTINCT FROM 3 OR v->'missing' IS DISTINCT FROM '[]'::jsonb
       OR v->'products' IS DISTINCT FROM '[]'::jsonb OR pg_temp.has_rows(v_dep) IS DISTINCT FROM ''
       OR (SELECT count(*) FROM rolebyte.user_account WHERE tenant_id = v_dep AND subject_key LIKE 'svc:%') IS DISTINCT FROM 0
       OR (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_dep AND kind = 'tenantRenamed' AND actor = v_a
              AND payload = '{"from":"","to":"Pirmā sabiedrība"}') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'the first run on saas: %', v;
    END IF;
    PERFORM pg_temp.drefused('company_first_run', v_a, '{"name":"Atkal","language":"lv"}', 'membership:conflict',
        'the company is already set up', 'the first run twice');

    -- A company named when it was made.
    v_a := pg_temp.world('Named at birth');
    PERFORM pg_temp.drefused('company_first_run', v_a, '{"name":"Other","language":"en"}', 'membership:conflict',
        'the company is already set up', 'a company named when made');

    -- No service declared: the name is still empty afterwards.
    v_a := pg_temp.world('');
    v_dep := pg_temp.dep();
    BEGIN
        TRUNCATE rolebyte.service CASCADE;
        PERFORM pg_temp.drefused('company_first_run', v_a, '{"name":"Pirmā","language":"lv"}', 'membership:conflict',
            'the deployment''s services have not declared themselves yet', 'no service declared');
        IF (SELECT name FROM rolebyte.tenant WHERE id = v_dep) IS DISTINCT FROM '' THEN
            RAISE EXCEPTION 'the name must still be empty';
        END IF;
        RAISE EXCEPTION 'undo' USING errcode = 'P0002';
    EXCEPTION
        WHEN sqlstate 'P0002' THEN NULL;
    END;

    -- On local, by the company's administrator: named, roles, every offered product, service accounts.
    v_a := pg_temp.world('');
    v_dep := pg_temp.dep();
    v_local := pg_temp.member(v_dep, 'Local admin', 'active');
    PERFORM pg_temp.ok('administrator_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep, 'subjectKey', v_local),
        'make a company administrator');
    v := pg_temp.ok('company_first_run', jsonb_build_object('actor', v_local, 'mode', 'local', 'name', 'Vietējā',
        'language', 'lv'), 'the first run on local');
    IF (SELECT name FROM rolebyte.tenant WHERE id = v_dep) IS DISTINCT FROM 'Vietējā'
       OR pg_temp.role_names(v_dep) IS DISTINCT FROM 'Viesis,Vadītājs,Darbinieks'
       OR v->'products' IS DISTINCT FROM '["alpha-lite","alpha-pack","alpha-plus","beta-pack","duo-pack"]'::jsonb
       OR pg_temp.has_keys(v_dep) IS DISTINCT FROM 'alpha,beta,delta,gamma'
       OR pg_temp.has_rows(v_dep) IS DISTINCT FROM 'alpha,alpha/task,beta,delta,gamma'
       OR v->'missing' IS DISTINCT FROM '[]'::jsonb
       OR (SELECT count(*) FROM rolebyte.user_account WHERE tenant_id = v_dep AND subject_key LIKE 'svc:%'
              AND status = 'active') IS DISTINCT FROM 4
       OR pg_temp.levels(v_dep, 'svc:shared') IS DISTINCT FROM 'alpha api:read, beta api:sync' THEN
        RAISE EXCEPTION 'the first run on local: %', v;
    END IF;

    -- On local, refused: a member who is no administrator, a non-member, a service; on saas, the company's
    -- administrator who is not on the list; on local with no company marked.
    v_a := pg_temp.world('');
    v_dep := pg_temp.dep();
    v_member := pg_temp.member(v_dep, 'Plain', 'active');
    v_local := pg_temp.member(v_dep, 'Local admin', 'active');
    PERFORM pg_temp.ok('administrator_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep, 'subjectKey', v_local),
        'make a company administrator');
    PERFORM pg_temp.refused('company_first_run', jsonb_build_object('actor', v_member, 'mode', 'local',
        'name', 'X', 'language', 'en'), 'membership:forbidden', 'not a deployment administrator', 'local, a plain member');
    PERFORM pg_temp.refused('company_first_run', jsonb_build_object('actor', pg_temp.person(), 'mode', 'local',
        'name', 'X', 'language', 'en'), 'membership:forbidden', 'not a deployment administrator', 'local, a non-member');
    PERFORM pg_temp.refused('company_first_run', jsonb_build_object('actor', 'svc:client', 'mode', 'local',
        'name', 'X', 'language', 'en'), 'membership:forbidden', 'not a deployment administrator', 'local, a service');
    PERFORM pg_temp.refused('company_first_run', jsonb_build_object('actor', v_local, 'mode', 'saas',
        'name', 'X', 'language', 'en'), 'membership:forbidden', 'not a deployment administrator',
        'saas, the company''s administrator who is not on the list');
    UPDATE rolebyte.user_account SET status = 'invited' WHERE tenant_id = v_dep AND subject_key = v_local;
    PERFORM pg_temp.refused('company_first_run', jsonb_build_object('actor', v_local, 'mode', 'local',
        'name', 'X', 'language', 'en'), 'membership:forbidden', 'not a deployment administrator', 'local, an invited administrator');
    DELETE FROM rolebyte.deployment_admin;
    DELETE FROM rolebyte.deployment;
    PERFORM pg_temp.refused('company_first_run', jsonb_build_object('actor', v_local, 'mode', 'local',
        'name', 'X', 'language', 'en'), 'membership:forbidden', 'not a deployment administrator', 'local, no company marked');
    RAISE NOTICE 'm: the first run';
END $$;

-- n. A deployment run on the customer's own machines follows what is offered.
DO $$
DECLARE
    v_a   text;
    v_dep text;
    v     jsonb;
BEGIN
    v_a := pg_temp.world('Local Co');
    v_dep := pg_temp.dep();
    BEGIN
        v := pg_temp.ok('local_company_follow', '{"actor":"svc:register","mode":"local"}', 'the first follow');
        IF v->'added' IS DISTINCT FROM '["alpha-lite","alpha-pack","alpha-plus","beta-pack","duo-pack"]'::jsonb
           OR (v->>'changed')::boolean IS DISTINCT FROM true
           OR pg_temp.has_keys(v_dep) IS DISTINCT FROM 'alpha,beta,delta,gamma'
           OR pg_temp.lines('productTicked', v_dep) IS DISTINCT FROM 5
           OR v->'accounts'->'added' IS DISTINCT FROM '["svc:alpha-api","svc:alpha-sync","svc:beta-api","svc:shared"]'::jsonb
           OR pg_temp.status(v_dep, 'svc:shared') IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION 'the first follow: %', v;
        END IF;
        PERFORM pg_temp.unchanged('local_company_follow', '{"actor":"svc:register","mode":"local"}', 'a second follow');

        -- A product offered after: had after the next follow.
        PERFORM pg_temp.reg(pg_temp.cat1() || jsonb_build_array(pg_temp.prod('late-pack', 'Late pack',
            jsonb_build_array(pg_temp.give('eps', '')), '["alpha-pack"]'::jsonb, '[]'::jsonb)));
        IF pg_temp.products(v_dep) LIKE '%late-pack%' THEN
            RAISE EXCEPTION 'a company that lacks what a product gives is not adopted into it';
        END IF;
        v := pg_temp.ok('local_company_follow', '{"actor":"svc:register","mode":"local"}', 'a follow after a new product');
        IF v->'added' IS DISTINCT FROM '["late-pack"]'::jsonb OR (v->>'changed')::boolean IS DISTINCT FROM true
           OR pg_temp.has_keys(v_dep) IS DISTINCT FROM 'alpha,beta,delta,eps,gamma' THEN
            RAISE EXCEPTION 'a newly offered product is had after the follow: %', v;
        END IF;
        PERFORM pg_temp.unchanged('local_company_follow', '{"actor":"svc:register","mode":"local"}', 'a follow after that');

        -- Refused.
        PERFORM pg_temp.refused('local_company_follow', '{"actor":"svc:register","mode":"saas"}', 'membership:invalid', NULL,
            'the follow on saas');
        PERFORM pg_temp.refused('local_company_follow', '{"actor":"svc:register"}', 'membership:invalid', NULL,
            'the follow with no mode');
        PERFORM pg_temp.refused('local_company_follow', '{"mode":"local"}', 'membership:invalid', NULL,
            'the follow with no actor');

        -- With no company marked it does nothing.
        DELETE FROM rolebyte.deployment_admin;
        DELETE FROM rolebyte.deployment;
        v := pg_temp.unchanged('local_company_follow', '{"actor":"svc:register","mode":"local"}', 'the follow with no company');
        IF v->'added' IS DISTINCT FROM '[]'::jsonb THEN
            RAISE EXCEPTION 'the follow with no company adds nothing: %', v;
        END IF;
        RAISE EXCEPTION 'undo' USING errcode = 'P0002';
    EXCEPTION
        WHEN sqlstate 'P0002' THEN NULL;
    END;
    RAISE NOTICE 'n: the follow on a deployment run on the customer''s own machines';
END $$;

-- o. The starting roles and the products on offer.
DO $$
DECLARE
    v_a      text;
    v_t      text := util.generate_ulid();
    v_t2     text := util.generate_ulid();
    v        jsonb;
BEGIN
    v_a := pg_temp.world('Deployment Co');

    -- A company with no roles gets them; again, nothing is made; a name it already uses is reported missing.
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_t, 'No roles yet'), (v_t2, 'Own worker');
    v := pg_temp.dok('company_roles_seed', v_a, jsonb_build_object('tenantId', v_t, 'language', 'lv'), 'seed a company');
    IF jsonb_array_length(v->'roles') IS DISTINCT FROM 3 OR v->'kept' IS DISTINCT FROM '[]'::jsonb
       OR v->'missing' IS DISTINCT FROM '[]'::jsonb
       OR pg_temp.role_names(v_t) IS DISTINCT FROM 'Viesis,Vadītājs,Darbinieks'
       OR pg_temp.lines('tenantRoleSeeded', v_t) IS DISTINCT FROM 3 THEN
        RAISE EXCEPTION 'seeding a company with no roles: %', v;
    END IF;
    v := pg_temp.dok('company_roles_seed', v_a, jsonb_build_object('tenantId', v_t, 'language', 'lv'), 'seed again');
    IF v->'roles' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(v->'kept') IS DISTINCT FROM 3
       OR v->'missing' IS DISTINCT FROM '[]'::jsonb OR pg_temp.lines('tenantRoleSeeded', v_t) IS DISTINCT FROM 3 THEN
        RAISE EXCEPTION 'seeding a company that has the roles makes nothing: %', v;
    END IF;

    INSERT INTO rolebyte.tenant_role (id, tenant_id, name) VALUES (util.generate_ulid(), v_t2, 'Worker');
    v := pg_temp.dok('company_roles_seed', v_a, jsonb_build_object('tenantId', v_t2, 'language', 'en'), 'seed a company with a Worker');
    IF jsonb_array_length(v->'roles') IS DISTINCT FROM 2 OR v->'missing' IS DISTINCT FROM '["worker"]'::jsonb
       OR (SELECT count(*) FROM rolebyte.tenant_role WHERE tenant_id = v_t2) IS DISTINCT FROM 3
       OR (SELECT count(*) FROM rolebyte.tenant_role WHERE tenant_id = v_t2 AND seed = 'worker') IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'a name the company already uses is reported missing: %', v;
    END IF;

    PERFORM pg_temp.drefused('company_roles_seed', v_a, jsonb_build_object('tenantId', v_t, 'language', 'de'),
        'membership:invalid', NULL, 'a language that is not offered');
    PERFORM pg_temp.drefused('company_roles_seed', v_a, jsonb_build_object('tenantId', v_t, 'language', 'LV'),
        'membership:invalid', NULL, 'a language in capitals');
    PERFORM pg_temp.drefused('company_roles_seed', v_a, jsonb_build_object('tenantId', v_t), 'membership:invalid', NULL,
        'no language');
    PERFORM pg_temp.drefused('company_roles_seed', v_a, jsonb_build_object('tenantId', pg_temp.person(), 'language', 'en'),
        'membership:not_found', NULL, 'an unknown company');
    PERFORM pg_temp.drefused('company_roles_seed', v_a, jsonb_build_object('language', 'en'),
        'membership:invalid', NULL, 'no company');

    -- The products on offer: what each gives, with the service's permissions and when it last declared.
    v := pg_temp.dok('deployment_products', v_a, '{}', 'the products on offer');
    IF jsonb_array_length(v->'products') IS DISTINCT FROM 5
       OR (SELECT jsonb_agg(p->>'key') FROM jsonb_array_elements(v->'products') p)
          IS DISTINCT FROM '["alpha-lite","alpha-pack","alpha-plus","beta-pack","duo-pack"]'::jsonb THEN
        RAISE EXCEPTION 'the products, by key: %', v;
    END IF;
    IF v->'products'->1->>'displayName' IS DISTINCT FROM 'Alpha pack'
       OR (v->'products'->1->>'offered')::boolean IS DISTINCT FROM true
       OR v->'products'->1->'needs' IS DISTINCT FROM '[]'::jsonb
       OR v->'products'->2->'needs' IS DISTINCT FROM '["alpha-pack"]'::jsonb
       OR jsonb_array_length(v->'products'->4->'gives') IS DISTINCT FROM 2
       OR v->'products'->1->'gives'->0->>'service' IS DISTINCT FROM 'alpha'
       OR v->'products'->1->'gives'->0->>'feature' IS DISTINCT FROM ''
       OR v->'products'->1->'gives'->0->>'serviceName' IS DISTINCT FROM 'Alpha'
       OR (v->'products'->1->'gives'->0->>'permissions')::int IS DISTINCT FROM 1
       OR v->'products'->1->'gives'->0->>'lastDeclaredAt' IS NULL
       OR v->'products'->0->'gives'->0->>'feature' IS DISTINCT FROM 'task'
       OR v->'products'->3->'gives'->0->'lastDeclaredAt' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'the products carry what they promise: %', v;
    END IF;
    -- A product whose service has only retired permissions still counts the live ones only.
    BEGIN
        UPDATE rolebyte.service_permission SET retired_at = now() WHERE service_key = 'alpha';
        v := pg_temp.dok('deployment_products', v_a, '{}', 'the products after a retirement');
        IF (v->'products'->1->'gives'->0->>'permissions')::int IS DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'a retired permission is not counted: %', v;
        END IF;
        -- A product whose service has only retired permissions is listed as not offered, and
        -- is refused when ticked or named at an opening; the others are still offered.
        IF (v->'products'->0->>'offered')::boolean IS DISTINCT FROM false
           OR (v->'products'->1->>'offered')::boolean IS DISTINCT FROM false
           OR (v->'products'->2->>'offered')::boolean IS DISTINCT FROM false
           OR (v->'products'->3->>'offered')::boolean IS DISTINCT FROM true
           OR (v->'products'->4->>'offered')::boolean IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'a product over retired permissions is not offered: %', v;
        END IF;
        PERFORM pg_temp.drefused('company_has_set', v_a,
            jsonb_build_object('tenantId', v_t, 'product', 'alpha-pack', 'has', true), 'membership:not_found',
            'this deployment offers no such product', 'tick a product that is not offered');
        PERFORM pg_temp.drefused('company_open', v_a, pg_temp.oi('"Retired Co"', '"en"', '["alpha-pack"]'),
            'membership:not_found', 'this deployment offers no such product', 'open with a product that is not offered');
        RAISE EXCEPTION 'undo' USING errcode = 'P0002';
    EXCEPTION
        WHEN sqlstate 'P0002' THEN NULL;
    END;
    RAISE NOTICE 'o: the starting roles and the products on offer';
END $$;

-- p. The companies' reads, and a suspended customer company.
DO $$
DECLARE
    v_a    text;
    v_dep  text;
    v_c1   text;
    v_c2   text;
    v_c3   text;
    v      jsonb;
    v_ids  jsonb;
BEGIN
    v_a := pg_temp.world('Deployment Co');
    v_dep := pg_temp.dep();
    v_c1 := pg_temp.open_with(v_a, 'Has alpha', '["alpha-pack"]');
    v_c2 := pg_temp.customer('Plain customer');
    v_c3 := pg_temp.open_with(v_a, 'Suspended', '[]');
    UPDATE rolebyte.tenant SET status = 'suspended' WHERE id = v_c3;

    v := pg_temp.dok('company_list', v_a, '{}', 'list the companies');
    SELECT jsonb_agg(id ORDER BY created_at, id) INTO v_ids FROM rolebyte.tenant;
    IF jsonb_array_length(v->'companies') IS DISTINCT FROM 4
       OR (SELECT jsonb_agg(c->'id') FROM jsonb_array_elements(v->'companies') c) IS DISTINCT FROM v_ids THEN
        RAISE EXCEPTION 'the companies come in the order they were made: %', v;
    END IF;
    IF (SELECT c FROM jsonb_array_elements(v->'companies') c WHERE c->>'id' = v_dep)
           IS DISTINCT FROM jsonb_build_object('id', v_dep, 'name', 'Deployment Co', 'status', 'active',
               'createdAt', (SELECT created_at FROM rolebyte.tenant WHERE id = v_dep), 'own', true,
               'products', '[]'::jsonb, 'entitlements', '[]'::jsonb, 'administrators', 0)
       OR (SELECT c->'products' FROM jsonb_array_elements(v->'companies') c WHERE c->>'id' = v_c1)
           IS DISTINCT FROM '["alpha-pack"]'::jsonb
       OR (SELECT c->'entitlements' FROM jsonb_array_elements(v->'companies') c WHERE c->>'id' = v_c1)
           IS DISTINCT FROM '[{"service":"alpha","feature":""}]'::jsonb
       OR (SELECT (c->>'administrators')::int FROM jsonb_array_elements(v->'companies') c WHERE c->>'id' = v_c1) IS DISTINCT FROM 1
       OR (SELECT (c->>'administrators')::int FROM jsonb_array_elements(v->'companies') c WHERE c->>'id' = v_c2) IS DISTINCT FROM 0
       OR (SELECT (c->>'own')::boolean FROM jsonb_array_elements(v->'companies') c WHERE c->>'id' = v_c1) IS DISTINCT FROM false
       OR (SELECT c->>'status' FROM jsonb_array_elements(v->'companies') c WHERE c->>'id' = v_c3) IS DISTINCT FROM 'suspended' THEN
        RAISE EXCEPTION 'the companies carry what they promise: %', v;
    END IF;

    -- A suspended company is listed with its status and can be given a product.
    v := pg_temp.has_set(v_a, v_c3, 'alpha-pack', true);
    IF (v->>'changed')::boolean IS DISTINCT FROM true OR pg_temp.products(v_c3) IS DISTINCT FROM 'alpha-pack' THEN
        RAISE EXCEPTION 'a suspended company can be given a product: %', v;
    END IF;

    -- One company, with the time each entitlement was given.
    v := pg_temp.dok('company_get', v_a, jsonb_build_object('tenantId', v_c3), 'get a company');
    IF v->'company'->>'status' IS DISTINCT FROM 'suspended' OR v->'company'->>'name' IS DISTINCT FROM 'Suspended'
       OR v->'company'->'products' IS DISTINCT FROM '["alpha-pack"]'::jsonb
       OR v->'company'->'entitlements'->0->>'service' IS DISTINCT FROM 'alpha'
       OR v->'company'->'entitlements'->0->>'feature' IS DISTINCT FROM ''
       OR v->'company'->'entitlements'->0->>'entitledAt' IS NULL
       OR (v->'company'->>'own')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'one company: %', v;
    END IF;
    v := pg_temp.dok('company_get', v_a, jsonb_build_object('tenantId', v_dep), 'get the deployment''s company');
    IF (v->'company'->>'own')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'the deployment''s company is its own: %', v;
    END IF;
    PERFORM pg_temp.drefused('company_get', v_a, '{}', 'membership:invalid', NULL, 'get with no company');
    PERFORM pg_temp.drefused('company_get', v_a, jsonb_build_object('tenantId', pg_temp.person()),
        'membership:not_found', NULL, 'get an unknown company');
    RAISE NOTICE 'p: the reads of the companies, a suspended company';
END $$;

-- q. Products: the guard in both directions, what a product gives, what an untick takes,
-- adoption, a catalog change, a product removed while had, and the accounts' administrators.
DO $$
DECLARE
    v_a     text;
    v_c     text;
    v_c2    text;
    v_c3    text;
    v_x     text;
    v_y     text;
    v_z     text;
    v_q     text;
    v       jsonb;
    v_list  jsonb;
    v_uid   text;
    v_pos   text;
    v_snap  text;
    v_n     int;
BEGIN
    v_a := pg_temp.world('Deployment Co');

    -- The guard, both ways.
    v_c := pg_temp.open_with(v_a, 'Guarded', '[]');
    PERFORM pg_temp.drefused('company_has_set', v_a,
        jsonb_build_object('tenantId', v_c, 'product', 'alpha-plus', 'has', true), 'membership:conflict',
        'this product needs alpha-pack', 'tick without the needed product');
    PERFORM pg_temp.has_set(v_a, v_c, 'alpha-pack', true);
    PERFORM pg_temp.has_set(v_a, v_c, 'alpha-plus', true);
    PERFORM pg_temp.drefused('company_has_set', v_a,
        jsonb_build_object('tenantId', v_c, 'product', 'alpha-pack', 'has', false), 'membership:conflict',
        'alpha-plus needs this product', 'untick while needed');
    PERFORM pg_temp.has_set(v_a, v_c, 'alpha-plus', false);
    PERFORM pg_temp.has_set(v_a, v_c, 'alpha-pack', false);
    IF pg_temp.products(v_c) IS DISTINCT FROM '' OR pg_temp.has_rows(v_c) IS DISTINCT FROM '' THEN
        RAISE EXCEPTION 'unticked in the right order, nothing is left: % %', pg_temp.products(v_c), pg_temp.has_rows(v_c);
    END IF;
    PERFORM pg_temp.drefused('company_has_set', v_a,
        jsonb_build_object('tenantId', v_c, 'product', 'beta-pack', 'has', false), 'membership:not_found',
        'the company was never given this', 'untick what was never ticked');

    -- A product giving two services, and one giving a feature of a service.
    PERFORM pg_temp.has_set(v_a, v_c, 'duo-pack', true);
    IF pg_temp.has_rows(v_c) IS DISTINCT FROM 'delta,gamma' THEN
        RAISE EXCEPTION 'a product giving two services gives both: %', pg_temp.has_rows(v_c);
    END IF;
    PERFORM pg_temp.has_set(v_a, v_c, 'alpha-lite', true);
    IF pg_temp.has_rows(v_c) IS DISTINCT FROM 'alpha/task,delta,gamma' OR pg_temp.has_keys(v_c) LIKE '%alpha%' THEN
        RAISE EXCEPTION 'a product giving one feature gives that feature only: %', pg_temp.has_rows(v_c);
    END IF;
    PERFORM pg_temp.has_set(v_a, v_c, 'duo-pack', false);
    PERFORM pg_temp.has_set(v_a, v_c, 'alpha-lite', false);
    IF pg_temp.has_rows(v_c) IS DISTINCT FROM '' THEN
        RAISE EXCEPTION 'both gone: %', pg_temp.has_rows(v_c);
    END IF;

    -- An untick with another ticked product giving the same service: that stays.
    v_c2 := pg_temp.open_with(v_a, 'Shares', '["alpha-pack","alpha-lite"]');
    PERFORM pg_temp.has_set(v_a, v_c2, 'alpha-pack', false);
    IF pg_temp.has_rows(v_c2) IS DISTINCT FROM 'alpha/task' THEN
        RAISE EXCEPTION 'what another ticked product still gives stays: %', pg_temp.has_rows(v_c2);
    END IF;
    -- Without it: every row of the service goes, a hand-written feature row included.
    v_c3 := pg_temp.open_with(v_a, 'Alone', '["alpha-pack"]');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_c3, 'service', 'alpha',
        'feature', 'task'), 'a feature row written by hand');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_c3, 'service', 'eps'),
        'a service nobody sells');
    IF pg_temp.has_rows(v_c3) IS DISTINCT FROM 'alpha,alpha/task,eps' THEN
        RAISE EXCEPTION 'the rows before the untick: %', pg_temp.has_rows(v_c3);
    END IF;
    PERFORM pg_temp.has_set(v_a, v_c3, 'alpha-pack', false);
    IF pg_temp.has_rows(v_c3) IS DISTINCT FROM 'eps'
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'tenantEntitlementRevoked' AND tenant_id = v_c3) IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'every row of the service is closed, the others left: %', pg_temp.has_rows(v_c3);
    END IF;

    -- Adoption: a company holding every entitlement of a product is ticked with the line, one holding
    -- only part is not, and a product whose need is not had is not adopted.
    v_a := pg_temp.world('Deployment Co');
    v_x := pg_temp.customer('Holds alpha');
    v_y := pg_temp.customer('Holds a feature');
    v_z := pg_temp.customer('Holds beta');
    v_q := pg_temp.customer('Holds half');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_x, 'service', 'alpha'), 'x');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_y, 'service', 'alpha',
        'feature', 'task'), 'y');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_z, 'service', 'beta'), 'z');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_q, 'service', 'gamma'), 'q');
    -- Without `adopt` a registration ticks nothing, and a product added over a service that
    -- companies hold gives them neither the product nor its accounts; a company with no
    -- ticked product is not touched at all.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', v_x, 'subjectKey', 'svc:alpha-api',
        'displayName', 'Waiting', 'roles', jsonb_build_array(pg_temp.lvl('alpha', 'api', 'write'))), 'an account of a product nobody has');
    v_snap := pg_temp.snap(v_x, ARRAY['svc:alpha-api', 'svc:extra']) || pg_temp.has_rows(v_x);
    v := pg_temp.reg(pg_temp.cat1() || jsonb_build_array(pg_temp.prod('alpha-extra', 'Alpha extra',
        jsonb_build_array(pg_temp.give('alpha', '')), '[]'::jsonb,
        jsonb_build_array(pg_temp.acct('svc:extra', 'Extra', '[]'::jsonb)))));
    IF (v->>'adopted')::int IS DISTINCT FROM 0 OR (v->>'companies')::int IS DISTINCT FROM 0
       OR pg_temp.products(v_x) IS DISTINCT FROM '' OR pg_temp.products(v_y) IS DISTINCT FROM ''
       OR pg_temp.status(v_x, 'svc:extra') IS NOT NULL
       OR pg_temp.snap(v_x, ARRAY['svc:alpha-api', 'svc:extra']) || pg_temp.has_rows(v_x) IS DISTINCT FROM v_snap THEN
        RAISE EXCEPTION 'registering without adopt ticks nothing and touches no company without a ticked product: %', v;
    END IF;
    PERFORM pg_temp.refused('products_register', jsonb_build_object('actor', 'fx', 'products', pg_temp.cat1(),
        'adopt', 'yes'), 'membership:invalid', 'adopt', 'adopt that is not a boolean');
    PERFORM pg_temp.reg(pg_temp.cat1());
    v := pg_temp.reg(pg_temp.cat1(), true);
    IF (v->>'adopted')::int IS DISTINCT FROM 5 OR (v->>'registered')::int IS DISTINCT FROM 0
       OR pg_temp.products(v_x) IS DISTINCT FROM 'alpha-lite,alpha-pack,alpha-plus'
       OR pg_temp.products(v_y) IS DISTINCT FROM 'alpha-lite'
       OR pg_temp.products(v_z) IS DISTINCT FROM 'beta-pack'
       OR pg_temp.products(v_q) IS DISTINCT FROM ''
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'productTicked' AND payload->>'adopted' = 'true'
              AND tenant_id = v_x) IS DISTINCT FROM 3
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'productTicked' AND payload = '{"product":"alpha-pack","adopted":true}'
              AND tenant_id = v_x AND actor = 'fx') IS DISTINCT FROM 1
       OR (v->>'companies')::int IS DISTINCT FROM 3 THEN
        RAISE EXCEPTION 'adoption: % x=% y=% z=% q=%', v, pg_temp.products(v_x), pg_temp.products(v_y),
            pg_temp.products(v_z), pg_temp.products(v_q);
    END IF;
    -- An adopted product is given like a ticked one: its feature row is written, so that
    -- unticking another product cannot close what it gives.
    IF pg_temp.has_rows(v_x) IS DISTINCT FROM 'alpha,alpha/task' OR pg_temp.has_rows(v_y) IS DISTINCT FROM 'alpha/task' THEN
        RAISE EXCEPTION 'adoption gives every entitlement of the product: % %', pg_temp.has_rows(v_x), pg_temp.has_rows(v_y);
    END IF;
    PERFORM pg_temp.has_set(v_a, v_x, 'alpha-plus', false);
    IF pg_temp.has_rows(v_x) IS DISTINCT FROM 'alpha,alpha/task' THEN
        RAISE EXCEPTION 'unticking one product closes nothing another adopted product gives: %', pg_temp.has_rows(v_x);
    END IF;
    PERFORM pg_temp.has_set(v_a, v_x, 'alpha-plus', true);
    -- Asked again, adoption has nothing left to do.
    v := pg_temp.reg(pg_temp.cat1(), true);
    IF (v->>'adopted')::int IS DISTINCT FROM 0 OR (v->>'companies')::int IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'adoption happens once: %', v;
    END IF;

    -- A new list may not break the guard: a product that a company has ticked cannot come to need one
    -- that company has not ticked.
    PERFORM pg_temp.refused('products_register', jsonb_build_object('actor', 'fx',
        'products', jsonb_set(pg_temp.cat1(), '{2,needs}', '["beta-pack"]'::jsonb)),
        'membership:conflict', 'alpha-lite needs beta-pack', 'a list that breaks the needs guard');

    -- The follow keeps a company's last administrator: ending the only administrator, here a service
    -- account holding the rung, is refused with a sentence naming nobody, and nothing changes.
    v_c := pg_temp.open_with(v_a, 'Last admin', '["alpha-pack"]');
    PERFORM pg_temp.ok('role_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
        'userId', pg_temp.uid(v_c, 'svc:alpha-api'), 'service', 'rolebyte', 'group', 'membership', 'level', 'admin'),
        'a rung given to a service account');
    UPDATE rolebyte.user_account SET status = 'revoked'
     WHERE tenant_id = v_c AND NOT subject_key LIKE 'svc:%';
    PERFORM pg_temp.drefused('company_has_set', v_a,
        jsonb_build_object('tenantId', v_c, 'product', 'alpha-pack', 'has', false), 'membership:conflict',
        'a company keeps at least one administrator', 'an untick that would end the last administrator');

    -- A levels-only repair counts as a change.
    v_c := pg_temp.open_with(v_a, 'Repaired', '["alpha-pack"]');
    UPDATE rolebyte.assignment SET state = 'revoked', revoked_at = now()
     WHERE user_id = pg_temp.uid(v_c, 'svc:alpha-api');
    v := pg_temp.has_set(v_a, v_c, 'alpha-pack', true);
    IF (v->>'changed')::boolean IS DISTINCT FROM true
       OR pg_temp.levels(v_c, 'svc:alpha-api') IS DISTINCT FROM 'alpha api:read, alpha api:write' THEN
        RAISE EXCEPTION 'a repair of levels alone is a change: %', v;
    END IF;
    UPDATE rolebyte.assignment SET state = 'revoked', revoked_at = now()
     WHERE user_id = pg_temp.uid(v_c, 'svc:alpha-api');
    v := pg_temp.reg(pg_temp.cat1());
    IF (v->>'companies')::int IS DISTINCT FROM 1
       OR pg_temp.levels(v_c, 'svc:alpha-api') IS DISTINCT FROM 'alpha api:read, alpha api:write' THEN
        RAISE EXCEPTION 'a registration counts a company whose levels alone were repaired: %', v;
    END IF;

    -- A catalog change: a service added to a ticked product is given, one removed is revoked, and what
    -- nobody ever sold is left alone.
    v_a := pg_temp.world('Deployment Co');
    v_c := pg_temp.open_with(v_a, 'Changing', '["beta-pack"]');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_c, 'service', 'eps'),
        'a service nobody sells');
    v_list := jsonb_set(pg_temp.cat1(), '{1,gives}',
        jsonb_build_array(pg_temp.give('beta', ''), pg_temp.give('delta', '')));
    v := pg_temp.reg(v_list);
    IF (v->>'registered')::int IS DISTINCT FROM 1 OR pg_temp.has_rows(v_c) IS DISTINCT FROM 'beta,delta,eps'
       OR (v->>'companies')::int IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'a service added to a ticked product is given: % %', v, pg_temp.has_rows(v_c);
    END IF;
    v_list := jsonb_set(pg_temp.cat1(), '{1,gives}', jsonb_build_array(pg_temp.give('delta', '')));
    v := pg_temp.reg(v_list);
    IF pg_temp.has_rows(v_c) IS DISTINCT FROM 'delta,eps'
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'tenantEntitlementRevoked' AND tenant_id = v_c
              AND payload = '{"service":"beta","feature":""}') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'a service taken from a ticked product is revoked: % %', v, pg_temp.has_rows(v_c);
    END IF;
    v := pg_temp.reg(pg_temp.cat1());

    -- A product removed from the list while a company has it is refused, and nothing changes.
    PERFORM pg_temp.refused('products_register',
        jsonb_build_object('actor', 'fx', 'products', (pg_temp.cat1() - 1)),
        'membership:conflict', 'cannot be removed', 'a product removed while a company has it');
    -- One nobody has can go.
    v := pg_temp.reg(pg_temp.cat1() - 4);
    IF (v->>'unregistered')::int IS DISTINCT FROM 1 OR EXISTS (SELECT 1 FROM rolebyte.product WHERE key = 'duo-pack') THEN
        RAISE EXCEPTION 'a product nobody has is removed: %', v;
    END IF;
    v := pg_temp.reg(pg_temp.cat1());

    -- The follow never grants and never takes an administrator's level, whatever the account holds.
    v_a := pg_temp.world('Deployment Co');
    v_c := pg_temp.open_with(v_a, 'Admin level', '["alpha-pack"]');
    v_uid := pg_temp.uid(v_c, 'svc:alpha-api');
    PERFORM pg_temp.ok('role_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_c, 'userId', v_uid,
        'service', 'rolebyte', 'group', 'membership', 'level', 'admin'), 'a rung given to a service account by hand');
    UPDATE rolebyte.product_account SET roles = jsonb_build_array(pg_temp.lvl('rolebyte', 'membership', 'admin'))
     WHERE product_key = 'alpha-pack' AND subject_key = 'svc:alpha-sync';
    UPDATE rolebyte.user_account SET note = 'memo' WHERE id = pg_temp.uid(v_c, 'svc:alpha-sync');
    INSERT INTO rolebyte.chart_position (id, tenant_id, name) VALUES ('seat-q', v_c, 'Seat');
    INSERT INTO rolebyte.chart_holder (tenant_id, user_id, position_id)
    VALUES (v_c, pg_temp.uid(v_c, 'svc:alpha-sync'), 'seat-q');
    PERFORM pg_temp.has_set(v_a, v_c, 'beta-pack', true);
    IF pg_temp.levels(v_c, 'svc:alpha-api') IS DISTINCT FROM 'alpha api:read, alpha api:write, rolebyte membership:admin'
       OR pg_temp.levels(v_c, 'svc:alpha-sync') IS DISTINCT FROM '' THEN
        RAISE EXCEPTION 'the follow leaves an administrator''s level as it is, in both directions: % / %',
            pg_temp.levels(v_c, 'svc:alpha-api'), pg_temp.levels(v_c, 'svc:alpha-sync');
    END IF;
    -- Ending an account also does what a removal does: its note and its seat go, with their lines.
    v := pg_temp.has_set(v_a, v_c, 'alpha-pack', false);
    IF pg_temp.status(v_c, 'svc:alpha-sync') IS DISTINCT FROM 'revoked'
       OR (SELECT note FROM rolebyte.user_account WHERE id = pg_temp.uid(v_c, 'svc:alpha-sync')) IS DISTINCT FROM ''
       OR EXISTS (SELECT 1 FROM rolebyte.chart_holder WHERE tenant_id = v_c AND user_id = pg_temp.uid(v_c, 'svc:alpha-sync'))
       OR (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_c AND user_id = pg_temp.uid(v_c, 'svc:alpha-sync')
              AND kind IN ('userRevoked', 'noteChanged', 'chartPersonRemoved', 'serviceAccountRemoved')) IS DISTINCT FROM 4
       OR pg_temp.status(v_c, 'svc:alpha-api') IS DISTINCT FROM 'revoked'
       OR (SELECT count(*) FROM rolebyte.assignment a JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
            WHERE a.user_id = v_uid AND a.state = 'granted' AND rd.service_key = 'rolebyte') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'ending a service account does what a removal does and leaves its administrator level: %', v;
    END IF;
    UPDATE rolebyte.product_account SET roles = '[]'::jsonb WHERE product_key = 'alpha-pack' AND subject_key = 'svc:alpha-sync';
    RAISE NOTICE 'q: products, the guard, what an untick takes, adoption, a catalog change';
END $$;

-- r. On the local mode the company's own administrator, who is on no list, is refused by every
-- procedure of the door but the first run, which is the one a local deployment runs.
DO $$
DECLARE
    v_a      text;
    v_dep    text;
    v_cust   text;
    v_other  text;
    v_local  text;
    v_inputs jsonb;
    v_proc   text;
    v        jsonb;
BEGIN
    v_a := pg_temp.world('');
    v_dep := pg_temp.dep();
    v_cust := pg_temp.customer('Customer One');
    v_other := pg_temp.member(v_cust, 'Other company', 'active');
    v_local := pg_temp.member(v_dep, 'Local admin', 'active');
    PERFORM pg_temp.ok('administrator_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep, 'subjectKey', v_local),
        'make a company administrator');
    IF EXISTS (SELECT 1 FROM rolebyte.deployment_admin da JOIN rolebyte.user_account u ON u.id = da.user_id
                WHERE u.subject_key = v_local)
       OR NOT rolebyte.is_administrator(pg_temp.uid(v_dep, v_local)) THEN
        RAISE EXCEPTION 'the local administrator is an administrator of the company and on no list';
    END IF;

    v_inputs := jsonb_build_object(
        'deployment_door_check', '{}'::jsonb,
        'company_list', '{}'::jsonb,
        'company_get', jsonb_build_object('tenantId', v_cust),
        'company_administrators', jsonb_build_object('tenantId', v_cust),
        'deployment_products', '{}'::jsonb,
        'deployment_admins', '{}'::jsonb,
        'company_open', pg_temp.oi(),
        'company_has_set', jsonb_build_object('tenantId', v_cust, 'product', 'alpha-pack', 'has', true),
        'company_administrator_set', jsonb_build_object('tenantId', v_cust, 'subjectKey', pg_temp.person(),
                                                        'displayName', 'Probe'),
        'company_administrator_unset', jsonb_build_object('tenantId', v_cust, 'userId', pg_temp.uid(v_cust, v_other)),
        'company_roles_seed', jsonb_build_object('tenantId', v_cust, 'language', 'lv'),
        'deployment_admin_grant', jsonb_build_object('subjectKey', v_other),
        'deployment_admin_revoke', jsonb_build_object('userId', pg_temp.uid(v_dep, v_a)));
    IF (SELECT count(*) FROM jsonb_object_keys(v_inputs)) IS DISTINCT FROM 13 THEN
        RAISE EXCEPTION 'the list lost a procedure of the door';
    END IF;

    FOR v_proc IN SELECT k FROM jsonb_object_keys(v_inputs) k LOOP
        PERFORM pg_temp.refused(v_proc,
            (v_inputs->v_proc) || jsonb_build_object('actor', v_local, 'mode', 'local'),
            'membership:forbidden', 'not a deployment administrator',
            v_proc || ' on local by the company''s own administrator');
    END LOOP;

    -- The control: the first run, the one a local deployment runs, is accepted.
    v := pg_temp.ok('company_first_run', jsonb_build_object('actor', v_local, 'mode', 'local', 'name', 'Own Co',
        'language', 'en'), 'the first run on local by the company''s own administrator');
    IF (SELECT name FROM rolebyte.tenant WHERE id = v_dep) IS DISTINCT FROM 'Own Co'
       OR v->'company'->>'name' IS DISTINCT FROM 'Own Co' THEN
        RAISE EXCEPTION 'the first run on local names the company: %', v;
    END IF;
    PERFORM pg_temp.refused('company_list', jsonb_build_object('actor', v_local, 'mode', 'local'),
        'membership:forbidden', 'not a deployment administrator', 'a read on local after the first run');
    RAISE NOTICE 'r: the local mode, the company''s own administrator';
END $$;

-- s. Opening a company with two products where the second cannot be given.
DO $$
DECLARE
    v_a text;
    v   jsonb;
BEGIN
    v_a := pg_temp.world('Deployment Co');

    -- The second product is a key the list does not hold.
    PERFORM pg_temp.drefused('company_open', v_a, pg_temp.oi('"Two Co"', '"en"', '["alpha-pack","nope"]'),
        'membership:not_found', 'this deployment offers no such product', 'a second product the list does not hold');

    -- The second product is in the list and not offered: every permission of its service is retired.
    BEGIN
        UPDATE rolebyte.service_permission SET retired_at = now() WHERE service_key = 'beta';
        IF rolebyte.product_offered('beta-pack') IS DISTINCT FROM false
           OR rolebyte.product_offered('alpha-pack') IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'only beta-pack is not offered now';
        END IF;
        PERFORM pg_temp.drefused('company_open', v_a, pg_temp.oi('"Two Co"', '"en"', '["alpha-pack","beta-pack"]'),
            'membership:not_found', 'this deployment offers no such product', 'a second product that is not offered');
        RAISE EXCEPTION 'undo' USING errcode = 'P0002';
    EXCEPTION
        WHEN sqlstate 'P0002' THEN NULL;
    END;

    -- The same opening with both valid is accepted.
    v := pg_temp.dok('company_open', v_a, pg_temp.oi('"Two Co"', '"en"', '["alpha-pack","beta-pack"]'),
        'open with two products that can be given');
    IF pg_temp.products(v->'company'->>'id') IS DISTINCT FROM 'alpha-pack,beta-pack'
       OR pg_temp.has_keys(v->'company'->>'id') IS DISTINCT FROM 'alpha,beta' THEN
        RAISE EXCEPTION 'the opening with two valid products: %', v;
    END IF;
    RAISE NOTICE 's: an opening with a second product that cannot be given';
END $$;

-- t. What is offered: a product over a service with no permission at all is listed as not offered and is
-- refused when ticked and when named at an opening; a service declared a day ago and one declared an hour
-- ago are both offered, each showing its own time. A product that gives the register's own service is
-- refused by the list (block i, the invalid product that gives `rolebyte`).
DO $$
DECLARE
    v_a    text;
    v_c    text;
    v      jsonb;
    v_day  timestamptz := now() - interval '1 day';
    v_hour timestamptz := now() - interval '1 hour';
BEGIN
    v_a := pg_temp.world('Deployment Co');
    v_c := pg_temp.customer('Ticks');
    BEGIN
        PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"bare","displayName":"Bare"}', 'register bare');
        PERFORM pg_temp.reg(pg_temp.cat1() || jsonb_build_array(pg_temp.prod('bare-pack', 'Bare pack',
            jsonb_build_array(pg_temp.give('bare', '')), '[]'::jsonb, '[]'::jsonb)));
        v := pg_temp.dok('deployment_products', v_a, '{}', 'the products on offer');
        IF (SELECT (p->>'offered')::boolean FROM jsonb_array_elements(v->'products') p WHERE p->>'key' = 'bare-pack')
              IS DISTINCT FROM false
           OR (SELECT p->'gives'->0->'lastDeclaredAt' FROM jsonb_array_elements(v->'products') p
                WHERE p->>'key' = 'bare-pack') IS DISTINCT FROM 'null'::jsonb
           OR (SELECT (p->'gives'->0->>'permissions')::int FROM jsonb_array_elements(v->'products') p
                WHERE p->>'key' = 'bare-pack') IS DISTINCT FROM 0
           OR (SELECT (p->>'offered')::boolean FROM jsonb_array_elements(v->'products') p WHERE p->>'key' = 'alpha-pack')
              IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'a product over a service that never declared itself is listed as not offered: %', v;
        END IF;
        PERFORM pg_temp.drefused('company_has_set', v_a,
            jsonb_build_object('tenantId', v_c, 'product', 'bare-pack', 'has', true), 'membership:not_found',
            'this deployment offers no such product', 'tick a product over a service with no permission');
        PERFORM pg_temp.drefused('company_open', v_a, pg_temp.oi('"Bare Co"', '"en"', '["bare-pack"]'),
            'membership:not_found', 'this deployment offers no such product',
            'open with a product over a service with no permission');
        RAISE EXCEPTION 'undo' USING errcode = 'P0002';
    EXCEPTION
        WHEN sqlstate 'P0002' THEN NULL;
    END;

    -- Age never hides a product: alpha last declared a day ago, beta an hour ago.
    UPDATE rolebyte.service_declaration SET last_declared_at = v_day WHERE service_key = 'alpha';
    INSERT INTO rolebyte.service_declaration (service_key, declared_by, first_declared_at, last_declared_at)
    VALUES ('beta', 'svc:beta-decl', v_day, v_hour);
    v := pg_temp.dok('deployment_products', v_a, '{}', 'the products on offer, declared at different times');
    IF (SELECT (p->>'offered')::boolean FROM jsonb_array_elements(v->'products') p WHERE p->>'key' = 'alpha-pack')
          IS DISTINCT FROM true
       OR (SELECT (p->'gives'->0->>'lastDeclaredAt')::timestamptz FROM jsonb_array_elements(v->'products') p
            WHERE p->>'key' = 'alpha-pack') IS DISTINCT FROM v_day
       OR (SELECT (p->>'offered')::boolean FROM jsonb_array_elements(v->'products') p WHERE p->>'key' = 'beta-pack')
          IS DISTINCT FROM true
       OR (SELECT (p->'gives'->0->>'lastDeclaredAt')::timestamptz FROM jsonb_array_elements(v->'products') p
            WHERE p->>'key' = 'beta-pack') IS DISTINCT FROM v_hour THEN
        RAISE EXCEPTION 'a product declared a day ago and one an hour ago are both offered, each with its own time: %', v;
    END IF;
    PERFORM pg_temp.has_set(v_a, v_c, 'alpha-pack', true);
    RAISE NOTICE 't: what is offered';
    RAISE NOTICE 'PASS unit.rolebyte_deployment_door';
END $$;

-- Everything above was done inside this transaction, tenants and services emptied
-- included: the register is left exactly as it was found.
ROLLBACK;
