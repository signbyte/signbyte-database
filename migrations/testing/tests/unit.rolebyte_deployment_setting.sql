-- Unit test: the person a deployment's settings name is applied by the register
-- (`deployment_admin_apply`), once per value, run as the register's own role.
-- Blocks, each labelled in the test below:
--   a  saas, no company, a name: a company with an empty name and no starting role,
--      marked; the person its invited administrator and on the list
--   b  saas, a marked company, never a member: invited, no administrator's rung, on the list
--   c  saas, an active and an invited member not on the list: put on it, nothing else changes
--   d  saas, a revoked member, twice: refused each time with its line, not listed, value not remembered
--   e  the same value twice: the second changes nothing
--   f  the same value after the entry was removed by hand: not put back
--   g  a second person's value: added, the first keeps the entry
--   h  values A, B, A with A's entry removed between: A is listed again
--   i  applied, revoked, the same value: refused with its line
--   j  never a member and no name, with a marked company and with none: a name is needed, nothing written
--   k  two companies, none marked: no company, nothing written
--   l  local, no company, a name: company made and marked, the person its invited administrator, list empty
--   m  local, one company: a new person, a member and a revoked member; list empty throughout
--   n  exactly one company, not marked: it is marked, then the person is classified
--   o  a mode of another spelling, no mode, a service's key, a malformed key, no actor: refused, nothing written
--   p  the columns, and the payloads this procedure writes
--   q  a suspended company is treated like any other
--   r  resolve: the right on saas once active, none on local
--   s  a value is the person with the mode: local then saas, and saas then local, apply again
--   t  a person already on the list from the screen, a new value: applied, no list entry, no line
--   u  local, a member already holding the rung, a new value: applied, no rung granted
--   v  one company, not marked, a revoked member: the company marked, the refusal line, nothing else
--   w  one company, not marked, never a member and no name: the company marked, nothing else
-- The answer's three flags (companyMarked, listAdded, rungGranted) are asserted in the blocks above.
-- Two instances calling at once are not shown here: one transaction cannot show it, and it rests on the lock.
--
-- The whole test runs in one transaction that is rolled back at the end. It empties the
-- register's tenants inside that transaction; the rollback restores them.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_deployment_setting.sql

BEGIN;

-- Calls one register procedure as the owner and returns its answer.
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

-- Calls deployment_admin_apply as the register's own role; returns the whole answer.
CREATE OR REPLACE FUNCTION pg_temp.apply_raw(p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    BEGIN
        EXECUTE 'SET ROLE rolebyte_public';
        CALL rolebyte.deployment_admin_apply(p_in, v);
        EXECUTE 'RESET ROLE';
    EXCEPTION
        WHEN sqlstate 'P0001' THEN
            v := sqlerrm::jsonb;
    END;
    RETURN v;
END $$;

-- An apply that must succeed; returns its data.
CREATE OR REPLACE FUNCTION pg_temp.apply(p_mode text, p_key text, p_name text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.apply_raw(jsonb_strip_nulls(jsonb_build_object(
        'actor', 'apply-test', 'mode', p_mode, 'subjectKey', p_key, 'displayName', p_name)));
BEGIN
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'apply failed: %', v;
    END IF;
    RETURN v->'data';
END $$;

-- What the register's tables and history hold, as one comparable text.
CREATE OR REPLACE FUNCTION pg_temp.fp() RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.tenant t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.user_account t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.assignment t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.tenant_role t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.deployment t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.deployment_admin t),
        (SELECT count(*) FROM rolebyte.event)))
$$;

CREATE OR REPLACE FUNCTION pg_temp.reset() RETURNS void
LANGUAGE sql AS $$ TRUNCATE rolebyte.tenant CASCADE $$;

-- A company, opened by the register's own act.
CREATE OR REPLACE FUNCTION pg_temp.company(p_name text) RETURNS text
LANGUAGE sql AS $$
    SELECT pg_temp.ok('tenant_create', jsonb_build_object('actor', 'setting-test', 'name', p_name), 'company ' || p_name)->>'id'
$$;

-- A company, marked as the deployment's own.
CREATE OR REPLACE FUNCTION pg_temp.marked_company(p_name text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_id text := pg_temp.company(p_name);
BEGIN
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'setting-test', 'tenantId', v_id), 'mark ' || p_name);
    RETURN v_id;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.person() RETURNS text
LANGUAGE sql AS $$ SELECT 'sub:' || util.generate_ulid() $$;

-- A member invited to a company; with p_active, claimed too.
CREATE OR REPLACE FUNCTION pg_temp.member(p_tenant text, p_key text, p_name text, p_active boolean) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_id text;
BEGIN
    v_id := pg_temp.ok('user_invite', jsonb_build_object('actor', 'setting-test', 'tenantId', p_tenant,
        'subjectKey', p_key, 'displayName', p_name), 'invite ' || p_name)->>'id';
    IF p_active THEN
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'setting-test', 'subjectKey', p_key), 'claim ' || p_name);
    END IF;
    RETURN v_id;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.revoke_member(p_tenant text, p_user text) RETURNS void
LANGUAGE sql AS $$
    SELECT pg_temp.ok('user_revoke', jsonb_build_object('actor', 'setting-test', 'tenantId', p_tenant, 'userId', p_user), 'revoke')
$$;

CREATE OR REPLACE FUNCTION pg_temp.account(p_tenant text, p_key text) RETURNS text
LANGUAGE sql AS $$
    SELECT id FROM rolebyte.user_account WHERE tenant_id = p_tenant AND subject_key = p_key
$$;

CREATE OR REPLACE FUNCTION pg_temp.status(p_user text) RETURNS text
LANGUAGE sql AS $$ SELECT status FROM rolebyte.user_account WHERE id = p_user $$;

CREATE OR REPLACE FUNCTION pg_temp.on_list(p_user text) RETURNS boolean
LANGUAGE sql AS $$ SELECT EXISTS (SELECT 1 FROM rolebyte.deployment_admin WHERE user_id = p_user) $$;

CREATE OR REPLACE FUNCTION pg_temp.has_rung(p_user text) RETURNS boolean
LANGUAGE sql AS $$
    SELECT EXISTS (SELECT 1
                     FROM rolebyte.assignment a
                     JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
                    WHERE a.user_id = p_user AND a.state = 'granted'
                      AND rd.service_key = 'rolebyte' AND rd.role_group = 'membership' AND rd.role_level = 'admin')
$$;

CREATE OR REPLACE FUNCTION pg_temp.lines(p_kind text, p_tenant text) RETURNS int
LANGUAGE sql AS $$ SELECT count(*)::int FROM rolebyte.event WHERE kind = p_kind AND tenant_id = p_tenant $$;

CREATE OR REPLACE FUNCTION pg_temp.listed() RETURNS int
LANGUAGE sql AS $$ SELECT count(*)::int FROM rolebyte.deployment_admin $$;

-- The answer carries this outcome.
CREATE OR REPLACE FUNCTION pg_temp.expect(p_out jsonb, p_outcome text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_out->>'outcome' IS DISTINCT FROM p_outcome THEN
        RAISE EXCEPTION '% should answer %: %', p_why, p_outcome, p_out;
    END IF;
END $$;

-- The call must be refused membership:invalid, name nothing of the key, and write nothing.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_in jsonb, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    before text := pg_temp.fp();
    v      jsonb := pg_temp.apply_raw(p_in);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION '% should be refused membership:invalid: %', p_why, v;
    END IF;
    IF p_in->>'subjectKey' IS NOT NULL AND position(p_in->>'subjectKey' IN v::text) > 0 THEN
        RAISE EXCEPTION '% was refused with a message that repeats the key: %', p_why, v;
    END IF;
    IF pg_temp.fp() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.membership(p_subject text, p_tenant text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', p_subject), v);
    RETURN (SELECT m FROM jsonb_array_elements(v->'data'->'memberships') m WHERE m->>'tenantId' = p_tenant);
END $$;

DO $$
DECLARE
    v      jsonb;
    v_fp   text;
    v_svc  text := 'sdset' || lower(substr(util.generate_ulid(), 20, 6));
    v_co   text;
    v_co2  text;
    v_p    text;
    v_q    text;
    v_r    text;
    v_ua   text;
    v_ub   text;
    v_up   text;
    v_uq   text;
    v_ur   text;
    v_snap text;
    v_n    int;
    v_at   timestamptz;
    v_m    jsonb;
BEGIN
    -- a. saas, no company, a name. The fixture declares a permission that a starting
    --    role would hold, so seeding the company's roles would have made one.
    PERFORM pg_temp.reset();
    PERFORM pg_temp.ok('service_register', jsonb_build_object('actor', 'setting-test', 'service', v_svc,
        'displayName', 'Setting demo'), 'a: register the service');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'setting-test', 'service', v_svc,
        'permission', jsonb_build_object('feature', 'task', 'act', 'view', 'description', 'See tasks',
            'class', 'ordinary', 'plane', 'object', 'seeds', jsonb_build_array('worker'))), 'a: a seeding permission');
    v_co := pg_temp.company('Scratch');
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role WHERE tenant_id = v_co) THEN
        RAISE EXCEPTION 'a: precondition: a company opened by tenant_create should hold a starting role';
    END IF;
    PERFORM pg_temp.reset();

    v_p := pg_temp.person();
    v := pg_temp.apply('saas', v_p, 'Anna Ozola');
    PERFORM pg_temp.expect(v, 'applied', 'a: a fresh deployment');
    IF (v->>'companyMade')::boolean IS DISTINCT FROM true OR (v->>'memberAdded')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'a: should answer companyMade and memberAdded true: %', v;
    END IF;
    IF (v->>'companyMarked')::boolean IS DISTINCT FROM true OR (v->>'listAdded')::boolean IS DISTINCT FROM true
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'a: should answer companyMarked, listAdded and rungGranted true: %', v;
    END IF;
    v_co := v->>'companyId';
    v_up := v->>'userId';
    IF (SELECT count(*) FROM rolebyte.tenant) IS DISTINCT FROM 1
       OR (SELECT name FROM rolebyte.tenant WHERE id = v_co) IS DISTINCT FROM ''
       OR (SELECT company_tenant_id FROM rolebyte.deployment) IS DISTINCT FROM v_co THEN
        RAISE EXCEPTION 'a: one company with an empty name, marked as the deployment''s own';
    END IF;
    IF pg_temp.status(v_up) IS DISTINCT FROM 'invited' OR pg_temp.account(v_co, v_p) IS DISTINCT FROM v_up
       OR NOT pg_temp.has_rung(v_up) THEN
        RAISE EXCEPTION 'a: the person should be an invited member holding the administrator''s rung';
    END IF;
    IF (SELECT added_from FROM rolebyte.deployment_admin WHERE user_id = v_up) IS DISTINCT FROM 'settings'
       OR pg_temp.listed() IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'a: the person should be on the list as added from the settings';
    END IF;
    IF pg_temp.lines('tenantCreated', v_co) <> 1 OR pg_temp.lines('deploymentCompanyMarked', v_co) <> 1
       OR pg_temp.lines('userInvited', v_co) <> 1 OR pg_temp.lines('roleGranted', v_co) <> 1
       OR pg_temp.lines('deploymentAdminAdded', v_co) <> 1 OR pg_temp.lines('deploymentAdminSettingApplied', v_co) <> 1 THEN
        RAISE EXCEPTION 'a: each history line should be written once';
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.tenant_role WHERE tenant_id = v_co)
       OR pg_temp.lines('tenantRoleSeeded', v_co) <> 0 THEN
        RAISE EXCEPTION 'a: no starting role should be made for the company';
    END IF;

    -- p. The columns and the payloads this procedure writes (on the company of a).
    IF (SELECT admin_setting_subject_key FROM rolebyte.deployment) IS DISTINCT FROM v_p
       OR (SELECT admin_setting_applied_at FROM rolebyte.deployment) IS NULL THEN
        RAISE EXCEPTION 'p: the deployment''s row should hold the key and a time';
    END IF;
    IF (SELECT payload FROM rolebyte.event WHERE tenant_id = v_co AND kind = 'deploymentAdminSettingApplied')
           IS DISTINCT FROM '{"mode": "saas"}'::jsonb
       OR (SELECT payload FROM rolebyte.event WHERE tenant_id = v_co AND kind = 'deploymentAdminAdded')
           IS DISTINCT FROM '{"addedFrom": "settings"}'::jsonb
       OR (SELECT payload FROM rolebyte.event WHERE tenant_id = v_co AND kind = 'deploymentCompanyMarked')
           IS DISTINCT FROM '{}'::jsonb
       OR (SELECT payload FROM rolebyte.event WHERE tenant_id = v_co AND kind = 'tenantCreated')
           IS DISTINCT FROM '{"name": ""}'::jsonb THEN
        RAISE EXCEPTION 'p: the payloads written should hold what they name and nothing more';
    END IF;

    -- b. saas, a marked company, never a member, a name.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company B');
    v_q := pg_temp.person();
    v_uq := pg_temp.member(v_co, v_q, 'Other Member', true);
    v_fp := md5((SELECT t::text FROM rolebyte.user_account t WHERE id = v_uq) ||
                (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.assignment t WHERE user_id = v_uq));
    v_p := pg_temp.person();
    v := pg_temp.apply('saas', v_p, 'Berta Liepa');
    PERFORM pg_temp.expect(v, 'applied', 'b: a never-member');
    v_up := v->>'userId';
    IF (v->>'memberAdded')::boolean IS DISTINCT FROM true OR (v->>'companyMade')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'b: should answer memberAdded true and companyMade false: %', v;
    END IF;
    IF (v->>'listAdded')::boolean IS DISTINCT FROM true OR (v->>'companyMarked')::boolean IS DISTINCT FROM false
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'b: should answer listAdded true, companyMarked and rungGranted false: %', v;
    END IF;
    IF pg_temp.status(v_up) IS DISTINCT FROM 'invited' OR pg_temp.has_rung(v_up) OR NOT pg_temp.on_list(v_up) THEN
        RAISE EXCEPTION 'b: an invited member holding no administrator''s rung, on the list';
    END IF;
    IF (SELECT count(*) FROM rolebyte.assignment WHERE user_id = v_up) <> 0 THEN
        RAISE EXCEPTION 'b: the new member should hold no role at all';
    END IF;
    IF v_fp IS DISTINCT FROM md5((SELECT t::text FROM rolebyte.user_account t WHERE id = v_uq) ||
                (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.assignment t WHERE user_id = v_uq))
       OR pg_temp.listed() IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'b: no other account should change';
    END IF;

    -- c. saas, an active member and an invited member, neither on the list.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company C');
    v_p := pg_temp.person();
    v_q := pg_temp.person();
    v_ua := pg_temp.member(v_co, v_p, 'Active One', true);
    v_ub := pg_temp.member(v_co, v_q, 'Invited Two', false);
    v_snap := md5((SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.user_account t) ||
                  (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.assignment t));
    v := pg_temp.apply('saas', v_p, NULL);
    PERFORM pg_temp.expect(v, 'applied', 'c: the active member');
    IF (v->>'memberAdded')::boolean IS DISTINCT FROM false OR v->>'userId' IS DISTINCT FROM v_ua THEN
        RAISE EXCEPTION 'c: the active member is not added again: %', v;
    END IF;
    IF (v->>'listAdded')::boolean IS DISTINCT FROM true OR (v->>'companyMarked')::boolean IS DISTINCT FROM false
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'c: should answer listAdded true, companyMarked and rungGranted false: %', v;
    END IF;
    v := pg_temp.apply('saas', v_q, NULL);
    PERFORM pg_temp.expect(v, 'applied', 'c: the invited member');
    IF NOT pg_temp.on_list(v_ua) OR NOT pg_temp.on_list(v_ub) OR pg_temp.listed() IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'c: both should be on the list';
    END IF;
    IF v_snap IS DISTINCT FROM md5((SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.user_account t) ||
                  (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.assignment t)) THEN
        RAISE EXCEPTION 'c: accounts and roles should be unchanged';
    END IF;

    -- d. saas, a revoked member, called twice. Another person was applied first, so
    --    the remembered value is known and must stay.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company D');
    v_q := pg_temp.person();
    PERFORM pg_temp.apply('saas', v_q, 'First Person');
    SELECT admin_setting_applied_at INTO v_at FROM rolebyte.deployment;
    v_r := pg_temp.person();
    v_ur := pg_temp.member(v_co, v_r, 'Revoked Person', true);
    PERFORM pg_temp.revoke_member(v_co, v_ur);
    v_fp := pg_temp.fp();
    v_n := (SELECT count(*) FROM rolebyte.event);
    v := pg_temp.apply('saas', v_r, 'Revoked Person');
    PERFORM pg_temp.expect(v, 'removedMember', 'd: the first call');
    IF (v->>'companyMarked')::boolean IS DISTINCT FROM false OR (v->>'listAdded')::boolean IS DISTINCT FROM false
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'd: a refusal marks, lists and grants nothing: %', v;
    END IF;
    IF v->>'userId' IS DISTINCT FROM v_ur OR v->>'companyId' IS DISTINCT FROM v_co THEN
        RAISE EXCEPTION 'd: should answer the account and company: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.event) IS DISTINCT FROM v_n + 1 THEN
        RAISE EXCEPTION 'd: the first call should write exactly one history line';
    END IF;
    v := pg_temp.apply('saas', v_r, NULL);
    PERFORM pg_temp.expect(v, 'removedMember', 'd: the second call');
    IF (SELECT count(*) FROM rolebyte.event) IS DISTINCT FROM v_n + 2
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentAdminRefused' AND user_id = v_ur) <> 2 THEN
        RAISE EXCEPTION 'd: two deploymentAdminRefused lines';
    END IF;
    IF (SELECT payload FROM rolebyte.event WHERE kind = 'deploymentAdminRefused' AND user_id = v_ur LIMIT 1)
           IS DISTINCT FROM '{"from": "settings", "reason": "revoked"}'::jsonb THEN
        RAISE EXCEPTION 'p: the refusal line should hold only where it came from and why';
    END IF;
    IF pg_temp.on_list(v_ur) OR pg_temp.listed() IS DISTINCT FROM 1 OR pg_temp.status(v_ur) IS DISTINCT FROM 'revoked' THEN
        RAISE EXCEPTION 'd: not listed, and still revoked';
    END IF;
    IF (SELECT admin_setting_subject_key FROM rolebyte.deployment) IS DISTINCT FROM v_q
       OR (SELECT admin_setting_applied_at FROM rolebyte.deployment) IS DISTINCT FROM v_at THEN
        RAISE EXCEPTION 'd: the remembered value should be untouched';
    END IF;

    -- e. The same value twice.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company E');
    v_p := pg_temp.person();
    PERFORM pg_temp.expect(pg_temp.apply('saas', v_p, 'Elza Kalna'), 'applied', 'e: the first');
    v_fp := pg_temp.fp();
    v := pg_temp.apply('saas', v_p, NULL);
    PERFORM pg_temp.expect(v, 'unchanged', 'e: the second');
    IF pg_temp.fp() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'e: unchanged should write nothing';
    END IF;
    IF (v->>'companyMarked')::boolean IS DISTINCT FROM false OR (v->>'listAdded')::boolean IS DISTINCT FROM false
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'e: unchanged marks, lists and grants nothing: %', v;
    END IF;

    -- f. The same value after the entry was removed by hand: not put back.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company F');
    v_p := pg_temp.person();
    v_up := pg_temp.apply('saas', v_p, 'Filips Ozols')->>'userId';
    PERFORM pg_temp.ok('deployment_admin_remove', jsonb_build_object('actor', 'setting-test', 'userId', v_up), 'f: remove');
    v_fp := pg_temp.fp();
    PERFORM pg_temp.expect(pg_temp.apply('saas', v_p, NULL), 'unchanged', 'f: the same value again');
    IF pg_temp.on_list(v_up) OR pg_temp.fp() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'f: the entry should not be put back, and nothing written';
    END IF;

    -- g. A second person's value after the first.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company G');
    v_p := pg_temp.person();
    v_q := pg_temp.person();
    v_up := pg_temp.apply('saas', v_p, 'Gunta Ruka')->>'userId';
    v_uq := pg_temp.apply('saas', v_q, 'Gunta Vilka')->>'userId';
    IF NOT pg_temp.on_list(v_up) OR NOT pg_temp.on_list(v_uq) OR pg_temp.listed() IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'g: the second is added and the first keeps the entry';
    END IF;

    -- h. A, B, A with A's entry removed in between.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company H');
    v_p := pg_temp.person();
    v_q := pg_temp.person();
    v_up := pg_temp.apply('saas', v_p, 'Hugo Eglis')->>'userId';
    PERFORM pg_temp.apply('saas', v_q, 'Helga Birze');
    PERFORM pg_temp.ok('deployment_admin_remove', jsonb_build_object('actor', 'setting-test', 'userId', v_up), 'h: remove A');
    IF pg_temp.on_list(v_up) THEN
        RAISE EXCEPTION 'h: precondition: A''s entry is removed';
    END IF;
    PERFORM pg_temp.expect(pg_temp.apply('saas', v_p, NULL), 'applied', 'h: A again');
    IF NOT pg_temp.on_list(v_up) THEN
        RAISE EXCEPTION 'h: A should be on the list again';
    END IF;

    -- i. Applied, revoked, the same value.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company I');
    v_p := pg_temp.person();
    v_up := pg_temp.apply('saas', v_p, 'Indra Klava')->>'userId';
    PERFORM pg_temp.revoke_member(v_co, v_up);
    IF pg_temp.on_list(v_up) THEN
        RAISE EXCEPTION 'i: precondition: a revoked account leaves the list';
    END IF;
    PERFORM pg_temp.expect(pg_temp.apply('saas', v_p, NULL), 'removedMember', 'i: the same value after the revoke');
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentAdminRefused' AND user_id = v_up) <> 1
       OR pg_temp.on_list(v_up) THEN
        RAISE EXCEPTION 'i: one refusal line, and not on the list';
    END IF;

    -- j. Never a member and no name: with a marked company, and with no company.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company J');
    v_fp := pg_temp.fp();
    v := pg_temp.apply('saas', pg_temp.person(), NULL);
    PERFORM pg_temp.expect(v, 'nameNeeded', 'j: a marked company');
    IF v->>'companyId' IS DISTINCT FROM v_co OR v->>'userId' IS NOT NULL OR pg_temp.fp() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'j: a name is needed and nothing is written: %', v;
    END IF;
    v := pg_temp.apply('saas', pg_temp.person(), '   ');
    PERFORM pg_temp.expect(v, 'nameNeeded', 'j: a blank name is no name');
    PERFORM pg_temp.reset();
    v_fp := pg_temp.fp();
    v := pg_temp.apply('local', pg_temp.person(), NULL);
    PERFORM pg_temp.expect(v, 'nameNeeded', 'j: no company at all');
    IF v->>'companyId' IS NOT NULL OR pg_temp.fp() IS DISTINCT FROM v_fp OR EXISTS (SELECT 1 FROM rolebyte.tenant) THEN
        RAISE EXCEPTION 'j: no company should be made and nothing written: %', v;
    END IF;

    -- k. Two companies, none marked.
    PERFORM pg_temp.reset();
    PERFORM pg_temp.company('Company K1');
    PERFORM pg_temp.company('Company K2');
    v_fp := pg_temp.fp();
    v := pg_temp.apply('saas', pg_temp.person(), 'Karlis Dzenis');
    PERFORM pg_temp.expect(v, 'noCompany', 'k: two companies');
    IF v->>'companyId' IS NOT NULL OR v->>'userId' IS NOT NULL OR pg_temp.fp() IS DISTINCT FROM v_fp
       OR EXISTS (SELECT 1 FROM rolebyte.deployment) THEN
        RAISE EXCEPTION 'k: nothing is written and nothing marked: %', v;
    END IF;

    -- l. local, no company, a name.
    PERFORM pg_temp.reset();
    v_p := pg_temp.person();
    v := pg_temp.apply('local', v_p, 'Lauma Skuja');
    PERFORM pg_temp.expect(v, 'applied', 'l: a fresh deployment');
    v_co := v->>'companyId';
    v_up := v->>'userId';
    IF (v->>'companyMade')::boolean IS DISTINCT FROM true OR (v->>'memberAdded')::boolean IS DISTINCT FROM true
       OR (SELECT company_tenant_id FROM rolebyte.deployment) IS DISTINCT FROM v_co
       OR pg_temp.status(v_up) IS DISTINCT FROM 'invited' OR NOT pg_temp.has_rung(v_up) THEN
        RAISE EXCEPTION 'l: company made and marked, the person its invited administrator: %', v;
    END IF;
    IF pg_temp.listed() IS DISTINCT FROM 0 OR pg_temp.lines('deploymentAdminAdded', v_co) <> 0 THEN
        RAISE EXCEPTION 'l: the list is never written on local';
    END IF;
    IF (v->>'companyMarked')::boolean IS DISTINCT FROM true OR (v->>'listAdded')::boolean IS DISTINCT FROM false
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'l: should answer companyMarked and rungGranted true, listAdded false: %', v;
    END IF;

    -- m. local, one company.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company M');
    v_p := pg_temp.person();
    v_q := pg_temp.person();
    v_r := pg_temp.person();
    v := pg_temp.apply('local', v_p, 'Marta Opine');
    PERFORM pg_temp.expect(v, 'applied', 'm: a never-member');
    v_up := v->>'userId';
    IF (v->>'memberAdded')::boolean IS DISTINCT FROM true OR pg_temp.status(v_up) IS DISTINCT FROM 'invited'
       OR NOT pg_temp.has_rung(v_up) OR pg_temp.listed() IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'm: a new person is invited and holds the rung, list empty: %', v;
    END IF;
    v_uq := pg_temp.member(v_co, v_q, 'Martins Egle', true);
    IF pg_temp.has_rung(v_uq) THEN
        RAISE EXCEPTION 'm: precondition: the member holds no rung yet';
    END IF;
    v_n := pg_temp.lines('roleGranted', v_co);
    v := pg_temp.apply('local', v_q, NULL);
    PERFORM pg_temp.expect(v, 'applied', 'm: a member');
    IF NOT pg_temp.has_rung(v_uq) OR (v->>'memberAdded')::boolean IS DISTINCT FROM false
       OR pg_temp.lines('roleGranted', v_co) IS DISTINCT FROM v_n + 1 OR pg_temp.listed() IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'm: a member gains the rung, list empty: %', v;
    END IF;
    IF (v->>'rungGranted')::boolean IS DISTINCT FROM true OR (v->>'listAdded')::boolean IS DISTINCT FROM false
       OR (v->>'companyMarked')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'm: should answer rungGranted true, listAdded and companyMarked false: %', v;
    END IF;
    v_ur := pg_temp.member(v_co, v_r, 'Mirdza Priede', true);
    PERFORM pg_temp.revoke_member(v_co, v_ur);
    PERFORM pg_temp.expect(pg_temp.apply('local', v_r, NULL), 'removedMember', 'm: a revoked member');
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentAdminRefused' AND user_id = v_ur) <> 1
       OR pg_temp.has_rung(v_ur) OR pg_temp.listed() IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'm: a revoked member gets one refusal line and no rung, list empty';
    END IF;

    -- n. Exactly one company, not marked.
    PERFORM pg_temp.reset();
    v_co := pg_temp.company('Company N');
    IF EXISTS (SELECT 1 FROM rolebyte.deployment) THEN
        RAISE EXCEPTION 'n: precondition: nothing is marked';
    END IF;
    v_p := pg_temp.person();
    v := pg_temp.apply('saas', v_p, 'Nora Bruzis');
    PERFORM pg_temp.expect(v, 'applied', 'n: the only company');
    IF (SELECT company_tenant_id FROM rolebyte.deployment) IS DISTINCT FROM v_co
       OR pg_temp.lines('deploymentCompanyMarked', v_co) <> 1
       OR (v->>'companyMade')::boolean IS DISTINCT FROM false OR v->>'companyId' IS DISTINCT FROM v_co
       OR NOT pg_temp.on_list(v->>'userId') THEN
        RAISE EXCEPTION 'n: the company is marked with its line, then the person classified against it: %', v;
    END IF;
    IF (v->>'companyMarked')::boolean IS DISTINCT FROM true OR (v->>'listAdded')::boolean IS DISTINCT FROM true
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'n: should answer companyMarked and listAdded true, rungGranted false: %', v;
    END IF;

    -- o. Refusals, with a company and with none.
    PERFORM pg_temp.reset();
    v_p := pg_temp.person();
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'mode', 'SaaS', 'subjectKey', v_p, 'displayName', 'Olga Pole'), 'o: mode SaaS, no company');
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'subjectKey', v_p, 'displayName', 'Olga Pole'), 'o: no mode, no company');
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'mode', 'saas', 'subjectKey', 'svc:o-client-key', 'displayName', 'Olga Pole'), 'o: a service key, no company');
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'mode', 'saas', 'subjectKey', 'sub:SHORT', 'displayName', 'Olga Pole'), 'o: a malformed key, no company');
    PERFORM pg_temp.refused(jsonb_build_object('mode', 'saas', 'subjectKey', v_p, 'displayName', 'Olga Pole'), 'o: no actor, no company');
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'mode', 'local', 'displayName', 'Olga Pole'), 'o: no key, no company');
    IF EXISTS (SELECT 1 FROM rolebyte.tenant) THEN
        RAISE EXCEPTION 'o: a refusal must not make a company';
    END IF;
    v_co := pg_temp.marked_company('Company O');
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'mode', 'SaaS', 'subjectKey', v_p, 'displayName', 'Olga Pole'), 'o: mode SaaS');
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'subjectKey', v_p, 'displayName', 'Olga Pole'), 'o: no mode');
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'mode', 'saas', 'subjectKey', 'svc:o-client-key', 'displayName', 'Olga Pole'), 'o: a service key');
    PERFORM pg_temp.refused(jsonb_build_object('actor', 'apply-test', 'mode', 'local', 'subjectKey', 'sub:SHORT', 'displayName', 'Olga Pole'), 'o: a malformed key');
    PERFORM pg_temp.refused(jsonb_build_object('mode', 'saas', 'subjectKey', v_p, 'displayName', 'Olga Pole'), 'o: no actor');

    -- q. A suspended company, and a member of it not on the list.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company Q');
    v_p := pg_temp.person();
    v_up := pg_temp.member(v_co, v_p, 'Qarla Vitola', true);
    UPDATE rolebyte.tenant SET status = 'suspended' WHERE id = v_co;
    PERFORM pg_temp.expect(pg_temp.apply('saas', v_p, NULL), 'applied', 'q: a suspended company');
    IF NOT pg_temp.on_list(v_up) THEN
        RAISE EXCEPTION 'q: the member should be on the list';
    END IF;

    -- r. The right as resolve answers it.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company R');
    v_p := pg_temp.person();
    PERFORM pg_temp.apply('saas', v_p, 'Rasa Kokle');
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'setting-test', 'subjectKey', v_p), 'r: claim on saas');
    v_m := pg_temp.membership(v_p, v_co);
    IF v_m->'highScopes' IS DISTINCT FROM '["deployment:admin"]'::jsonb THEN
        RAISE EXCEPTION 'r: a saas person made active should carry highScopes deployment:admin: %', v_m;
    END IF;
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company R2');
    v_q := pg_temp.person();
    PERFORM pg_temp.apply('local', v_q, 'Rolands Zars');
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'setting-test', 'subjectKey', v_q), 'r: claim on local');
    v_m := pg_temp.membership(v_q, v_co);
    IF v_m IS NULL OR v_m ? 'highScopes' OR pg_temp.listed() IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'r: a local person has no highScopes, and the list is empty: %', v_m;
    END IF;

    -- s. A value is the person with the mode: the same person in the other mode is new.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company S');
    v_p := pg_temp.person();
    v := pg_temp.apply('local', v_p, 'Sandra Leja');
    PERFORM pg_temp.expect(v, 'applied', 's: local first');
    v_up := v->>'userId';
    IF pg_temp.on_list(v_up) THEN
        RAISE EXCEPTION 's: precondition: not on the list after local';
    END IF;
    v := pg_temp.apply('saas', v_p, 'Sandra Leja');
    PERFORM pg_temp.expect(v, 'applied', 's: the same person on saas');
    IF NOT pg_temp.on_list(v_up) OR (v->>'listAdded')::boolean IS DISTINCT FROM true
       OR (SELECT admin_setting_mode FROM rolebyte.deployment) IS DISTINCT FROM 'saas' THEN
        RAISE EXCEPTION 's: the same person on saas is applied again, listed, with the mode remembered: %', v;
    END IF;
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company S2');
    v_q := pg_temp.person();
    v_uq := pg_temp.member(v_co, v_q, 'Sigita Vanaga', true);
    PERFORM pg_temp.expect(pg_temp.apply('saas', v_q, NULL), 'applied', 's: saas against a company');
    IF pg_temp.has_rung(v_uq) THEN
        RAISE EXCEPTION 's: precondition: no rung after saas';
    END IF;
    v := pg_temp.apply('local', v_q, NULL);
    PERFORM pg_temp.expect(v, 'applied', 's: the same person on local');
    IF NOT pg_temp.has_rung(v_uq) OR (v->>'rungGranted')::boolean IS DISTINCT FROM true
       OR (v->>'listAdded')::boolean IS DISTINCT FROM false
       OR (SELECT admin_setting_mode FROM rolebyte.deployment) IS DISTINCT FROM 'local' THEN
        RAISE EXCEPTION 's: the same person on local gains the rung, with the mode remembered: %', v;
    END IF;

    -- t. A person already on the list (put there from the screen), named by a new value.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company T');
    v_p := pg_temp.person();
    v_up := pg_temp.member(v_co, v_p, 'Tamara Zile', true);
    PERFORM pg_temp.ok('deployment_admin_add', jsonb_build_object('actor', 'setting-test', 'subjectKey', v_p,
        'addedFrom', 'screen'), 't: put on the list from the screen');
    v_n := pg_temp.lines('deploymentAdminAdded', v_co);
    v := pg_temp.apply('saas', v_p, NULL);
    PERFORM pg_temp.expect(v, 'applied', 't: already on the list');
    IF (v->>'listAdded')::boolean IS DISTINCT FROM false OR pg_temp.lines('deploymentAdminAdded', v_co) IS DISTINCT FROM v_n
       OR pg_temp.listed() IS DISTINCT FROM 1
       OR (SELECT added_from FROM rolebyte.deployment_admin WHERE user_id = v_up) IS DISTINCT FROM 'screen' THEN
        RAISE EXCEPTION 't: listAdded false, no new deploymentAdminAdded line, the entry as it was: %', v;
    END IF;

    -- u. On local, a member who already holds the rung, named by a new value.
    PERFORM pg_temp.reset();
    v_co := pg_temp.marked_company('Company U');
    v_p := pg_temp.person();
    v_q := pg_temp.person();
    v_up := pg_temp.apply('local', v_p, 'Uldis Kreija')->>'userId';
    PERFORM pg_temp.apply('local', v_q, 'Una Bite');
    IF NOT pg_temp.has_rung(v_up) THEN
        RAISE EXCEPTION 'u: precondition: the first person holds the rung';
    END IF;
    v := pg_temp.apply('local', v_p, NULL);
    PERFORM pg_temp.expect(v, 'applied', 'u: a new value for a rung holder');
    IF (v->>'rungGranted')::boolean IS DISTINCT FROM false OR (v->>'memberAdded')::boolean IS DISTINCT FROM false
       OR (v->>'listAdded')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'u: rungGranted false, nothing added: %', v;
    END IF;

    -- v. Exactly one company, not marked, the person a revoked member of it.
    PERFORM pg_temp.reset();
    v_co := pg_temp.company('Company V');
    v_p := pg_temp.person();
    v_ur := pg_temp.member(v_co, v_p, 'Vilma Ozola', true);
    PERFORM pg_temp.revoke_member(v_co, v_ur);
    v_n := (SELECT count(*) FROM rolebyte.event);
    v := pg_temp.apply('saas', v_p, 'Vilma Ozola');
    PERFORM pg_temp.expect(v, 'removedMember', 'v: a revoked member of the only company');
    IF (v->>'companyMarked')::boolean IS DISTINCT FROM true OR (v->>'listAdded')::boolean IS DISTINCT FROM false
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'v: companyMarked true, the others false: %', v;
    END IF;
    IF (SELECT company_tenant_id FROM rolebyte.deployment) IS DISTINCT FROM v_co
       OR (SELECT admin_setting_subject_key FROM rolebyte.deployment) IS NOT NULL
       OR (SELECT admin_setting_mode FROM rolebyte.deployment) IS NOT NULL
       OR pg_temp.lines('deploymentCompanyMarked', v_co) <> 1
       OR pg_temp.lines('deploymentAdminRefused', v_co) <> 1
       OR (SELECT count(*) FROM rolebyte.event) IS DISTINCT FROM v_n + 2
       OR pg_temp.listed() IS DISTINCT FROM 0 OR pg_temp.has_rung(v_ur) THEN
        RAISE EXCEPTION 'v: the mark and its line, the refusal line, nothing else';
    END IF;

    -- w. Exactly one company, not marked, never a member and no name.
    PERFORM pg_temp.reset();
    v_co := pg_temp.company('Company W');
    v_n := (SELECT count(*) FROM rolebyte.event);
    v := pg_temp.apply('saas', pg_temp.person(), NULL);
    PERFORM pg_temp.expect(v, 'nameNeeded', 'w: the only company, no name');
    IF (v->>'companyMarked')::boolean IS DISTINCT FROM true OR (v->>'listAdded')::boolean IS DISTINCT FROM false
       OR (v->>'rungGranted')::boolean IS DISTINCT FROM false
       OR (SELECT company_tenant_id FROM rolebyte.deployment) IS DISTINCT FROM v_co
       OR (SELECT count(*) FROM rolebyte.event) IS DISTINCT FROM v_n + 1
       OR pg_temp.listed() IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'w: companyMarked true and only the mark written: %', v;
    END IF;

    RAISE NOTICE 'PASS unit.rolebyte_deployment_setting';
END $$;

-- Everything above was done inside this transaction, tenants emptied included:
-- the register is left exactly as it was found.
ROLLBACK;
