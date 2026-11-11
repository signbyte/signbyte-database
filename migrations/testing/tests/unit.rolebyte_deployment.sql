-- Unit test: the deployment's own company and the people who administer the deployment.
-- Marking the company: the register marks it by itself only when exactly one company
-- exists (one history line); with none, with several and none marked, or with one
-- marked among several it changes nothing and answers how many companies there are; an
-- input naming a company is refused. The deployment's own act of naming the company
-- marks it, repeats without change, refuses a second company and an unknown one.
-- The list of administrators: a listed active member of the company resolves with the member
-- `highScopes` ["deployment:admin"] and the scope is never in `scopes`; the same
-- member unlisted has no `highScopes` member at all; a listed member revoked from the
-- company resolves to no membership of it and is not listed; an account of another
-- company only, a person who is a member nowhere, a service's account, a revoked
-- account, an unknown source and a missing company are each refused with nothing
-- written; an invited account is accepted and has the right once it is active; a
-- person who is in a second company has the right in the deployment's company only;
-- adding twice, removing, removing again and adding again behave as stated, each
-- change a history line naming who made it. A level stored directly in the group
-- `deployment` and granted never reaches `scopes` or `highScopes`; a declaration
-- and `role_define` naming that group are refused. The read of the company and the
-- list carry what they promise.
--
-- The whole test runs in one transaction that is rolled back at the end, so the
-- deployment's company and list it makes never reach a test that runs after it
-- in the same database. It empties the register's tenants inside that transaction
-- to test the empty case; the rollback restores them.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_deployment.sql

BEGIN;

-- Calls one register procedure and returns its answer.
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

-- What the deployment's two tables, the history and the registered services and
-- levels hold, as one comparable text.
CREATE OR REPLACE FUNCTION pg_temp.fingerprint() RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.deployment t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.deployment_admin t),
        (SELECT count(*) FROM rolebyte.event),
        (SELECT count(*) FROM rolebyte.service),
        (SELECT count(*) FROM rolebyte.role_definition)))
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

-- The register's whole answer for a subject.
CREATE OR REPLACE FUNCTION pg_temp.resolved(p_subject text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', p_subject), v);
    RETURN v;
END $$;

-- The subject's membership in one tenant, or NULL when none is answered.
CREATE OR REPLACE FUNCTION pg_temp.membership(p_subject text, p_tenant text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT m
      FROM jsonb_array_elements(pg_temp.resolved(p_subject)->'data'->'memberships') m
     WHERE m->>'tenantId' = p_tenant;
$$;

-- The history lines of one kind for one account.
CREATE OR REPLACE FUNCTION pg_temp.lines(p_kind text, p_user text) RETURNS int
LANGUAGE sql AS $$
    SELECT count(*)::int FROM rolebyte.event WHERE kind = p_kind AND user_id = p_user;
$$;

DO $$
DECLARE
    v        jsonb;
    v_fp     text;
    v_events bigint;
    v_solo   text;   -- a company that is the only one for a while
    v_ta     text;   -- the deployment's own company, opened first
    v_tb     text;   -- a second company
    v_p1     text;   -- sub keys, by person
    v_p2     text;
    v_p3     text;
    v_p4     text;
    v_p5     text;
    v_p6     text;
    v_p7     text;
    v_svc    text;
    v_u1     text;   -- account ids in company A
    v_u2     text;
    v_u3     text;
    v_u6     text;
    v_u7     text;
    v_us     text;
    v_u7b    text;
    v_m      jsonb;
    v_def    text;
    v_names  text[];
    v_today  text := to_char((now() AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD');
BEGIN
    -- 0. The register as the other tests left it is set aside inside this transaction
    --    only: every tenant and what hangs on it is emptied, and the rollback at the
    --    end puts it all back.
    TRUNCATE rolebyte.tenant CASCADE;

    -- 1. Nothing is marked on an empty register: marking succeeds with no company
    --    and writes nothing; the reads answer no company; adding a person is refused.
    v_fp := pg_temp.fingerprint();
    v := pg_temp.ok('deployment_company_mark', '{"actor":"dep-test"}', 'marking on an empty register');
    IF v->'company' IS DISTINCT FROM 'null'::jsonb OR (v->>'changed')::boolean IS DISTINCT FROM false
       OR (v->>'companies')::int IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'marking on an empty register should answer no company, changed false, companies 0: %', v;
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'marking on an empty register should write nothing';
    END IF;
    v := pg_temp.ok('deployment_get', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid()), 'get with nothing marked');
    IF v->'company' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'get with nothing marked should answer no company: %', v;
    END IF;
    v := pg_temp.ok('deployment_admin_list', '{}', 'list with nothing marked');
    IF v->'admins' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'the list with nothing marked should be empty: %', v;
    END IF;
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', 'sub:' || util.generate_ulid(), 'addedFrom', 'settings'),
        'membership:conflict', 'the deployment has no company of its own yet', 'adding with no company marked');

    -- 1b. Exactly one company: the register marks it by itself, with one history line
    --     naming the actor; marking again changes nothing and answers the same company.
    --     The company is then emptied away again for the rest of the test.
    v_solo := pg_temp.ok('tenant_create', '{"actor":"dep-test","name":"Vienīgā sabiedrība"}', 'the only company')->>'id';
    v := pg_temp.ok('deployment_company_mark', '{"actor":"dep-test-solo"}', 'marking the only company');
    IF v->'company'->>'id' IS DISTINCT FROM v_solo OR v->'company'->>'name' IS DISTINCT FROM 'Vienīgā sabiedrība'
       OR (v->>'changed')::boolean IS DISTINCT FROM true OR (v->>'companies')::int IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'the only company should be marked, changed true, companies 1: %', v;
    END IF;
    IF (SELECT company_tenant_id FROM rolebyte.deployment) IS DISTINCT FROM v_solo
       OR (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_solo AND kind = 'deploymentCompanyMarked'
              AND actor = 'dep-test-solo') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'marking the only company should write the row and one history line naming the actor';
    END IF;
    v := pg_temp.unchanged('deployment_company_mark', '{"actor":"dep-test-solo"}', 'marking the only company again');
    IF v->'company'->>'id' IS DISTINCT FROM v_solo OR (v->>'companies')::int IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'marking again should answer the same company and one company: %', v;
    END IF;
    TRUNCATE rolebyte.tenant CASCADE;
    IF EXISTS (SELECT 1 FROM rolebyte.deployment) THEN
        RAISE EXCEPTION 'emptying the tenants should leave no company marked';
    END IF;

    -- Two companies, opened one after the other, and the people.
    v_ta :=pg_temp.ok('tenant_create', '{"actor":"dep-test","name":"Uzņēmums Ā"}', 'company A')->>'id';
    v_tb := pg_temp.ok('tenant_create', '{"actor":"dep-test","name":"Sabiedrība B"}', 'company B')->>'id';
    -- Within one transaction both carry the same creation time: set it so the order is plain.
    UPDATE rolebyte.tenant SET created_at = now() - interval '2 days' WHERE id = v_ta;
    UPDATE rolebyte.tenant SET created_at = now() - interval '1 day'  WHERE id = v_tb;

    v_p1 := 'sub:' || util.generate_ulid();   -- listed, active in A
    v_p2 := 'sub:' || util.generate_ulid();   -- active in A, never listed
    v_p3 := 'sub:' || util.generate_ulid();   -- listed, then revoked from A
    v_p4 := 'sub:' || util.generate_ulid();   -- a member of B only
    v_p5 := 'sub:' || util.generate_ulid();   -- a member nowhere
    v_p6 := 'sub:' || util.generate_ulid();   -- invited to A, claims later
    v_p7 := 'sub:' || util.generate_ulid();   -- active in A and in B
    v_svc := 'svc:dep-test-' || util.generate_ulid();

    v_u1 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'dep-test', 'tenantId', v_ta, 'subjectKey', v_p1, 'displayName', 'Ēvalds Šmits'), 'invite 1')->>'id';
    v_u2 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'dep-test', 'tenantId', v_ta, 'subjectKey', v_p2, 'displayName', 'Zane Ķirsone'), 'invite 2')->>'id';
    v_u3 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'dep-test', 'tenantId', v_ta, 'subjectKey', v_p3, 'displayName', 'Āris Bērziņš'), 'invite 3')->>'id';
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'dep-test', 'tenantId', v_tb, 'subjectKey', v_p4, 'displayName', 'Ģirts Ozoliņš'), 'invite 4');
    v_u6 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'dep-test', 'tenantId', v_ta, 'subjectKey', v_p6, 'displayName', 'Dainis Čaks'), 'invite 6')->>'id';
    v_u7 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'dep-test', 'tenantId', v_ta, 'subjectKey', v_p7, 'displayName', 'Ilze Ūdre'), 'invite 7')->>'id';
    v_u7b := pg_temp.ok('user_invite', jsonb_build_object('actor', 'dep-test', 'tenantId', v_tb, 'subjectKey', v_p7, 'displayName', 'Ilze Ūdre'), 'invite 7 in B')->>'id';
    v_us := pg_temp.ok('user_invite', jsonb_build_object('actor', 'dep-test', 'tenantId', v_ta, 'subjectKey', v_svc, 'displayName', 'Pakalpojuma konts'), 'invite the service account')->>'id';
    FOREACH v_def IN ARRAY ARRAY[v_p1, v_p2, v_p3, v_p4, v_p7] LOOP
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'dep-test', 'subjectKey', v_def), 'claim');
    END LOOP;

    -- 2. Two companies and none marked: the register chooses nothing, writes nothing and
    --    answers no company with the number of companies; it is not an error. An input
    --    that names a company is refused, marked or not.
    v := pg_temp.unchanged('deployment_company_mark', '{"actor":"dep-test"}', 'marking with two companies and none marked');
    IF v->'company' IS DISTINCT FROM 'null'::jsonb OR (v->>'companies')::int IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'two unmarked companies should answer no company and companies 2: %', v;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.deployment) THEN
        RAISE EXCEPTION 'the register must not choose between two companies';
    END IF;
    PERFORM pg_temp.refused('deployment_company_mark',
        jsonb_build_object('actor', 'dep-test', 'tenantId', v_ta),
        'membership:invalid', 'this act names no company', 'marking with a tenantId named');
    PERFORM pg_temp.refused('deployment_company_mark', '{}', 'membership:invalid', NULL, 'marking with no actor');

    -- 3. The deployment's own act of naming the company: a tenant is required and must
    --    exist; the first naming marks it with one history line naming the actor.
    PERFORM pg_temp.refused('deployment_company_set', '{"actor":"dep-test"}',
        'membership:invalid', NULL, 'naming no company');
    PERFORM pg_temp.refused('deployment_company_set', '{"tenantId":"x"}',
        'membership:invalid', NULL, 'naming a company with no actor');
    PERFORM pg_temp.refused('deployment_company_set',
        jsonb_build_object('actor', 'dep-test', 'tenantId', 'no-such-tenant'),
        'membership:not_found', NULL, 'naming a tenant that does not exist');
    v_events := (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentCompanyMarked');
    v := pg_temp.ok('deployment_company_set',
        jsonb_build_object('actor', 'dep-test-mark', 'tenantId', v_ta), 'naming the company');
    IF v->'company'->>'id' IS DISTINCT FROM v_ta OR v->'company'->>'name' IS DISTINCT FROM 'Uzņēmums Ā'
       OR (v->>'changed')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'naming a company should mark it, changed true: %', v;
    END IF;
    IF (SELECT company_tenant_id FROM rolebyte.deployment) IS DISTINCT FROM v_ta
       OR (SELECT count(*) FROM rolebyte.deployment) <> 1 THEN
        RAISE EXCEPTION 'exactly one deployment row naming company A should exist';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'deploymentCompanyMarked'
            AND actor = 'dep-test-mark') IS DISTINCT FROM 1
       OR (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentCompanyMarked') <> v_events + 1 THEN
        RAISE EXCEPTION 'naming a company should write one history line in it, naming the actor';
    END IF;

    -- 4. Naming the same company again changes nothing; naming another is refused and
    --    nothing is written; a tenant that does not exist is still refused. With two
    --    companies and one marked, the register's own act changes nothing and answers
    --    the marked one.
    v := pg_temp.unchanged('deployment_company_set',
        jsonb_build_object('actor', 'dep-test', 'tenantId', v_ta), 'naming the same company again');
    IF v->'company'->>'id' IS DISTINCT FROM v_ta THEN
        RAISE EXCEPTION 'naming again should answer the company: %', v;
    END IF;
    PERFORM pg_temp.refused('deployment_company_set',
        jsonb_build_object('actor', 'dep-test', 'tenantId', v_tb),
        'membership:conflict', NULL, 'naming a different company');
    PERFORM pg_temp.refused('deployment_company_set',
        jsonb_build_object('actor', 'dep-test', 'tenantId', 'no-such-tenant'),
        'membership:not_found', NULL, 'naming a tenant that does not exist, once marked');
    v := pg_temp.unchanged('deployment_company_mark', '{"actor":"dep-test"}', 'marking with two companies and one marked');
    IF v->'company'->>'id' IS DISTINCT FROM v_ta OR (v->>'companies')::int IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'two companies with one marked should answer the marked one and companies 2: %', v;
    END IF;

    -- 5. The read of the company: a member of it gets it; a member of another
    --    company only, a service's key, an unknown subject and no subject get null.
    v := pg_temp.ok('deployment_get', jsonb_build_object('subjectKey', v_p2), 'get for a member');
    IF v->'company'->>'id' IS DISTINCT FROM v_ta OR v->'company'->>'name' IS DISTINCT FROM 'Uzņēmums Ā' THEN
        RAISE EXCEPTION 'a member of the company should be answered it: %', v;
    END IF;
    FOREACH v_def IN ARRAY ARRAY[v_p4, v_svc, 'sub:' || util.generate_ulid(), v_p6, NULL] LOOP
        v := pg_temp.ok('deployment_get', jsonb_build_object('subjectKey', v_def), 'get for ' || coalesce(v_def, 'no subject'));
        IF v->'company' IS DISTINCT FROM 'null'::jsonb THEN
            RAISE EXCEPTION 'get should answer no company for %, got %', coalesce(v_def, 'no subject'), v;
        END IF;
    END LOOP;

    -- 6. A listed active member resolves with highScopes, and the scope is not in scopes;
    --    an unlisted member has no highScopes member at all.
    v := pg_temp.ok('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test-add', 'subjectKey', v_p1, 'addedFrom', 'settings'), 'add person 1');
    IF v->>'userId' IS DISTINCT FROM v_u1 OR (v->>'changed')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'adding a member should answer their account and changed true: %', v;
    END IF;
    v_m := pg_temp.membership(v_p1, v_ta);
    IF v_m->'highScopes' IS DISTINCT FROM '["deployment:admin"]'::jsonb THEN
        RAISE EXCEPTION 'a listed member should resolve with highScopes deployment:admin: %', v_m;
    END IF;
    IF v_m->'scopes' @> '["deployment:admin"]'::jsonb THEN
        RAISE EXCEPTION 'deployment:admin must not be in scopes: %', v_m;
    END IF;
    v_m := pg_temp.membership(v_p2, v_ta);
    IF v_m IS NULL OR v_m ? 'highScopes' THEN
        RAISE EXCEPTION 'an unlisted member should resolve with no highScopes member at all: %', v_m;
    END IF;
    IF v_m->'scopes' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'an unlisted member with no levels keeps an empty scopes list: %', v_m;
    END IF;

    -- 7. Each add has a history line in the company, naming the actor and the source.
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentAdminAdded' AND user_id = v_u1
            AND tenant_id = v_ta AND actor = 'dep-test-add' AND payload->>'addedFrom' = 'settings') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'adding should write one history line in the company naming the actor and the source';
    END IF;

    -- 8. Adding twice: the second changes nothing.
    PERFORM pg_temp.unchanged('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test-add-2', 'subjectKey', v_p1, 'addedFrom', 'screen'), 'adding person 1 again');
    IF (SELECT added_by || '/' || added_from FROM rolebyte.deployment_admin WHERE user_id = v_u1) IS DISTINCT FROM 'dep-test-add/settings' THEN
        RAISE EXCEPTION 'adding again should keep the first entry as it was';
    END IF;

    -- 9. Refusals, each with nothing written: another company only, a member nowhere,
    --    a service's account, a source that is neither, no subject, no actor.
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p4, 'addedFrom', 'settings'),
        'membership:not_found', NULL, 'adding a member of another company only');
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p5, 'addedFrom', 'settings'),
        'membership:not_found', NULL, 'adding a person who is a member nowhere');
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_svc, 'addedFrom', 'settings'),
        'membership:invalid', NULL, 'adding a service''s account');
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p2, 'addedFrom', 'web'),
        'membership:invalid', NULL, 'adding from an unknown source');
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p2),
        'membership:invalid', NULL, 'adding with no source');
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'addedFrom', 'settings'),
        'membership:invalid', NULL, 'adding with no subject');
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('subjectKey', v_p2, 'addedFrom', 'settings'),
        'membership:invalid', NULL, 'adding with no actor');
    IF EXISTS (SELECT 1 FROM rolebyte.deployment_admin WHERE user_id IN (v_us, v_u2)) THEN
        RAISE EXCEPTION 'a refused add must leave no entry';
    END IF;

    -- 10. A listed member who is revoked from the company resolves to no membership of it,
    --     and their entry leaves the list in the same act, with a history line in the
    --     company naming the actor of the revoke; adding them again is refused.
    PERFORM pg_temp.ok('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p3, 'addedFrom', 'screen'), 'add person 3');
    IF pg_temp.membership(v_p3, v_ta)->'highScopes' IS DISTINCT FROM '["deployment:admin"]'::jsonb THEN
        RAISE EXCEPTION 'person 3 should have the right before they are revoked';
    END IF;
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', 'dep-test-revoke', 'tenantId', v_ta, 'userId', v_u3), 'revoke person 3');
    IF EXISTS (SELECT 1 FROM rolebyte.deployment_admin WHERE user_id = v_u3) THEN
        RAISE EXCEPTION 'revoking a listed account must delete its entry in the same act';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentAdminRemoved' AND user_id = v_u3
            AND tenant_id = v_ta AND actor = 'dep-test-revoke' AND payload ? 'revoked') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'revoking a listed account should write one deploymentAdminRemoved line in its company naming the actor of the revoke';
    END IF;
    IF pg_temp.membership(v_p3, v_ta) IS NOT NULL THEN
        RAISE EXCEPTION 'a revoked member should resolve to no membership of the company: %', pg_temp.membership(v_p3, v_ta);
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(pg_temp.ok('deployment_admin_list', '{}', 'list')->'admins') a
                WHERE a->>'userId' = v_u3) THEN
        RAISE EXCEPTION 'a revoked member should not be on the list';
    END IF;
    PERFORM pg_temp.refused('deployment_admin_remove', jsonb_build_object('actor', 'dep-test', 'userId', v_u3),
        'membership:not_found', NULL, 'removing the entry of a revoked account');
    PERFORM pg_temp.refused('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p3, 'addedFrom', 'screen'),
        'membership:conflict', NULL, 'adding a revoked account');
    v := pg_temp.ok('deployment_get', jsonb_build_object('subjectKey', v_p3), 'get for a revoked member');
    IF v->'company' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'a revoked member should be answered no company: %', v;
    END IF;

    -- 11. An invited account is accepted and has the right only once it is active.
    v := pg_temp.ok('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p6, 'addedFrom', 'settings'), 'add an invited account');
    IF v->>'userId' IS DISTINCT FROM v_u6 OR (v->>'changed')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'an invited account should be accepted: %', v;
    END IF;
    IF pg_temp.resolved(v_p6)->'data'->'memberships' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'an invited account resolves to nothing: %', pg_temp.resolved(v_p6);
    END IF;
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p6), 'claim person 6');
    IF pg_temp.membership(v_p6, v_ta)->'highScopes' IS DISTINCT FROM '["deployment:admin"]'::jsonb THEN
        RAISE EXCEPTION 'an account made active should resolve with the right: %', pg_temp.membership(v_p6, v_ta);
    END IF;

    -- 12. A listed person who is also an active member of a second company has the
    --     right in the deployment's company only.
    PERFORM pg_temp.ok('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test', 'subjectKey', v_p7, 'addedFrom', 'settings'), 'add person 7');
    v := pg_temp.resolved(v_p7)->'data'->'memberships';
    IF jsonb_array_length(v) <> 2
       OR (SELECT m->'highScopes' FROM jsonb_array_elements(v) m WHERE m->>'tenantId' = v_ta) IS DISTINCT FROM '["deployment:admin"]'::jsonb
       OR (SELECT m ? 'highScopes' FROM jsonb_array_elements(v) m WHERE m->>'tenantId' = v_tb) IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'person 7 should have highScopes in company A only: %', v;
    END IF;
    -- Even an entry for the account in the other company (which no procedure makes,
    -- written here as the owner) is not answered: the right is the deployment's own
    -- company's membership only.
    INSERT INTO rolebyte.deployment_admin (user_id, added_by, added_from) VALUES (v_u7b, 'dep-test', 'settings');
    v := pg_temp.resolved(v_p7)->'data'->'memberships';
    IF (SELECT m ? 'highScopes' FROM jsonb_array_elements(v) m WHERE m->>'tenantId' = v_tb) IS DISTINCT FROM false
       OR (SELECT m->'highScopes' FROM jsonb_array_elements(v) m WHERE m->>'tenantId' = v_ta) IS DISTINCT FROM '["deployment:admin"]'::jsonb THEN
        RAISE EXCEPTION 'an entry for an account outside the deployment''s company must not be answered: %', v;
    END IF;
    DELETE FROM rolebyte.deployment_admin WHERE user_id = v_u7b;

    -- 13. The list carries what it promises, by display name then account id.
    PERFORM pg_temp.ok('resolve', jsonb_build_object('subjectKey', v_p1, 'issuing', true), 'a sign-in for person 1');
    v := pg_temp.ok('deployment_admin_list', '{}', 'list')->'admins';
    SELECT array_agg(a->>'userId' ORDER BY ord) INTO v_names FROM jsonb_array_elements(v) WITH ORDINALITY t(a, ord);
    IF v_names IS DISTINCT FROM ARRAY[v_u6, v_u7, v_u1] THEN
        RAISE EXCEPTION 'the list should be ordered by display name (Dainis, Ilze, Ēvalds): %', v;
    END IF;
    v_m := v->2;
    IF v_m->>'userId' IS DISTINCT FROM v_u1 OR v_m->>'subjectKey' IS DISTINCT FROM v_p1
       OR v_m->>'displayName' IS DISTINCT FROM 'Ēvalds Šmits' OR v_m->>'status' IS DISTINCT FROM 'active'
       OR v_m->>'lastSignedInOn' IS DISTINCT FROM v_today OR v_m->>'addedBy' IS DISTINCT FROM 'dep-test-add'
       OR v_m->>'addedFrom' IS DISTINCT FROM 'settings' OR NOT (v_m ? 'addedAt') OR v_m->>'addedAt' IS NULL THEN
        RAISE EXCEPTION 'a list entry should carry its fields: %', v_m;
    END IF;
    IF NOT (v->0 ? 'lastSignedInOn') OR v->0->'lastSignedInOn' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'a member who has not signed in carries a null day: %', v->0;
    END IF;

    -- 14. Remove, remove again, add again; each change a history line naming the actor.
    v := pg_temp.ok('deployment_admin_remove', jsonb_build_object('actor', 'dep-test-rm', 'userId', v_u7), 'remove person 7');
    IF v->>'userId' IS DISTINCT FROM v_u7 OR (v->>'changed')::boolean IS DISTINCT FROM true
       OR v->>'subjectKey' IS DISTINCT FROM v_p7 THEN
        RAISE EXCEPTION 'removing should answer the account, its subject key and changed true: %', v;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.deployment_admin WHERE user_id = v_u7)
       OR (SELECT m ? 'highScopes' FROM (SELECT pg_temp.membership(v_p7, v_ta) m) q) IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'removing should end the right at the next answer';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'deploymentAdminRemoved' AND user_id = v_u7
            AND tenant_id = v_ta AND actor = 'dep-test-rm') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'removing should write one history line in the company naming the actor';
    END IF;
    PERFORM pg_temp.refused('deployment_admin_remove', jsonb_build_object('actor', 'dep-test', 'userId', v_u7),
        'membership:not_found', NULL, 'removing again');
    PERFORM pg_temp.refused('deployment_admin_remove', jsonb_build_object('actor', 'dep-test', 'userId', v_u2),
        'membership:not_found', NULL, 'removing an account never listed');
    PERFORM pg_temp.refused('deployment_admin_remove', jsonb_build_object('actor', 'dep-test'),
        'membership:invalid', NULL, 'removing with no account');
    v := pg_temp.ok('deployment_admin_add',
        jsonb_build_object('actor', 'dep-test-add-3', 'subjectKey', v_p7, 'addedFrom', 'screen'), 'add person 7 again');
    IF (v->>'changed')::boolean IS DISTINCT FROM true
       OR pg_temp.membership(v_p7, v_ta)->'highScopes' IS DISTINCT FROM '["deployment:admin"]'::jsonb
       OR pg_temp.lines('deploymentAdminAdded', v_u7) <> 2 THEN
        RAISE EXCEPTION 'adding after a removal should work and be a second history line: %', v;
    END IF;

    -- 15. The group deployment is the register's own. A level stored directly in it and
    --     granted never reaches scopes or highScopes, for a listed or an unlisted member.
    PERFORM pg_temp.ok('service_register', '{"actor":"dep-test","service":"dep-svc","displayName":"Dep"}', 'register a service');
    INSERT INTO rolebyte.role_definition (id, service_key, role_group, role_level)
    VALUES (util.generate_ulid(), 'dep-svc', 'deployment', 'admin')
    RETURNING id INTO v_def;
    INSERT INTO rolebyte.assignment (id, user_id, role_definition_id) VALUES (util.generate_ulid(), v_u1, v_def);
    INSERT INTO rolebyte.assignment (id, user_id, role_definition_id) VALUES (util.generate_ulid(), v_u2, v_def);
    v_m := pg_temp.membership(v_p2, v_ta);
    IF v_m->'scopes' IS DISTINCT FROM '[]'::jsonb OR v_m ? 'highScopes' THEN
        RAISE EXCEPTION 'a stored deployment level granted to an unlisted member must reach nothing: %', v_m;
    END IF;
    v_m := pg_temp.membership(v_p1, v_ta);
    IF v_m->'scopes' @> '["deployment:admin"]'::jsonb OR v_m->'highScopes' IS DISTINCT FROM '["deployment:admin"]'::jsonb THEN
        RAISE EXCEPTION 'a stored deployment level must not reach scopes, and highScopes stays as it was: %', v_m;
    END IF;

    -- 16. A declaration naming the group, under any service key, and role_define naming
    --     it, are refused with nothing written.
    PERFORM pg_temp.refused('service_declare',
        '{"actor":"svc:dep-decl","allowed":["dep-decl"],"section":{"services":[{"key":"dep-decl","roles":[{"group":"deployment","level":"admin"}]}]}}',
        'membership:config_key_conflict', 'the register''s own', 'declaring a deployment level');
    PERFORM pg_temp.refused('service_declare',
        '{"actor":"svc:dep-decl","allowed":["rolebyte"],"section":{"services":[{"key":"rolebyte","roles":[{"group":"deployment","level":"admin"}]}]}}',
        'membership:config_key_conflict', 'the register''s own', 'declaring a deployment level under the register''s own key');
    PERFORM pg_temp.refused('role_define',
        '{"actor":"dep-test","service":"dep-svc","group":"deployment","level":"other"}',
        'membership:invalid', 'the register''s own', 'defining a deployment level');
    IF EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE role_group = 'deployment' AND role_level <> 'admin') THEN
        RAISE EXCEPTION 'a refused definition must leave no level in the group deployment';
    END IF;

    -- 17. An active service account's entry, written straight into the list as the owner
    --     (no procedure makes one), is never answered: no highScopes, and no company.
    UPDATE rolebyte.user_account SET status = 'active' WHERE id = v_us;
    INSERT INTO rolebyte.deployment_admin (user_id, added_by, added_from) VALUES (v_us, 'dep-test', 'settings');
    v_m := pg_temp.membership(v_svc, v_ta);
    IF v_m IS NULL OR v_m ? 'highScopes' THEN
        RAISE EXCEPTION 'an active service account must resolve with no highScopes member: %', v_m;
    END IF;
    v := pg_temp.ok('deployment_get', jsonb_build_object('subjectKey', v_svc), 'get for an active service account');
    IF v->'company' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'an active service account must be answered no company: %', v;
    END IF;
    DELETE FROM rolebyte.deployment_admin WHERE user_id = v_us;

    -- 18. The company suspended: a member is answered no company, as the sign-in answers
    --     no membership there; active again, the company is answered again.
    v := pg_temp.ok('deployment_get', jsonb_build_object('subjectKey', v_p2), 'get before the suspension');
    IF v->'company'->>'id' IS DISTINCT FROM v_ta THEN
        RAISE EXCEPTION 'a member of an active company should be answered it: %', v;
    END IF;
    UPDATE rolebyte.tenant SET status = 'suspended' WHERE id = v_ta;
    v := pg_temp.ok('deployment_get', jsonb_build_object('subjectKey', v_p2), 'get for a member of a suspended company');
    IF v->'company' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'a member of a suspended company should be answered no company: %', v;
    END IF;
    IF pg_temp.membership(v_p2, v_ta) IS NOT NULL THEN
        RAISE EXCEPTION 'a suspended company answers no membership';
    END IF;
    UPDATE rolebyte.tenant SET status = 'active' WHERE id = v_ta;
    v := pg_temp.ok('deployment_get', jsonb_build_object('subjectKey', v_p2), 'get once active again');
    IF v->'company'->>'id' IS DISTINCT FROM v_ta THEN
        RAISE EXCEPTION 'an active company should be answered again: %', v;
    END IF;

    RAISE NOTICE 'PASS unit.rolebyte_deployment';
END $$;

-- Everything above was done inside this transaction, tenants emptied included:
-- the register is left exactly as it was found.
ROLLBACK;
