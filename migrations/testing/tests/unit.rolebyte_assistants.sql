-- SQL unit tests for an assistant in the register: a named machine member that
-- belongs to one person, who connects an AI app as it. An administrator adds it
-- for one person (the register mints its key), chosen then and never changed, and
-- names and renames it; a person may have several. The first assistant in a
-- tenant brings the seeded Assistant role, which every assistant starts in. The
-- sign-in service asks for a person's own assistants when the person connects an
-- app, and again at every refresh.
--
-- Everything this file makes is rolled back at its end: it declares a seed,
-- and the shipped-roles test needs a database where no service declared one.
--
-- Run as the owner (bypasses the EXECUTE grants; the role boundary is the
-- role-leak acceptances'):
--   psql "$DSN" -f migrations/testing/tests/unit.rolebyte_assistants.sql
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

-- What an assistant answers as, in the sign-in lookup: tenant and assistant keys.
CREATE OR REPLACE FUNCTION pg_temp.own(p_person text) RETURNS text[]
LANGUAGE sql AS $$
    SELECT COALESCE(array_agg((i->>'tenantId') || ' ' || (i->>'assistant') ORDER BY (i->>'tenantId') || ' ' || (i->>'assistant')), '{}')
      FROM jsonb_array_elements(pg_temp.ok('assistants_of_person', jsonb_build_object('subjectKey', p_person),
                                           'the lookup for ' || p_person)->'items') i;
$$;

DO $$
DECLARE
    v        jsonb;
    v_svc    text := 'ast' || lower(substr(util.generate_ulid(), 20, 6));
    v_admin  text := 'sub:' || util.generate_ulid();
    v_anna   text := 'sub:' || util.generate_ulid();
    v_janis  text := 'sub:' || util.generate_ulid();
    v_ilze   text := 'sub:' || util.generate_ulid();
    v_toms   text := 'sub:' || util.generate_ulid();
    v_other  text := 'sub:' || util.generate_ulid();
    v_ta     text;
    v_tb     text;
    v_tc     text;
    v_uanna  text;
    v_ujanis text;
    v_uilze  text;
    v_utoms  text;
    v_uother text;
    v_umach  text;
    v_ubanna text;
    v_a1     jsonb;
    v_a2     jsonb;
    v_a3     jsonb;
    v_ab     jsonb;
    v_ac     jsonb;
    v_role   text;
    v_n      int;
    v_e      int;
BEGIN
  BEGIN
    ------------------------------------------------------------------
    -- Seeds: a service names the Assistant role beside Worker and Manager; the
    -- old seed is gone.
    ------------------------------------------------------------------
    PERFORM pg_temp.ok('service_register', jsonb_build_object('actor', 'op:test', 'service', v_svc,
        'displayName', 'Assistant demo'), 'register');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'task', 'act', 'view', 'description', 'See them', 'class', 'ordinary',
                           'plane', 'object', 'seeds', jsonb_build_array('worker', 'assistant'))), 'task:view');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'task/comment', 'act', 'add', 'description', 'Say something', 'class', 'ordinary',
                           'plane', 'object', 'seeds', jsonb_build_array('assistant'))), 'task/comment:add');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'task', 'act', 'delete', 'description', 'Remove one', 'class', 'ordinary',
                           'plane', 'object', 'seeds', jsonb_build_array('manager'))), 'task:delete');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'task', 'act', 'edit', 'description', 'Change it', 'class', 'ordinary',
                           'plane', 'object', 'seeds', jsonb_build_array('helper'))), 'membership:invalid', 'the old seed helper');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'task', 'act', 'edit', 'description', 'Change it', 'class', 'ordinary',
                           'plane', 'object', 'seeds', jsonb_build_array('robot'))), 'membership:invalid', 'an unknown seed');

    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Assistants A',
        'administrator', jsonb_build_object('subjectKey', v_admin, 'displayName', 'Kārlis Egle')), 'open A');
    v_ta := v->'tenant'->>'id';
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Assistants B',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Bēla')), 'open B');
    v_tb := v->'tenant'->>'id';
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Assistants C',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Cēsis')), 'open C');
    v_tc := v->'tenant'->>'id';
    IF EXISTS (SELECT 1 FROM rolebyte.tenant_role WHERE tenant_id = v_ta AND seed = 'assistant') THEN
        RAISE EXCEPTION 'a tenant opens with no Assistant role: it comes with its first assistant';
    END IF;

    v_uanna  := pg_temp.ok('user_invite', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'subjectKey', v_anna,
        'displayName', 'Anna'), 'invite Anna')->>'id';
    v_ujanis := pg_temp.ok('user_invite', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'subjectKey', v_janis,
        'displayName', 'Jānis'), 'invite Jānis')->>'id';
    v_uilze  := pg_temp.ok('user_invite', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'subjectKey', v_ilze,
        'displayName', 'Ilze'), 'invite Ilze, never signs in')->>'id';
    v_utoms  := pg_temp.ok('user_invite', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'subjectKey', v_toms,
        'displayName', 'Toms'), 'invite Toms')->>'id';
    v_uother := pg_temp.ok('user_invite', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'subjectKey', v_other,
        'displayName', 'Otrs'), 'invite Otrs to B')->>'id';
    v_ubanna := pg_temp.ok('user_invite', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'subjectKey', v_anna,
        'displayName', 'Anna'), 'invite Anna to B')->>'id';
    v_umach  := pg_temp.ok('user_invite', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'subjectKey', 'svc:a-service', 'displayName', 'A service'), 'invite a machine')->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', k), 'claim ' || k)
       FROM unnest(ARRAY[v_anna, v_janis, v_toms, v_other, 'svc:a-service']) k;
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userId', v_utoms), 'remove Toms');

    ------------------------------------------------------------------
    -- Added for one person: a key the register minted, active at once, the
    -- person named, recorded with both.
    ------------------------------------------------------------------
    v_a1 := pg_temp.ok('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Assistant 1',
        'personId', v_uanna), 'add Assistant 1 for Anna');
    IF v_a1->>'subjectKey' !~ '^svc:assistant-[0-9A-HJKMNP-TV-Z]{26}$' THEN
        RAISE EXCEPTION 'an assistant''s key is the register''s: %', v_a1;
    END IF;
    IF v_a1->>'name' IS DISTINCT FROM 'Assistant 1' OR v_a1->>'status' IS DISTINCT FROM 'active'
       OR v_a1->'person'->>'id' IS DISTINCT FROM v_uanna OR v_a1->'person'->>'subjectKey' IS DISTINCT FROM v_anna THEN
        RAISE EXCEPTION 'an assistant is active at once, by its name, for its person: %', v_a1;
    END IF;
    IF (SELECT array_agg(user_id) FROM rolebyte.assistant_person WHERE assistant_id = v_a1->>'id') IS DISTINCT FROM ARRAY[v_uanna] THEN
        RAISE EXCEPTION 'the assistant is Anna''s alone';
    END IF;
    IF (SELECT user_type_id FROM rolebyte.user_account WHERE id = v_a1->>'id')
       IS DISTINCT FROM (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_ta) THEN
        RAISE EXCEPTION 'an assistant holds the tenant''s default user type, as every member does';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE tenant_id = v_ta AND user_id = v_a1->>'id' AND kind = 'assistantAdded'
                     AND payload->>'name' = 'Assistant 1' AND payload->>'personId' = v_uanna AND actor = v_admin) THEN
        RAISE EXCEPTION 'adding an assistant is recorded with its person';
    END IF;

    ------------------------------------------------------------------
    -- Never for no person, two, a machine, an assistant, someone not active or
    -- of another workspace: refused, nothing made, nothing recorded.
    ------------------------------------------------------------------
    SELECT count(*) INTO v_n FROM rolebyte.user_account WHERE tenant_id = v_ta AND subject_key LIKE 'svc:assistant-%';
    SELECT count(*) INTO v_e FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'assistantAdded';
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'No one'),
        'membership:invalid', 'no person');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Two',
        'personId', jsonb_build_array(v_uanna, v_ujanis)), 'membership:invalid', 'two people');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'For a machine',
        'personId', v_umach), 'membership:invalid', 'a machine as its person');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'For an assistant',
        'personId', v_a1->>'id'), 'membership:invalid', 'an assistant as its person');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'For Ilze',
        'personId', v_uilze), 'membership:invalid', 'a person not yet active');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'For Toms',
        'personId', v_utoms), 'membership:invalid', 'a removed person');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'For Otrs',
        'personId', v_uother), 'membership:invalid', 'another workspace''s person');
    IF (SELECT count(*) FROM rolebyte.user_account WHERE tenant_id = v_ta AND subject_key LIKE 'svc:assistant-%') <> v_n
       OR (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'assistantAdded') <> v_e THEN
        RAISE EXCEPTION 'a refused assistant is neither made nor recorded';
    END IF;

    ------------------------------------------------------------------
    -- The Assistant role: made with the first assistant, holding the seed's
    -- boxes exactly, given to every assistant.
    ------------------------------------------------------------------
    v_role := v_a1->'role'->>'id';
    IF v_role IS NULL OR (SELECT seed FROM rolebyte.tenant_role WHERE id = v_role) IS DISTINCT FROM 'assistant'
       OR (SELECT name FROM rolebyte.tenant_role WHERE id = v_role) IS DISTINCT FROM 'Assistant' THEN
        RAISE EXCEPTION 'the first assistant brings the Assistant role: %', v_a1;
    END IF;
    IF 'lv' = ANY (util.app_languages())
       AND (SELECT labels->>'lv' FROM rolebyte.tenant_role WHERE id = v_role) IS DISTINCT FROM 'Asistents' THEN
        RAISE EXCEPTION 'the Assistant role reads Asistents in Latvian';
    END IF;
    IF (SELECT array_agg(sp.feature_key || ':' || sp.act ORDER BY sp.feature_key, sp.act)
          FROM rolebyte.tenant_role_permission t JOIN rolebyte.service_permission sp ON sp.id = t.permission_id
         WHERE t.tenant_role_id = v_role AND sp.service_key = v_svc) IS DISTINCT FROM ARRAY['task:view', 'task/comment:add'] THEN
        RAISE EXCEPTION 'the Assistant role holds exactly the boxes declared for it';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role_assignment
                    WHERE tenant_id = v_ta AND user_id = v_a1->>'id' AND tenant_role_id = v_role AND state = 'granted') THEN
        RAISE EXCEPTION 'the first assistant starts in the Assistant role';
    END IF;

    ------------------------------------------------------------------
    -- A person may have several; each assistant has its one person.
    ------------------------------------------------------------------
    v_a2 := pg_temp.ok('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Assistant 2',
        'personId', v_uanna), 'add Assistant 2 for Anna');
    v_a3 := pg_temp.ok('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Assistant 3',
        'personId', v_ujanis), 'add Assistant 3 for Jānis');
    IF v_a2->'role'->>'id' IS DISTINCT FROM v_role
       OR (SELECT count(*) FROM rolebyte.tenant_role WHERE tenant_id = v_ta AND seed = 'assistant') <> 1 THEN
        RAISE EXCEPTION 'the second assistant starts in the same Assistant role: %', v_a2;
    END IF;
    IF (SELECT count(*) FROM rolebyte.assistant_person WHERE user_id = v_uanna) <> 2
       OR (SELECT count(*) FROM rolebyte.assistant_person WHERE user_id = v_ujanis) <> 1 THEN
        RAISE EXCEPTION 'Anna has two assistants, Jānis one';
    END IF;
    v_ab := pg_temp.ok('assistant_create', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'name', 'Assistant 1',
        'personId', v_ubanna), 'Anna''s assistant in B; another workspace may use the same name');

    ------------------------------------------------------------------
    -- A name the workspace uses: its own role is left alone, and the assistant
    -- starts with no role.
    ------------------------------------------------------------------
    v := pg_temp.ok('user_invite', jsonb_build_object('actor', 'op:test', 'tenantId', v_tc, 'subjectKey', v_janis,
        'displayName', 'Jānis'), 'invite Jānis to C');
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_janis), 'claim Jānis in C');
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'op:test', 'tenantId', v_tc, 'name', 'assistant'), 'C names a role assistant');
    v_ac := pg_temp.ok('assistant_create', jsonb_build_object('actor', 'op:test', 'tenantId', v_tc, 'name', 'Asistents',
        'personId', v->>'id'), 'add an assistant to C');
    IF v_ac->'role' IS DISTINCT FROM 'null'::jsonb
       OR EXISTS (SELECT 1 FROM rolebyte.tenant_role WHERE tenant_id = v_tc AND seed = 'assistant')
       OR EXISTS (SELECT 1 FROM rolebyte.tenant_role_assignment WHERE user_id = v_ac->>'id') THEN
        RAISE EXCEPTION 'a workspace keeps its own role named Assistant; the assistant starts with none: %', v_ac;
    END IF;

    ------------------------------------------------------------------
    -- Names: unique among the workspace's assistants, ignoring case; free again
    -- once an assistant is removed; a role's name rule.
    ------------------------------------------------------------------
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'assistant 1',
        'personId', v_uanna), 'membership:conflict', 'a name another assistant has');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', '',
        'personId', v_uanna), 'membership:invalid', 'an empty name');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', '   ',
        'personId', v_uanna), 'membership:invalid', 'a blank name');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', repeat('x', 101),
        'personId', v_uanna), 'membership:invalid', 'a name too long');
    PERFORM pg_temp.refused('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', 'no-such-tenant', 'name', 'Lost',
        'personId', v_uanna), 'membership:not_found', 'a tenant that does not exist');

    ------------------------------------------------------------------
    -- Rename: the key, the roles and the person stay; a taken name and a person
    -- are refused.
    ------------------------------------------------------------------
    v := pg_temp.ok('assistant_rename', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userId', v_a1->>'id',
        'name', 'Darba asistents'), 'rename Assistant 1');
    IF v->>'name' IS DISTINCT FROM 'Darba asistents' OR v->>'subjectKey' IS DISTINCT FROM v_a1->>'subjectKey'
       OR (v->>'changed')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'a rename keeps the key: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role_assignment
                    WHERE user_id = v_a1->>'id' AND tenant_role_id = v_role AND state = 'granted')
       OR NOT EXISTS (SELECT 1 FROM rolebyte.assistant_person WHERE assistant_id = v_a1->>'id' AND user_id = v_uanna)
       OR NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE user_id = v_a1->>'id' AND kind = 'assistantRenamed'
                        AND payload->>'from' = 'Assistant 1' AND payload->>'to' = 'Darba asistents') THEN
        RAISE EXCEPTION 'a rename keeps the roles and the person, and is recorded with both names';
    END IF;
    v := pg_temp.ok('assistant_rename', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userId', v_a1->>'id',
        'name', 'Darba asistents'), 'the same name again');
    IF (v->>'changed')::boolean IS NOT FALSE THEN RAISE EXCEPTION 'the same name changes nothing: %', v; END IF;
    PERFORM pg_temp.refused('assistant_rename', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userId', v_a1->>'id',
        'name', 'ASSISTANT 2'), 'membership:conflict', 'a rename to a taken name');
    PERFORM pg_temp.refused('assistant_rename', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userId', v_uanna,
        'name', 'Not an assistant'), 'membership:not_found', 'renaming a person');
    PERFORM pg_temp.refused('assistant_rename', jsonb_build_object('actor', v_admin, 'tenantId', v_tb, 'userId', v_a1->>'id',
        'name', 'Elsewhere'), 'membership:not_found', 'another workspace''s assistant');

    ------------------------------------------------------------------
    -- The sign-in lookup: a person's own assistants, each in its workspace.
    ------------------------------------------------------------------
    IF pg_temp.own(v_anna) IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM unnest(ARRAY[
           v_ta || ' ' || (v_a1->>'subjectKey'), v_ta || ' ' || (v_a2->>'subjectKey'), v_tb || ' ' || (v_ab->>'subjectKey')]) x) THEN
        RAISE EXCEPTION 'Anna''s own: two in A, one in B, and not Jānis''s: %', pg_temp.own(v_anna);
    END IF;
    v := pg_temp.ok('assistants_of_person', jsonb_build_object('subjectKey', v_anna), 'Anna''s, whole');
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v->'items') i
                    WHERE i->>'tenantId' = v_ta AND i->>'tenantName' = 'Assistants A' AND i->>'userId' = v_uanna
                      AND i->>'assistantUserId' = v_a1->>'id' AND i->>'name' = 'Darba asistents') THEN
        RAISE EXCEPTION 'each names its workspace, the person''s member there, and the assistant by name: %', v;
    END IF;
    IF pg_temp.own(v_ilze) IS DISTINCT FROM '{}'::text[] OR pg_temp.own(v_other) IS DISTINCT FROM '{}'::text[] THEN
        RAISE EXCEPTION 'a person with no assistant has an empty list';
    END IF;
    PERFORM pg_temp.refused('assistants_of_person', jsonb_build_object('subjectKey', v_a1->>'subjectKey'),
        'membership:invalid', 'an assistant has no assistants');
    PERFORM pg_temp.refused('assistants_of_person', '{}'::jsonb, 'membership:invalid', 'nobody named');

    ------------------------------------------------------------------
    -- An assistant's person is chosen when it is added and never changed after:
    -- nothing gives an assistant to another person.
    ------------------------------------------------------------------
    IF to_regprocedure('rolebyte.assistant_person_set(jsonb, jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'nothing gives an assistant to another person';
    END IF;

    ------------------------------------------------------------------
    -- Gone from the lookup: Anna out of B, an assistant removed.
    ------------------------------------------------------------------
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'userId', v_ubanna), 'Anna out of B');
    IF pg_temp.own(v_anna) IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM unnest(ARRAY[
           v_ta || ' ' || (v_a1->>'subjectKey'), v_ta || ' ' || (v_a2->>'subjectKey')]) x) THEN
        RAISE EXCEPTION 'a workspace Anna left answers none of her assistants: %', pg_temp.own(v_anna);
    END IF;
    -- Added five days ago, so the day it was added and the day it was removed
    -- differ below.
    UPDATE rolebyte.user_account SET created_at = created_at - interval '5 days' WHERE id = v_a1->>'id';
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'userId', v_a1->>'id'), 'remove Assistant 1');
    IF pg_temp.own(v_anna) IS DISTINCT FROM ARRAY[v_ta || ' ' || (v_a2->>'subjectKey')] THEN
        RAISE EXCEPTION 'a removed assistant is nobody''s: %', pg_temp.own(v_anna);
    END IF;
    PERFORM pg_temp.ok('assistant_create', jsonb_build_object('actor', v_admin, 'tenantId', v_ta, 'name', 'Assistant 1',
        'personId', v_uanna), 'a removed assistant''s name is free again');
    -- A later line about the removed one, of another kind, is not its removal.
    INSERT INTO rolebyte.event (id, at, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), now() + interval '1 day', v_admin, v_ta, v_a1->>'id', 'tenantRoleRevoked', '{}'::jsonb);

    ------------------------------------------------------------------
    -- The lists: every assistant ever added, removed ones included, by name;
    -- whole, each names its person, when it was added and when it was removed.
    ------------------------------------------------------------------
    v := pg_temp.ok('assistant_list', jsonb_build_object('tenantId', v_ta), 'list A');
    IF jsonb_array_length(v->'items') IS DISTINCT FROM 4
       OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v->'items') i
                       WHERE i->>'subjectKey' = v_a1->>'subjectKey' AND i->>'name' = 'Darba asistents' AND i->>'status' = 'revoked')
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v->'items') i
                   WHERE i ? 'person' OR i ? 'addedAt' OR i ? 'removedAt') THEN
        RAISE EXCEPTION 'the list names every assistant, without its person or its dates: %', v;
    END IF;
    v := pg_temp.ok('assistant_list', jsonb_build_object('tenantId', v_ta, 'withPerson', true), 'the list whole');
    IF jsonb_array_length(v->'items') IS DISTINCT FROM 4
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v->'items') i
                   WHERE NOT (i ? 'person' AND i ? 'addedAt' AND i ? 'removedAt')) THEN
        RAISE EXCEPTION 'the list whole names each one''s person and dates: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v->'items') i
                    WHERE i->>'id' = v_a1->>'id' AND i->'person'->>'id' = v_uanna AND i->>'status' = 'revoked'
                      AND (i->>'addedAt')::timestamptz = (SELECT created_at FROM rolebyte.user_account WHERE id = v_a1->>'id')
                      AND (i->>'removedAt')::timestamptz = (SELECT at FROM rolebyte.event
                                                            WHERE user_id = v_a1->>'id' AND kind = 'userRevoked')
                      AND (i->>'addedAt')::timestamptz < (i->>'removedAt')::timestamptz) THEN
        RAISE EXCEPTION 'a removed assistant names its person, the day it was added and the day it was removed: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v->'items') i
                    WHERE i->>'id' = v_a3->>'id' AND i->'person'->>'id' = v_ujanis AND i->>'status' = 'active'
                      AND (i->>'addedAt')::timestamptz = (SELECT created_at FROM rolebyte.user_account WHERE id = v_a3->>'id')
                      AND i->'removedAt' = 'null'::jsonb) THEN
        RAISE EXCEPTION 'an assistant not removed has no day it was removed: %', v;
    END IF;
    v := pg_temp.ok('assistant_list', jsonb_build_object('tenantId', v_ta, 'userId', v_a3->>'id', 'withPerson', true), 'one, whole');
    IF jsonb_array_length(v->'items') IS DISTINCT FROM 1 OR v->'items'->0->'person'->>'id' IS DISTINCT FROM v_ujanis
       OR v->'items'->0->'person'->>'displayName' IS DISTINCT FROM 'Jānis'
       OR NOT (v->'items'->0 ? 'addedAt') OR v->'items'->0->'removedAt' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'one assistant whole names its person and dates: %', v;
    END IF;
    PERFORM pg_temp.refused('assistant_list', jsonb_build_object('tenantId', v_ta, 'userId', v_uanna, 'withPerson', true),
        'membership:not_found', 'a person read as an assistant');

    RAISE EXCEPTION USING ERRCODE = 'UT001', MESSAGE = 'roll the test back';
  EXCEPTION WHEN SQLSTATE 'UT001' THEN
    RAISE NOTICE 'PASS unit.rolebyte_assistants';
  END;
END $$;
