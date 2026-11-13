-- Unit test: a tenant role's, a user type's and a chart position's names in the
-- app's other languages.
--
--   * each is given its names in other languages (`labels`) when it is made,
--     trimmed, a null meaning none, and every read answers them beside the name
--     as entered: the role list, the definitions a placing service reads, a
--     role's update, a user type, a position, and the administration read's
--     tenant roles, user type and chart user type;
--   * a change merges them per language — a language sent with a name sets it,
--     one sent with null removes it, one not sent is left — and a role's update
--     and a position's rename change only what is sent, refusing a call that
--     sends nothing to change;
--   * each name in another language follows the name's own rule (1 to 100
--     characters on one line, no control character) as well as naming a
--     language the app speaks, and a refusal writes nothing;
--   * two roles never read alike in any language the app speaks, nor two user
--     types — a name in one language against another's name, or against its
--     name in the same language, ignoring case — while two positions may; a
--     role or type is never compared with itself, nor with another tenant's;
--   * a change of names alone is recorded with every name the object holds after
--     it, a change that changes nothing records nothing, and the line that makes
--     each of the three carries its names;
--   * lists stay in the order of the name as entered;
--   * the shipped roles and the default user type carry both languages: the
--     language asked is the name and the other stands beside it, unless the
--     tenant already reads that word otherwise;
--   * two administrators naming roles, or user types, at the same moment take
--     turns, so the second is refused when the two would read alike.
--
-- Self-contained, seed-then-assert, one RAISE EXCEPTION per failed assertion.
-- The race at the end commits as it goes and opens a second session (dblink).
--
-- Run as the owner:
--   psql "$DSN" -f migrations/testing/tests/unit.rolebyte_names.sql

CREATE EXTENSION IF NOT EXISTS dblink WITH SCHEMA public;

-- Calls one register procedure and returns its answer.
CREATE OR REPLACE FUNCTION pg_temp.rb(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
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

-- What a refusal must leave as it was: every role's, user type's and position's
-- names, and the length of the history.
CREATE OR REPLACE FUNCTION pg_temp.state() RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT string_agg(id || name || labels::text, ',' ORDER BY id) FROM rolebyte.tenant_role),
        (SELECT string_agg(id || name || labels::text, ',' ORDER BY id) FROM rolebyte.user_type),
        (SELECT string_agg(id || name || labels::text, ',' ORDER BY id) FROM rolebyte.chart_position),
        (SELECT count(*)::text FROM rolebyte.event)));
$$;

-- The call must be refused with exactly this code, and write nothing. Returns
-- the refusal's message.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_why text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text := pg_temp.state();
BEGIN
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    IF pg_temp.state() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but wrote something', p_why;
    END IF;
    RETURN v->>'message';
END $$;

-- The lines of a tenant's history so far, to tell later what one act wrote.
CREATE OR REPLACE FUNCTION pg_temp.mark(p_tenant text) RETURNS text[]
LANGUAGE sql AS $$
    SELECT COALESCE(array_agg(id), '{}'::text[]) FROM rolebyte.event WHERE tenant_id = p_tenant;
$$;

-- The lines written to a tenant's history since the mark: [{kind, payload}].
CREATE OR REPLACE FUNCTION pg_temp.since(p_tenant text, p_mark text[]) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object('kind', kind, 'payload', payload) ORDER BY id), '[]'::jsonb)
      FROM rolebyte.event
     WHERE tenant_id = p_tenant AND NOT (id = ANY (p_mark));
$$;

-- The one line an act wrote, which must be of this kind; returns its payload.
CREATE OR REPLACE FUNCTION pg_temp.one_line(p_lines jsonb, p_kind text, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
BEGIN
    IF jsonb_array_length(p_lines) IS DISTINCT FROM 1 OR p_lines->0->>'kind' IS DISTINCT FROM p_kind THEN
        RAISE EXCEPTION '%: expected one % line, the history holds %', p_why, p_kind, p_lines;
    END IF;
    RETURN p_lines->0->'payload';
END $$;

-- One member's row in the administration read of the tenant.
CREATE OR REPLACE FUNCTION pg_temp.access_row(p_tenant text, p_user text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.ok('access_list', jsonb_build_object('tenantId', p_tenant), 'access_list');
    r jsonb;
BEGIN
    SELECT m INTO r FROM jsonb_array_elements(v->'members') m WHERE m->>'id' = p_user;
    IF r IS NULL THEN
        RAISE EXCEPTION 'member % is not in the access list', p_user;
    END IF;
    RETURN r;
END $$;

-- One item of a list answer, found by its id.
CREATE OR REPLACE FUNCTION pg_temp.item(p_list jsonb, p_id text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT e FROM jsonb_array_elements(p_list) e WHERE e->>'id' = p_id;
$$;

DO $$
DECLARE
    v         jsonb;
    v_lines   jsonb;
    v_mark    text[];
    v_msg     text;
    r         record;
    v_svc     text := 'nmsv' || lower(substr(util.generate_ulid(), 20, 6));
    v_ta      text;   -- the tenant whose names are exercised
    v_tb      text;   -- another tenant, where the same words are free
    v_foreman text;
    v_yard    text;
    v_store   text;
    v_rigger  text;
    v_slinger text;
    v_alpha   text;
    v_beta    text;
    v_office  text;
    v_planner text;
    v_field   text;
    v_top     text;
    v_crew    text;
    v_person  text;
    v_te      text;
    v_tl      text;
    v_tc      text;
    v_tk      text;
    v_td      text;
    v_tg      text;
    v_biedrs  text;
BEGIN
    PERFORM pg_temp.ok('service_register', jsonb_build_object('actor', 'op:test', 'service', v_svc,
        'displayName', 'Names demo'), 'register');
    -- The chart's own key is registered once for the whole deployment.
    IF NOT EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'authority') THEN
        PERFORM pg_temp.ok('service_register', jsonb_build_object('actor', 'op:test', 'service', 'authority',
                           'displayName', 'Chart of authority'), 'register authority');
    END IF;
    v_ta := pg_temp.ok('tenant_create', '{"actor": "op:test", "name": "Names A"}', 'tenant A')->>'id';
    v_tb := pg_temp.ok('tenant_create', '{"actor": "op:test", "name": "Names B"}', 'tenant B')->>'id';
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'service', 'authority'), 'A holds the chart');

    ----------------------------------------------------------------
    -- 1. Given at creation, and read back beside the name.
    ----------------------------------------------------------------
    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Foreman',
        'labels', jsonb_build_object('lv', '  Brigadieris  '), 'description', 'Leads a crew'), 'define Foreman');
    v_foreman := v->>'id';
    IF v->>'name' IS DISTINCT FROM 'Foreman' OR v->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'a role is made with its names in other languages, trimmed: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'tenantRoleDefined', 'defining a role');
    IF v->>'name' IS DISTINCT FROM 'Foreman' OR v->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'the line that makes a role carries its names: %', v;
    END IF;
    IF (SELECT labels FROM rolebyte.tenant_role WHERE id = v_foreman) IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'the role keeps its names';
    END IF;

    v := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Yard hand',
        'labels', '{"lv": null}'::jsonb), 'define Yard hand');
    v_yard := v->>'id';
    IF v->'labels' IS DISTINCT FROM '{}'::jsonb THEN
        RAISE EXCEPTION 'a null given at creation is no name: %', v;
    END IF;
    v := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Storeman'),
        'define Storeman');
    v_store := v->>'id';
    IF v->'labels' IS DISTINCT FROM '{}'::jsonb THEN
        RAISE EXCEPTION 'a role given no names in other languages holds none: %', v;
    END IF;

    v := pg_temp.ok('tenant_role_list', jsonb_build_object('tenantId', v_ta), 'list A');
    IF pg_temp.item(v->'roles', v_foreman)->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb
       OR pg_temp.item(v->'roles', v_store)->'labels' IS DISTINCT FROM '{}'::jsonb THEN
        RAISE EXCEPTION 'the role list answers each role''s names: %', v;
    END IF;
    v := pg_temp.ok('tenant_role_definitions', jsonb_build_object('tenantId', v_ta), 'definitions A');
    IF pg_temp.item(v->'roles', v_foreman)->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb
       OR pg_temp.item(v->'roles', v_foreman)->>'name' IS DISTINCT FROM 'Foreman' THEN
        RAISE EXCEPTION 'the definitions a placing service copies carry each role''s names: %', v;
    END IF;

    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('user_type_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Office',
        'labels', jsonb_build_object('lv', 'Birojs')), 'define Office');
    v_office := v->>'id';
    IF v->>'name' IS DISTINCT FROM 'Office' OR v->'labels' IS DISTINCT FROM '{"lv": "Birojs"}'::jsonb THEN
        RAISE EXCEPTION 'a user type is made with its names in other languages: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'userTypeDefined', 'defining a user type');
    IF v->'labels' IS DISTINCT FROM '{"lv": "Birojs"}'::jsonb THEN
        RAISE EXCEPTION 'the line that makes a user type carries its names: %', v;
    END IF;
    v := pg_temp.ok('user_type_list', jsonb_build_object('tenantId', v_ta), 'user types of A');
    IF pg_temp.item(v->'userTypes', v_office)->'labels' IS DISTINCT FROM '{"lv": "Birojs"}'::jsonb THEN
        RAISE EXCEPTION 'the user type list answers each type''s names: %', v;
    END IF;

    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Director',
        'labels', jsonb_build_object('lv', 'Direktors')), 'the top position');
    v_top := v->>'id';
    IF v->>'name' IS DISTINCT FROM 'Director' OR v->'labels' IS DISTINCT FROM '{"lv": "Direktors"}'::jsonb THEN
        RAISE EXCEPTION 'a position is made with its names in other languages: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'chartPositionAdded', 'adding a position');
    IF v->>'name' IS DISTINCT FROM 'Director' OR v->'labels' IS DISTINCT FROM '{"lv": "Direktors"}'::jsonb THEN
        RAISE EXCEPTION 'the line that adds a position carries its names: %', v;
    END IF;
    v := pg_temp.ok('chart_get', jsonb_build_object('tenantId', v_ta), 'the chart of A');
    IF pg_temp.item(v->'positions', v_top)->'labels' IS DISTINCT FROM '{"lv": "Direktors"}'::jsonb THEN
        RAISE EXCEPTION 'the chart answers each position''s names: %', v;
    END IF;

    ----------------------------------------------------------------
    -- 2. A name in another language is held to the name's own rule, and to the
    --    languages the app speaks. Every act that takes names refuses each one,
    --    and writes nothing.
    ----------------------------------------------------------------
    FOR r IN SELECT * FROM (VALUES
        ('{"de": "Vorarbeiter"}'::jsonb,               'a language the app does not speak'),
        ('{"lv": "   "}'::jsonb,                       'an empty name'),
        (jsonb_build_object('lv', repeat('n', 101)),   'a 101-character name'),
        (jsonb_build_object('lv', 'Two' || chr(10) || 'lines'), 'a name on two lines'),
        (jsonb_build_object('lv', 'Bell' || chr(7) || 'ringer'), 'a name with a control character'),
        ('{"lv": 5}'::jsonb,                           'a name that is not text'),
        ('["lv"]'::jsonb,                              'names that are not a map by language')
    ) AS b(labels, why) LOOP
        PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
            'name', 'Refused', 'labels', r.labels), 'membership:invalid', 'a new role given ' || r.why);
        PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
            'roleId', v_foreman, 'labels', r.labels), 'membership:invalid', 'a role changed to ' || r.why);
        PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
            'name', 'Refused', 'labels', r.labels), 'membership:invalid', 'a new user type given ' || r.why);
        PERFORM pg_temp.refused('user_type_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
            'userTypeId', v_office, 'labels', r.labels), 'membership:invalid', 'a user type changed to ' || r.why);
        PERFORM pg_temp.refused('chart_position_add', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
            'name', 'Refused', 'parentId', v_top, 'labels', r.labels), 'membership:invalid', 'a new position given ' || r.why);
        PERFORM pg_temp.refused('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
            'positionId', v_top, 'labels', r.labels), 'membership:invalid', 'a position renamed to ' || r.why);
    END LOOP;
    v_msg := pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Refused', 'labels', jsonb_build_object('lv', repeat('n', 101))), 'membership:invalid', 'a long name');
    IF v_msg NOT LIKE '%name in lv%' THEN
        RAISE EXCEPTION 'the refusal says which language''s name: %', v_msg;
    END IF;
    -- The boundary itself is a name.
    v := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Long names',
        'labels', jsonb_build_object('lv', repeat('n', 100))), 'a 100-character name in Latvian');
    IF length(v->'labels'->>'lv') IS DISTINCT FROM 100 THEN
        RAISE EXCEPTION 'a 100-character name in another language is taken: %', v;
    END IF;

    ----------------------------------------------------------------
    -- 3. A role's names changed: merged per language; only what is sent changes.
    ----------------------------------------------------------------
    -- A language sent sets it; the one not sent stays.
    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_foreman,
        'labels', jsonb_build_object('en', 'Crew foreman')), 'give Foreman an English name');
    IF v->>'name' IS DISTINCT FROM 'Foreman' OR (v->>'changed')::boolean IS NOT TRUE
       OR v->'labels' IS DISTINCT FROM '{"en": "Crew foreman", "lv": "Brigadieris"}'::jsonb
       OR v->>'description' IS DISTINCT FROM 'Leads a crew' THEN
        RAISE EXCEPTION 'names alone change the names, and the name and description stay: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'tenantRoleRenamed', 'a change of names alone');
    IF v->>'from' IS DISTINCT FROM 'Foreman' OR v->>'to' IS DISTINCT FROM 'Foreman'
       OR v->'labels' IS DISTINCT FROM '{"en": "Crew foreman", "lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'a change of names alone is recorded with every name the role now holds: %', v;
    END IF;

    -- A language sent with null is removed; the other stays.
    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_foreman,
        'labels', '{"en": null}'::jsonb), 'take the English name away');
    IF v->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'null removes that language''s name and leaves the other: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'tenantRoleRenamed', 'a removal');
    IF v->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'a removal is recorded with the names left: %', v;
    END IF;

    -- Names not sent are left: a new description changes nothing else.
    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_foreman,
        'description', 'Leads a crew on site'), 'a description alone');
    IF v->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb OR v->>'name' IS DISTINCT FROM 'Foreman' THEN
        RAISE EXCEPTION 'a description alone leaves the names: %', v;
    END IF;
    PERFORM pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'tenantRoleDescribed', 'a description alone is no rename');

    -- The names it already holds, however spaced, change nothing and record nothing.
    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_foreman,
        'labels', jsonb_build_object('lv', ' Brigadieris ')), 'the same name again');
    IF (v->>'changed')::boolean IS NOT FALSE OR v->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'the same names again change nothing: %', v;
    END IF;
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_foreman,
        'labels', '{}'::jsonb, 'name', 'Foreman'), 'no names and the same name');
    IF (v->>'changed')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'an empty map and the same name change nothing: %', v;
    END IF;
    IF jsonb_array_length(pg_temp.since(v_ta, v_mark)) IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'a merge that changes nothing records nothing: %', pg_temp.since(v_ta, v_mark);
    END IF;

    -- A new name alone keeps the names in other languages, and the line says them.
    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_foreman,
        'name', 'Head foreman'), 'a new name alone');
    IF v->>'name' IS DISTINCT FROM 'Head foreman' OR v->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'a new name alone leaves the names in other languages: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'tenantRoleRenamed', 'a rename');
    IF v->>'from' IS DISTINCT FROM 'Foreman' OR v->>'to' IS DISTINCT FROM 'Head foreman'
       OR v->'labels' IS DISTINCT FROM '{"lv": "Brigadieris"}'::jsonb THEN
        RAISE EXCEPTION 'a rename carries the names in other languages it leaves: %', v;
    END IF;

    -- Something must be sent, and a name sent must be a name.
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_foreman), 'membership:invalid', 'a change that sends nothing to change');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_foreman, 'labels', 'null'::jsonb), 'membership:invalid', 'names sent as null');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_foreman, 'name', 'null'::jsonb), 'membership:invalid', 'a name sent as null');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_foreman, 'name', '  ', 'labels', '{"en": "Lead"}'::jsonb), 'membership:invalid', 'a blank name beside names');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'roleId', v_foreman, 'labels', '{"en": "Taken"}'::jsonb), 'membership:not_found', 'another tenant''s role');

    ----------------------------------------------------------------
    -- 4. A user type's names changed: merged per language, recorded with the type.
    ----------------------------------------------------------------
    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('user_type_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userTypeId', v_office,
        'labels', jsonb_build_object('en', 'Back office')), 'give Office an English name');
    IF v->>'name' IS DISTINCT FROM 'Office' OR v->'labels' IS DISTINCT FROM '{"en": "Back office", "lv": "Birojs"}'::jsonb THEN
        RAISE EXCEPTION 'a user type''s names are merged and its name stays: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'userTypeChanged', 'a user type''s names alone');
    IF v->>'name' IS DISTINCT FROM 'Office' OR v->'labels' IS DISTINCT FROM '{"en": "Back office", "lv": "Birojs"}'::jsonb THEN
        RAISE EXCEPTION 'a change of a user type''s names is recorded with the type as it now is: %', v;
    END IF;
    v := pg_temp.ok('user_type_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userTypeId', v_office,
        'labels', '{"en": null}'::jsonb), 'take the English name away');
    IF v->'labels' IS DISTINCT FROM '{"lv": "Birojs"}'::jsonb THEN
        RAISE EXCEPTION 'null removes a user type''s name in that language: %', v;
    END IF;
    v := pg_temp.ok('user_type_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userTypeId', v_office,
        'description', 'Works in the office'), 'a description alone');
    IF v->'labels' IS DISTINCT FROM '{"lv": "Birojs"}'::jsonb OR v->>'name' IS DISTINCT FROM 'Office' THEN
        RAISE EXCEPTION 'names not sent are left: %', v;
    END IF;

    ----------------------------------------------------------------
    -- 5. A position's names changed: only what is sent, recorded only on a change.
    ----------------------------------------------------------------
    v_crew := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Crew',
        'parentId', v_top, 'labels', jsonb_build_object('lv', 'Brigāde')), 'add Crew')->>'id';
    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'positionId', v_crew,
        'labels', jsonb_build_object('en', 'Team')), 'give Crew an English name');
    IF v->>'name' IS DISTINCT FROM 'Crew' OR v->'labels' IS DISTINCT FROM '{"en": "Team", "lv": "Brigāde"}'::jsonb THEN
        RAISE EXCEPTION 'a position''s names are merged and its name stays: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'chartPositionRenamed', 'a position''s names alone');
    IF v->>'name' IS DISTINCT FROM 'Crew' OR v->>'from' IS DISTINCT FROM 'Crew'
       OR v->'labels' IS DISTINCT FROM '{"en": "Team", "lv": "Brigāde"}'::jsonb THEN
        RAISE EXCEPTION 'a change of a position''s names alone is recorded with every name it now holds: %', v;
    END IF;

    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'positionId', v_crew,
        'labels', '{"en": null}'::jsonb), 'take the English name away');
    IF v->'labels' IS DISTINCT FROM '{"lv": "Brigāde"}'::jsonb THEN
        RAISE EXCEPTION 'null removes a position''s name in that language: %', v;
    END IF;
    PERFORM pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'chartPositionRenamed', 'a position''s name removed');

    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'positionId', v_crew,
        'labels', jsonb_build_object('lv', 'Brigāde')), 'the same name again');
    v := pg_temp.ok('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'positionId', v_crew,
        'name', 'Crew'), 'the same name as entered');
    IF jsonb_array_length(pg_temp.since(v_ta, v_mark)) IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'a position renamed to what it is records nothing: %', pg_temp.since(v_ta, v_mark);
    END IF;

    v_mark := pg_temp.mark(v_ta);
    v := pg_temp.ok('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'positionId', v_crew,
        'name', 'Site crew'), 'a new name alone');
    IF v->>'name' IS DISTINCT FROM 'Site crew' OR v->'labels' IS DISTINCT FROM '{"lv": "Brigāde"}'::jsonb THEN
        RAISE EXCEPTION 'a new name alone leaves a position''s names in other languages: %', v;
    END IF;
    v := pg_temp.one_line(pg_temp.since(v_ta, v_mark), 'chartPositionRenamed', 'a position renamed');
    IF v->>'name' IS DISTINCT FROM 'Site crew' OR v->>'from' IS DISTINCT FROM 'Crew'
       OR v->'labels' IS DISTINCT FROM '{"lv": "Brigāde"}'::jsonb THEN
        RAISE EXCEPTION 'a position''s rename carries the names it leaves: %', v;
    END IF;

    PERFORM pg_temp.refused('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'positionId', v_crew), 'membership:invalid', 'a rename that sends nothing');
    PERFORM pg_temp.refused('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'positionId', v_crew, 'labels', 'null'::jsonb), 'membership:invalid', 'a position''s names sent as null');
    PERFORM pg_temp.refused('chart_position_rename', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'positionId', v_crew, 'name', ''), 'membership:invalid', 'a position renamed to nothing');

    ----------------------------------------------------------------
    -- 6. Two roles never read alike in a language the app speaks, nor two user
    --    types; two positions may.
    ----------------------------------------------------------------
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Strādnieks'), 'define Strādnieks');
    -- A name in Latvian against another role's name.
    v_msg := pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Laborer', 'labels', jsonb_build_object('lv', 'strādnieks')), 'membership:conflict',
        'a role whose Latvian name is another role''s name');
    IF v_msg NOT LIKE '%in lv%' THEN
        RAISE EXCEPTION 'the refusal names the language the two read alike in: %', v_msg;
    END IF;
    -- It names the other role as entered: the administrator may see it under
    -- another word than the one that clashed.
    IF v_msg NOT LIKE '%Strādnieks%' THEN
        RAISE EXCEPTION 'the refusal names the role it reads alike: %', v_msg;
    END IF;
    -- A name in Latvian against another's name in Latvian.
    v_rigger := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Rigger', 'labels', jsonb_build_object('lv', 'Takelētājs')), 'define Rigger')->>'id';
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Slinger', 'labels', jsonb_build_object('lv', 'takelētājs')), 'membership:conflict',
        'two roles with one Latvian name');
    -- A name against another's name in Latvian.
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Takelētājs'), 'membership:conflict', 'a role named as another reads in Latvian');
    -- The same, reached by a change.
    v_slinger := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Slinger'), 'define Slinger')->>'id';
    v_msg := pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_slinger, 'labels', jsonb_build_object('lv', 'Takelētājs')), 'membership:conflict',
        'a role given another''s Latvian name');
    IF v_msg NOT LIKE '%in lv%' OR v_msg NOT LIKE '%Rigger%' THEN
        RAISE EXCEPTION 'a refused change names the language and the role it reads alike: %', v_msg;
    END IF;
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_slinger, 'name', 'takelētājs'), 'membership:conflict', 'a role renamed to another''s Latvian name');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_slinger, 'name', 'strādnieks'), 'membership:conflict', 'a role renamed to another''s name');
    -- An English reader too: a role named in Latvian with its English name.
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Krāsotājs', 'labels', jsonb_build_object('en', 'Painter')), 'define Krāsotājs');
    v_msg := pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'painter'), 'membership:conflict', 'a role named as another reads in English');
    IF v_msg NOT LIKE '%in en%' OR v_msg NOT LIKE '%Krāsotājs%' THEN
        RAISE EXCEPTION 'the refusal names English and the role as entered: %', v_msg;
    END IF;
    -- One word in two different languages is no clash: nobody reads both.
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Overseer', 'labels', jsonb_build_object('lv', 'Uzraugs')), 'Overseer, Uzraugs in Latvian');
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Watcher', 'labels', jsonb_build_object('en', 'Uzraugs')), 'Watcher, Uzraugs in English');
    -- A role is never compared with itself: it may take its own Latvian name.
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_rigger, 'name', 'Takelētājs'), 'Rigger named as it reads in Latvian');
    IF v->>'name' IS DISTINCT FROM 'Takelētājs' THEN RAISE EXCEPTION 'a role may take its own name: %', v; END IF;
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_rigger, 'name', 'Rigger'), 'and back');
    -- Another tenant's words are its own.
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'name', 'Laborer', 'labels', jsonb_build_object('lv', 'Strādnieks')), 'the same words in B');

    -- User types.
    v_planner := pg_temp.ok('user_type_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Planner', 'labels', jsonb_build_object('lv', 'Plānotājs')), 'define Planner')->>'id';
    v_msg := pg_temp.refused('user_type_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'plānotājs'), 'membership:conflict', 'a user type named as another reads in Latvian');
    IF v_msg NOT LIKE '%in lv%' OR v_msg NOT LIKE '%Planner%' THEN
        RAISE EXCEPTION 'the refusal names the language and the user type as entered: %', v_msg;
    END IF;
    PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Scheduler', 'labels', jsonb_build_object('lv', 'Plānotājs')), 'membership:conflict',
        'two user types with one Latvian name');
    PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Clerk', 'labels', jsonb_build_object('en', 'office')), 'membership:conflict',
        'a user type whose English name is another''s name');
    v_field := pg_temp.ok('user_type_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Field'), 'define Field')->>'id';
    PERFORM pg_temp.refused('user_type_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userTypeId', v_field, 'labels', jsonb_build_object('lv', 'Plānotājs')), 'membership:conflict',
        'a user type given another''s Latvian name');
    PERFORM pg_temp.refused('user_type_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userTypeId', v_field, 'name', 'Plānotājs'), 'membership:conflict', 'a user type renamed to another''s Latvian name');
    v := pg_temp.ok('user_type_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userTypeId', v_planner, 'name', 'Plānotājs'), 'Planner named as it reads in Latvian');
    IF v->>'name' IS DISTINCT FROM 'Plānotājs' THEN RAISE EXCEPTION 'a user type may take its own name: %', v; END IF;
    PERFORM pg_temp.ok('user_type_define', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'name', 'Scheduler', 'labels', jsonb_build_object('lv', 'Plānotājs')), 'the same words in B');

    -- Positions: two seats of one kind may carry one name, in every language.
    PERFORM pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Brigade',
        'parentId', v_top, 'labels', jsonb_build_object('lv', 'Brigāde')), 'one Brigade');
    PERFORM pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Brigade',
        'parentId', v_top, 'labels', jsonb_build_object('lv', 'Brigāde')), 'a second Brigade');

    ----------------------------------------------------------------
    -- 7. The administration read: each tenant role, the user type and the chart's
    --    user type with its names.
    ----------------------------------------------------------------
    v_person := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Ieva Liepa', 'roles', '[]'::jsonb), 'invite Ieva')->>'id';
    UPDATE rolebyte.user_account SET status = 'active' WHERE id = v_person;
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_person,
        'roleId', v_foreman), 'Ieva is a Head foreman');
    PERFORM pg_temp.ok('user_type_assign', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_person,
        'userTypeId', v_office), 'Ieva works in the office');
    PERFORM pg_temp.ok('chart_position_user_type_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'positionId', v_crew, 'userTypeId', v_planner), 'Site crew makes its people planners');
    v := pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_person,
        'positionId', v_crew), 'Ieva sits in Site crew');
    IF v->'labels' IS DISTINCT FROM '{"lv": "Brigāde"}'::jsonb THEN
        RAISE EXCEPTION 'a position answered by any act carries its names: %', v;
    END IF;
    v := pg_temp.access_row(v_ta, v_person);
    IF v->'tenantRoles' IS DISTINCT FROM jsonb_build_array(jsonb_build_object('id', v_foreman, 'name', 'Head foreman',
                                                         'labels', '{"lv": "Brigadieris"}'::jsonb)) THEN
        RAISE EXCEPTION 'the administration read names each tenant role in every language: %', v;
    END IF;
    IF v->'userType' IS DISTINCT FROM jsonb_build_object('id', v_office, 'name', 'Office', 'labels', '{"lv": "Birojs"}'::jsonb) THEN
        RAISE EXCEPTION 'the administration read names the user type in every language: %', v;
    END IF;
    IF v->'chartUserType' IS DISTINCT FROM jsonb_build_object('id', v_planner, 'name', 'Plānotājs',
                                                              'labels', '{"lv": "Plānotājs"}'::jsonb) THEN
        RAISE EXCEPTION 'the administration read names the chart''s user type in every language: %', v;
    END IF;

    ----------------------------------------------------------------
    -- 8. Lists keep the order of the name as entered: a screen re-sorts in its
    --    reader's words.
    ----------------------------------------------------------------
    v_alpha := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'name', 'Alpha team', 'labels', jsonb_build_object('lv', 'Zeta komanda')), 'Alpha')->>'id';
    v_beta := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'name', 'Beta team', 'labels', jsonb_build_object('lv', 'Alfa komanda')), 'Beta')->>'id';
    v := pg_temp.ok('tenant_role_list', jsonb_build_object('tenantId', v_tb), 'list B');
    IF (SELECT array_agg(e.value->>'id' ORDER BY e.ordinality) FROM jsonb_array_elements(v->'roles') WITH ORDINALITY e
         WHERE e.value->>'id' IN (v_alpha, v_beta)) IS DISTINCT FROM ARRAY[v_alpha, v_beta] THEN
        RAISE EXCEPTION 'the roles are in the order of their names as entered: %', v;
    END IF;

    ----------------------------------------------------------------
    -- 9. The shipped roles and the default user type, in both languages.
    --    This test's own service declares a permission for the shipped worker and
    --    manager, and takes the declaration back at the end, so the tests after
    --    it meet a deployment that ships no roles, as they expect.
    ----------------------------------------------------------------
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'task', 'act', 'view', 'description', 'See tasks', 'class', 'ordinary',
                           'plane', 'object', 'seeds', jsonb_build_array('worker', 'manager'))), 'ship roles');

    -- English asked: the English names, with the Latvian beside them.
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Names shipped EN',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Anna Ozola')),
        'open in English');
    v_te := v->'tenant'->>'id';
    IF (SELECT jsonb_object_agg(seed, jsonb_build_object('name', name, 'labels', labels))
          FROM rolebyte.tenant_role WHERE tenant_id = v_te)
       IS DISTINCT FROM '{"guest":   {"name": "Guest",   "labels": {"lv": "Viesis"}},
                          "worker":  {"name": "Worker",  "labels": {"lv": "Darbinieks"}},
                          "manager": {"name": "Manager", "labels": {"lv": "Vadītājs"}}}'::jsonb THEN
        RAISE EXCEPTION 'a tenant opened in English ships its roles in English, Latvian beside: %',
            (SELECT jsonb_agg(jsonb_build_object('seed', seed, 'name', name, 'labels', labels))
               FROM rolebyte.tenant_role WHERE tenant_id = v_te);
    END IF;
    IF (SELECT e->'labels' FROM jsonb_array_elements(v->'roles') e WHERE e->>'seed' = 'worker')
       IS DISTINCT FROM '{"lv": "Darbinieks"}'::jsonb THEN
        RAISE EXCEPTION 'opening a tenant answers the shipped roles with their names: %', v;
    END IF;
    IF (SELECT e.payload->'labels' FROM rolebyte.event e
         WHERE e.tenant_id = v_te AND e.kind = 'tenantRoleSeeded' AND e.payload->>'seed' = 'manager')
       IS DISTINCT FROM '{"lv": "Vadītājs"}'::jsonb THEN
        RAISE EXCEPTION 'the line that ships a role carries its names';
    END IF;
    IF (SELECT jsonb_build_object('name', t.name, 'labels', t.labels)
          FROM rolebyte.tenant n JOIN rolebyte.user_type t ON t.id = n.default_user_type_id WHERE n.id = v_te)
       IS DISTINCT FROM '{"name": "Member", "labels": {"lv": "Dalībnieks"}}'::jsonb THEN
        RAISE EXCEPTION 'the default user type is Member, Dalībnieks beside it';
    END IF;
    IF (SELECT e.payload->'labels' FROM rolebyte.event e
         WHERE e.tenant_id = v_te AND e.kind = 'userTypeDefined')
       IS DISTINCT FROM '{"lv": "Dalībnieks"}'::jsonb THEN
        RAISE EXCEPTION 'the line that makes the default user type carries its names';
    END IF;

    -- Latvian asked: the Latvian names, with the English beside them.
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Names shipped LV', 'language', 'lv',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Toms Ozols')),
        'open in Latvian');
    v_tl := v->'tenant'->>'id';
    IF (SELECT jsonb_object_agg(seed, jsonb_build_object('name', name, 'labels', labels))
          FROM rolebyte.tenant_role WHERE tenant_id = v_tl)
       IS DISTINCT FROM '{"guest":   {"name": "Viesis",     "labels": {"en": "Guest"}},
                          "worker":  {"name": "Darbinieks", "labels": {"en": "Worker"}},
                          "manager": {"name": "Vadītājs",   "labels": {"en": "Manager"}}}'::jsonb THEN
        RAISE EXCEPTION 'a tenant opened in Latvian ships its roles in Latvian, English beside';
    END IF;
    IF (SELECT jsonb_build_object('name', t.name, 'labels', t.labels)
          FROM rolebyte.tenant n JOIN rolebyte.user_type t ON t.id = n.default_user_type_id WHERE n.id = v_tl)
       IS DISTINCT FROM '{"name": "Dalībnieks", "labels": {"en": "Member"}}'::jsonb THEN
        RAISE EXCEPTION 'the Latvian default user type is Dalībnieks, Member beside it';
    END IF;
    -- Creating a tenant directly ships them the same way.
    v_tc := pg_temp.ok('tenant_create', '{"actor": "op:test", "name": "Names shipped by create", "language": "lv"}',
        'create in Latvian')->>'id';
    IF (SELECT labels FROM rolebyte.tenant_role WHERE tenant_id = v_tc AND seed = 'worker')
       IS DISTINCT FROM '{"en": "Worker"}'::jsonb THEN
        RAISE EXCEPTION 'a tenant created in Latvian ships Darbinieks with Worker beside it';
    END IF;

    -- A tenant that already reads a shipped word another way keeps it. Its roles
    -- are cleared first, as for a tenant opened before its services shipped any.
    v_tk := pg_temp.ok('tenant_create', '{"actor": "op:test", "name": "Names shipped later"}', 'create')->>'id';
    DELETE FROM rolebyte.tenant_role_permission WHERE tenant_role_id IN
        (SELECT id FROM rolebyte.tenant_role WHERE tenant_id = v_tk);
    DELETE FROM rolebyte.tenant_role WHERE tenant_id = v_tk;
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-k', 'tenantId', v_tk,
        'name', 'Darbinieks'), 'its own Darbinieks');
    PERFORM pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-k', 'tenantId', v_tk,
        'name', 'Kalps', 'labels', jsonb_build_object('en', 'Guest')), 'its own Kalps, Guest in English');
    v := pg_temp.ok('tenant_seed_roles', jsonb_build_object('actor', 'op:test', 'tenantId', v_tk), 'ship them now');
    IF v->'missing' IS DISTINCT FROM '["guest"]'::jsonb THEN
        RAISE EXCEPTION 'Guest stays missing: the tenant''s own role reads Guest in English: %', v;
    END IF;
    IF (SELECT jsonb_build_object('name', name, 'labels', labels) FROM rolebyte.tenant_role
         WHERE tenant_id = v_tk AND seed = 'worker')
       IS DISTINCT FROM '{"name": "Worker", "labels": {}}'::jsonb THEN
        RAISE EXCEPTION 'Worker is shipped without its Latvian name, which the tenant''s own Darbinieks keeps';
    END IF;
    IF (SELECT labels FROM rolebyte.tenant_role WHERE tenant_id = v_tk AND seed = 'manager')
       IS DISTINCT FROM '{"lv": "Vadītājs"}'::jsonb THEN
        RAISE EXCEPTION 'Manager is shipped with its Latvian name';
    END IF;
    IF (SELECT e->'labels' FROM jsonb_array_elements(v->'roles') e WHERE e->>'seed' = 'manager')
       IS DISTINCT FROM '{"lv": "Vadītājs"}'::jsonb THEN
        RAISE EXCEPTION 'the operator''s answer names the shipped roles in every language: %', v;
    END IF;
    v := pg_temp.ok('tenant_seed_roles', jsonb_build_object('actor', 'op:test', 'tenantId', v_tk), 'again');
    IF (SELECT e->'labels' FROM jsonb_array_elements(v->'kept') e WHERE e->>'seed' = 'manager')
       IS DISTINCT FROM '{"lv": "Vadītājs"}'::jsonb THEN
        RAISE EXCEPTION 'the shipped roles kept are answered with their names: %', v;
    END IF;

    -- The default user type, made at the first arrival of a tenant the register
    -- created: without its Latvian name when the tenant's own type has it...
    v_td := pg_temp.ok('tenant_create', '{"actor": "op:test", "name": "Names default"}', 'create')->>'id';
    PERFORM pg_temp.ok('user_type_define', jsonb_build_object('actor', 'adm-d', 'tenantId', v_td,
        'name', 'Dalībnieks'), 'its own Dalībnieks');
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-d', 'tenantId', v_td,
        'subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'First arrival', 'roles', '[]'::jsonb), 'arrive');
    IF (SELECT jsonb_build_object('name', t.name, 'labels', t.labels)
          FROM rolebyte.tenant n JOIN rolebyte.user_type t ON t.id = n.default_user_type_id WHERE n.id = v_td)
       IS DISTINCT FROM '{"name": "Member", "labels": {}}'::jsonb THEN
        RAISE EXCEPTION 'the default is Member alone when the tenant''s own type is Dalībnieks';
    END IF;
    -- ...and a type that already reads Member is adopted rather than doubled.
    v_tg := pg_temp.ok('tenant_create', '{"actor": "op:test", "name": "Names adopt"}', 'create')->>'id';
    v_biedrs := pg_temp.ok('user_type_define', jsonb_build_object('actor', 'adm-g', 'tenantId', v_tg,
        'name', 'Biedrs', 'labels', jsonb_build_object('en', 'Member')), 'its own Biedrs, Member in English')->>'id';
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-g', 'tenantId', v_tg,
        'subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'First arrival', 'roles', '[]'::jsonb), 'arrive');
    IF (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_tg) IS DISTINCT FROM v_biedrs
       OR (SELECT count(*) FROM rolebyte.user_type WHERE tenant_id = v_tg) IS DISTINCT FROM 1::bigint THEN
        RAISE EXCEPTION 'a type that reads Member becomes the default, and no second is made';
    END IF;

    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'task', 'act', 'view', 'description', 'See tasks', 'class', 'ordinary',
                           'plane', 'object')), 'ship nothing again');

    RAISE NOTICE 'unit.rolebyte_names: names held';
END $$;

----------------------------------------------------------------------------
-- The race: two administrators at the same moment. The first act runs in a
-- second session (dblink) and holds its transaction open with pg_sleep once it
-- is done; this session starts the second act only after it sees the other
-- session sleeping (its wait event, never a guessed head start), then asserts
-- that the second act waited, was refused, and that only the first act's object
-- stands. The rows the second session reads are committed first.
----------------------------------------------------------------------------

-- Waits until the backend is asleep in pg_sleep, for at most ten seconds.
CREATE OR REPLACE FUNCTION pg_temp.until_sleeping(p_pid int) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_until timestamptz := clock_timestamp() + interval '10 seconds';
BEGIN
    LOOP
        -- The activity view is read once per transaction unless told to look again.
        PERFORM pg_stat_clear_snapshot();
        EXIT WHEN EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = p_pid AND wait_event = 'PgSleep');
        IF clock_timestamp() > v_until THEN
            RAISE EXCEPTION 'the first act never reached its sleep: %',
                (SELECT row_to_json(a) FROM pg_stat_activity a WHERE a.pid = p_pid);
        END IF;
        PERFORM pg_sleep(0.02);
    END LOOP;
END $$;

-- Starts one act in the other session: the call, which must succeed, then the
-- transaction held open for two seconds.
CREATE OR REPLACE FUNCTION pg_temp.first(p_conn text, p_proc text, p_in jsonb) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM public.dblink_send_query(p_conn, format(
        $q$DO $x$ DECLARE v jsonb; BEGIN
             CALL rolebyte.%I(%L::jsonb, v);
             IF v->>'result' IS DISTINCT FROM 'success' THEN
                 RAISE EXCEPTION 'the first act failed: %%', v;
             END IF;
             PERFORM pg_sleep(2);
           END $x$ $q$, p_proc, p_in::text));
END $$;

-- Collects the other session's answer; raises what it raised.
CREATE OR REPLACE FUNCTION pg_temp.finish(p_conn text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM * FROM public.dblink_get_result(p_conn) AS t(status text);
    PERFORM * FROM public.dblink_get_result(p_conn) AS t(status text);
END $$;

-- Calls an act here; answers what it answered and how long it took.
CREATE OR REPLACE FUNCTION pg_temp.second(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_t0 timestamptz := clock_timestamp();
BEGIN
    RETURN pg_temp.rb(p_proc, p_in) || jsonb_build_object('waited', extract(epoch FROM clock_timestamp() - v_t0));
END $$;

DO $$
DECLARE
    v      jsonb;
    v_t    text;
    v_type text;
    v_conn text := 'names-race';
    v_pid  int;
BEGIN
    v_t := pg_temp.ok('tenant_create', '{"actor": "op:test", "name": "Names race"}', 'tenant')->>'id';
    v_type := pg_temp.ok('user_type_define', jsonb_build_object('actor', 'adm-r', 'tenantId', v_t,
        'name', 'Surveyor'), 'define Surveyor')->>'id';
    COMMIT;

    PERFORM public.dblink_connect(v_conn, format('dbname=%s user=%s', current_database(), current_user));
    SELECT t.pid INTO v_pid FROM public.dblink(v_conn, 'SELECT pg_backend_pid()') AS t(pid int);

    -- 1. Welder (Metinātājs in Latvian) there, a role named Metinātājs here.
    PERFORM pg_temp.first(v_conn, 'tenant_role_define', jsonb_build_object('actor', 'adm-first', 'tenantId', v_t,
        'name', 'Welder', 'labels', jsonb_build_object('lv', 'Metinātājs')));
    PERFORM pg_temp.until_sleeping(v_pid);
    v := pg_temp.second('tenant_role_define', jsonb_build_object('actor', 'adm-second', 'tenantId', v_t,
        'name', 'Metinātājs'));
    PERFORM pg_temp.finish(v_conn);
    COMMIT;
    IF v->>'code' IS DISTINCT FROM 'membership:conflict' THEN
        RAISE EXCEPTION 'a role reading as one being made at the same moment is refused once that one is there: %', v;
    END IF;
    IF (v->>'waited')::numeric < 1 THEN
        RAISE EXCEPTION 'the second role waited for the first to finish, it took % s', v->>'waited';
    END IF;
    IF (SELECT string_agg(name, ',') FROM rolebyte.tenant_role WHERE tenant_id = v_t AND seed = '')
       IS DISTINCT FROM 'Welder' THEN
        RAISE EXCEPTION 'only the first role stands';
    END IF;

    -- 2. Inspector (Inspektors in Latvian) there, Surveyor given that Latvian name here.
    PERFORM pg_temp.first(v_conn, 'user_type_define', jsonb_build_object('actor', 'adm-first', 'tenantId', v_t,
        'name', 'Inspector', 'labels', jsonb_build_object('lv', 'Inspektors')));
    PERFORM pg_temp.until_sleeping(v_pid);
    v := pg_temp.second('user_type_update', jsonb_build_object('actor', 'adm-second', 'tenantId', v_t,
        'userTypeId', v_type, 'labels', jsonb_build_object('lv', 'inspektors')));
    PERFORM pg_temp.finish(v_conn);
    COMMIT;
    IF v->>'code' IS DISTINCT FROM 'membership:conflict' THEN
        RAISE EXCEPTION 'a user type given the Latvian name of one being made at the same moment is refused: %', v;
    END IF;
    IF (v->>'waited')::numeric < 1 THEN
        RAISE EXCEPTION 'the change waited for the new user type, it took % s', v->>'waited';
    END IF;
    IF (SELECT labels FROM rolebyte.user_type WHERE id = v_type) IS DISTINCT FROM '{}'::jsonb THEN
        RAISE EXCEPTION 'Surveyor keeps no Latvian name';
    END IF;

    PERFORM public.dblink_disconnect(v_conn);
    RAISE NOTICE 'unit.rolebyte_names: ALL PASSED';
END $$;
