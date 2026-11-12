-- Unit test: who may change what a service declared.
-- A permission remembers the client that declared it. Only that client changes it
-- through a declaration; another client that holds the same key may repeat it
-- unchanged and is refused any change, with nothing of the document written. A
-- permission no client declared is taken by the first client to name it, and
-- the deployment's own registration still changes anything and never touches the
-- declarer. The chart of authority is all or nothing under one service key, on
-- both paths. A declaration reinstates a retired permission only when the same
-- client's declaration retired it; the deployment's registration reinstates any. The groups `declare` and `declare-group` are
-- reserved. A level may be defined only in a group the caller may use under its
-- key. One service key holds at most 1000 permissions and 100 levels through a
-- declaration, and no limit through the deployment's registration.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_declaration_ownership.sql

-- Declares a document as a client granted the listed keys, with the optional list
-- of groups, and returns the answer. A refusal raised after a write is returned
-- as the structured error, so a test reads both the same way.
CREATE OR REPLACE FUNCTION pg_temp.decl(p_actor text, p_allowed jsonb, p_section jsonb, p_groups jsonb DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    BEGIN
        CALL rolebyte.service_declare(jsonb_build_object(
            'actor', p_actor, 'allowed', p_allowed, 'section', p_section)
            || CASE WHEN p_groups IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('groups', p_groups) END, v);
    EXCEPTION
        WHEN sqlstate 'P0001' THEN
            v := sqlerrm::jsonb;
    END;
    RETURN v;
END $$;

-- The deployment's own registration of a document, answered the same way.
CREATE OR REPLACE FUNCTION pg_temp.owner(p_section jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    BEGIN
        CALL rolebyte.permissions_register(jsonb_build_object('actor', 'op:test', 'section', p_section), v);
    EXCEPTION
        WHEN sqlstate 'P0001' THEN
            v := sqlerrm::jsonb;
    END;
    RETURN v;
END $$;

-- Everything the register holds that these tests read, as one comparable text.
CREATE OR REPLACE FUNCTION pg_temp.fingerprint() RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.service t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.role_definition t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.service_permission t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.event t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.service_declaration t)))
$$;

-- The permissions and the history alone (a declaration row moves its time on every accepted call).
CREATE OR REPLACE FUNCTION pg_temp.perm_fingerprint() RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.service_permission t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.event t)))
$$;

-- One permission entry, and a document of one service entry.
CREATE OR REPLACE FUNCTION pg_temp.p(p_feature text, p_act text, p_desc text DEFAULT '', p_plane text DEFAULT 'object')
RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_build_object('feature', p_feature, 'act', p_act, 'description', p_desc,
                              'class', 'ordinary', 'plane', p_plane)
$$;

CREATE OR REPLACE FUNCTION pg_temp.pdoc(p_key text, p_perms jsonb, p_roles jsonb DEFAULT NULL) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_build_object('services', jsonb_build_array(
        jsonb_build_object('key', p_key, 'permissions', p_perms)
        || CASE WHEN p_roles IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('roles', p_roles) END))
$$;

-- A stored permission as the entry that would repeat it unchanged.
CREATE OR REPLACE FUNCTION pg_temp.cur(p_key text, p_feature text, p_act text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_build_object('feature', feature_key, 'act', act, 'description', description,
                              'class', class, 'plane', plane)
           || CASE WHEN labels = '{}'::jsonb THEN '{}'::jsonb ELSE jsonb_build_object('labels', labels) END
           || CASE WHEN cardinality(seeds) = 0 THEN '{}'::jsonb ELSE jsonb_build_object('seeds', to_jsonb(seeds)) END
      FROM rolebyte.service_permission
     WHERE service_key = p_key AND feature_key = p_feature AND act = p_act
$$;

-- The report line of one permission, by its name.
CREATE OR REPLACE FUNCTION pg_temp.report_line(p_answer jsonb, p_name text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT e FROM jsonb_array_elements(p_answer->'data'->'permissions') e WHERE e->>'key' = p_name
$$;

CREATE OR REPLACE FUNCTION pg_temp.declarer(p_key text, p_feature text, p_act text) RETURNS text
LANGUAGE sql AS $$
    SELECT declared_by FROM rolebyte.service_permission WHERE service_key = p_key AND feature_key = p_feature AND act = p_act
$$;

CREATE OR REPLACE FUNCTION pg_temp.events(p_kind text) RETURNS bigint
LANGUAGE sql AS $$
    SELECT count(*) FROM rolebyte.event WHERE kind = p_kind
$$;

-- The answer must be this error with exactly this message.
CREATE OR REPLACE FUNCTION pg_temp.said(p_answer jsonb, p_code text, p_message text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_answer->>'result' IS DISTINCT FROM 'error' OR p_answer->>'code' IS DISTINCT FROM p_code
       OR p_answer->>'message' IS DISTINCT FROM p_message THEN
        RAISE EXCEPTION '% should be refused % saying "%": %', p_why, p_code, p_message, left(p_answer::text, 400);
    END IF;
END $$;

-- A declaration that must be refused with this code and message, and write nothing.
CREATE OR REPLACE FUNCTION pg_temp.refuse_decl(p_actor text, p_key text, p_section jsonb, p_code text, p_message text,
                                               p_why text, p_groups jsonb DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    before text := pg_temp.fingerprint();
BEGIN
    PERFORM pg_temp.said(pg_temp.decl(p_actor, to_jsonb(ARRAY[p_key]), p_section, p_groups), p_code, p_message, p_why);
    IF pg_temp.fingerprint() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
END $$;

-- The deployment's registration that must be refused with this code and message, and write nothing.
CREATE OR REPLACE FUNCTION pg_temp.refuse_owner(p_section jsonb, p_code text, p_message text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    before text := pg_temp.fingerprint();
BEGIN
    PERFORM pg_temp.said(pg_temp.owner(p_section), p_code, p_message, p_why);
    IF pg_temp.fingerprint() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
END $$;

-- The answer must be a success; returns it.
CREATE OR REPLACE FUNCTION pg_temp.good(p_answer jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
BEGIN
    IF p_answer->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% should be accepted: %', p_why, left(p_answer::text, 400);
    END IF;
    RETURN p_answer;
END $$;

-- 1. Ownership of a permission.
DO $$
DECLARE
    k      text := 'own-a';
    v_c1   text := 'svc:own-one';
    v_c2   text := 'svc:own-two';
    v      jsonb;
    v_fp   text;
    v_n    bigint;
    v_rec  record;
    v_said text;
BEGIN
    -- The one vocabulary function has one argument list: no second form is left to make a call ambiguous.
    IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'rolebyte' AND p.proname = 'config_vocabulary') <> 1 THEN
        RAISE EXCEPTION 'the vocabulary function should exist in exactly one form';
    END IF;

    -- A new permission is added, with its declaring client.
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(
        pg_temp.p('item', 'view', 'See'),
        pg_temp.p('item', 'edit', 'Change') || '{"labels":{"lv":"Mainīt"},"seeds":["worker"]}'::jsonb))), 'a first declaration');
    IF (SELECT count(*) FROM jsonb_array_elements(v->'data'->'permissions') e WHERE e->>'status' = 'added') <> 2
       OR pg_temp.declarer(k, 'item', 'view') IS DISTINCT FROM v_c1
       OR pg_temp.declarer(k, 'item', 'edit') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'both permissions should be added with the declaring client: %', v;
    END IF;

    -- The same client changes its description, its labels and its seeds.
    v_n := pg_temp.events('permissionDescribed');
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]),
        pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'view') || '{"description":"See it"}'))), 'the declarer changes the description');
    IF pg_temp.report_line(v, k || '/item:view')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.report_line(v, k || '/item:view')->>'detail' IS DISTINCT FROM 'description'
       OR (SELECT description FROM rolebyte.service_permission WHERE service_key = k AND act = 'view') IS DISTINCT FROM 'See it'
       OR pg_temp.events('permissionDescribed') IS DISTINCT FROM v_n + 1
       OR pg_temp.declarer(k, 'item', 'view') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'the declarer should change the description and stay the declarer: %', v;
    END IF;
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]),
        pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'view') || '{"labels":{"lv":"Skatīt"}}'))), 'the declarer changes the labels');
    IF pg_temp.report_line(v, k || '/item:view')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.declarer(k, 'item', 'view') IS DISTINCT FROM v_c1
       OR pg_temp.report_line(v, k || '/item:view')->>'detail' IS DISTINCT FROM 'labels'
       OR (SELECT labels FROM rolebyte.service_permission WHERE service_key = k AND act = 'view') IS DISTINCT FROM '{"lv":"Skatīt"}'::jsonb THEN
        RAISE EXCEPTION 'the declarer should change the labels: %', v;
    END IF;
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]),
        pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'edit') || '{"seeds":["manager","worker"]}'))), 'the declarer changes the seeds');
    IF pg_temp.report_line(v, k || '/item:edit')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.declarer(k, 'item', 'edit') IS DISTINCT FROM v_c1
       OR pg_temp.report_line(v, k || '/item:edit')->>'detail' IS DISTINCT FROM 'seeds'
       OR (SELECT seeds FROM rolebyte.service_permission WHERE service_key = k AND act = 'edit') IS DISTINCT FROM ARRAY['manager', 'worker'] THEN
        RAISE EXCEPTION 'the declarer should change the seeds: %', v;
    END IF;

    -- Another client allowed the same key sends both unchanged: unchanged, nothing written.
    v_fp := pg_temp.perm_fingerprint();
    v := pg_temp.good(pg_temp.decl(v_c2, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(
        pg_temp.cur(k, 'item', 'view'), pg_temp.cur(k, 'item', 'edit')))), 'another client repeating a permission unchanged');
    IF pg_temp.report_line(v, k || '/item:view')->>'status' IS DISTINCT FROM 'unchanged'
       OR pg_temp.report_line(v, k || '/item:edit')->>'status' IS DISTINCT FROM 'unchanged'
       OR pg_temp.perm_fingerprint() IS DISTINCT FROM v_fp
       OR pg_temp.declarer(k, 'item', 'view') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'another client repeating a permission should change nothing: %', v;
    END IF;

    -- Another client changes the description, the labels, the seeds, or retires it: refused, nothing of the
    -- document (a new permission ahead of the change included) is written.
    v_said := k || '/item:%s: ' || k || '/item:%s was declared by another client, and only that client changes it';
    FOR v_rec IN SELECT * FROM (VALUES
        ('view', '{"description":"Someone else''s words"}'::jsonb, 'a description'),
        ('view', '{"labels":{"lv":"Cits"}}'::jsonb,               'the labels'),
        ('edit', '{"seeds":["worker"]}'::jsonb,                  'the seeds'),
        ('view', '{"retired":true}'::jsonb,                      'a retirement')) AS t(act, change, what) LOOP
        PERFORM pg_temp.refuse_decl(v_c2, k, pg_temp.pdoc(k, jsonb_build_array(
                pg_temp.p('item', 'fresh', 'Never written'),
                pg_temp.cur(k, 'item', v_rec.act) || v_rec.change)),
            'membership:config_key_conflict', format(v_said, v_rec.act, v_rec.act),
            'another client changing ' || v_rec.what);
    END LOOP;
    IF EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key = k AND act = 'fresh')
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'view') IS NOT NULL
       OR pg_temp.declarer(k, 'item', 'view') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'a refused change should leave the row and the document as they were';
    END IF;

    -- A permission with no plane yet: another client's declaration is refused, the declarer's fills it.
    UPDATE rolebyte.service_permission SET plane = NULL WHERE service_key = k AND act = 'view';
    PERFORM pg_temp.refuse_decl(v_c2, k, pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'view') || '{"plane":"object"}')),
        'membership:config_key_conflict', format(v_said, 'view', 'view'), 'another client filling in a missing plane');
    IF (SELECT plane FROM rolebyte.service_permission WHERE service_key = k AND act = 'view') IS NOT NULL THEN
        RAISE EXCEPTION 'the refused plane must not have been written';
    END IF;
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]),
        pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'view') || '{"plane":"object"}'))), 'the declarer filling in a plane');
    IF pg_temp.report_line(v, k || '/item:view')->>'detail' IS DISTINCT FROM 'plane'
       OR (SELECT plane FROM rolebyte.service_permission WHERE service_key = k AND act = 'view') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'the declarer should fill in the plane: %', v;
    END IF;

    -- A permission the deployment entered has no declarer; the first client to declare it takes it.
    v := pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('item', 'owned', 'Owner made')))),
        'the deployment adding a permission');
    IF pg_temp.report_line(v, k || '/item:owned')->>'status' IS DISTINCT FROM 'added' THEN
        RAISE EXCEPTION 'the deployment adding a permission should read added: %', v;
    END IF;
    IF pg_temp.declarer(k, 'item', 'owned') IS NOT NULL THEN
        RAISE EXCEPTION 'a permission the deployment adds should have no declarer';
    END IF;
    v_n := pg_temp.events('permissionClaimed');
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]),
        pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'owned')))), 'the first client declaring an owner-made permission');
    IF pg_temp.report_line(v, k || '/item:owned')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.report_line(v, k || '/item:owned')->>'detail' IS DISTINCT FROM 'declarer'
       OR pg_temp.declarer(k, 'item', 'owned') IS DISTINCT FROM v_c1
       OR pg_temp.events('permissionClaimed') IS DISTINCT FROM v_n + 1
       OR NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'permissionClaimed' AND actor = v_c1
                       AND payload->>'service' = k AND payload->>'permission' = k || '/item:owned') THEN
        RAISE EXCEPTION 'the first declaration should claim the permission with one history line: %', v;
    END IF;
    -- the same client again claims nothing more; a second client's change is refused
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]),
        pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'owned')))), 'the claiming client again');
    IF pg_temp.report_line(v, k || '/item:owned')->>'status' IS DISTINCT FROM 'unchanged'
       OR pg_temp.events('permissionClaimed') IS DISTINCT FROM v_n + 1 THEN
        RAISE EXCEPTION 'a second declaration by the same client should claim nothing: %', v;
    END IF;
    PERFORM pg_temp.refuse_decl(v_c2, k, pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'owned') || '{"description":"Mine now"}')),
        'membership:config_key_conflict', format(v_said, 'owned', 'owned'), 'a second client changing a claimed permission');
    -- a claim together with another difference: both are applied
    PERFORM pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('item', 'owned2', 'A')))), 'a second owner-made permission');
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('item', 'owned2', 'B')))),
        'a claim that also changes the description');
    IF pg_temp.report_line(v, k || '/item:owned2')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.report_line(v, k || '/item:owned2')->>'detail' IS DISTINCT FROM 'declarer, description'
       OR (SELECT description FROM rolebyte.service_permission WHERE service_key = k AND act = 'owned2') IS DISTINCT FROM 'B'
       OR pg_temp.declarer(k, 'item', 'owned2') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'a claim should also apply the other difference: %', v;
    END IF;

    -- The deployment's own registration changes a client's permission, and the declarer stays.
    v := pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'item', 'view') || '{"description":"Owner words"}'))),
        'the deployment changing a declared permission');
    IF pg_temp.report_line(v, k || '/item:view')->>'status' IS DISTINCT FROM 'changed'
       OR (SELECT description FROM rolebyte.service_permission WHERE service_key = k AND act = 'view') IS DISTINCT FROM 'Owner words'
       OR pg_temp.declarer(k, 'item', 'view') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'the deployment should change the permission and leave the declarer: %', v;
    END IF;
    -- A seeded permission would give every tenant a later test opens a seeded role: leave none behind.
    UPDATE rolebyte.service_permission SET seeds = '{}' WHERE service_key = k;
    RAISE NOTICE 'unit.rolebyte_declaration_ownership: ownership passed';
END $$;

-- 2. The chart's plane is all or nothing under a service key.
DO $$
DECLARE
    v_c1 text := 'svc:own-one';
    v    jsonb;
    v_fp text;
BEGIN
    -- A key holding the chart takes no other plane; a key holding another plane takes no chart permission.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-ch"]'::jsonb, pg_temp.pdoc('own-ch', jsonb_build_array(
        pg_temp.p('project', 'view', 'Chart', 'chart')))), 'a chart-only document');
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-tn"]'::jsonb, pg_temp.pdoc('own-tn', jsonb_build_array(
        pg_temp.p('project', 'create', 'Tenant', 'tenant'), pg_temp.p('project', 'view', 'Object', 'object')))),
        'a document of tenant and object permissions');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-ch', pg_temp.pdoc('own-ch', jsonb_build_array(pg_temp.p('task', 'create', 'Tenant', 'tenant'))),
        'membership:config_key_conflict',
        'own-ch/task:create: own-ch/task:create is a tenant permission, and service own-ch holds only permissions of the chart of authority',
        'a tenant permission under a chart key');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-ch', pg_temp.pdoc('own-ch', jsonb_build_array(pg_temp.p('task', 'view', 'Object', 'object'))),
        'membership:config_key_conflict',
        'own-ch/task:view: own-ch/task:view is a object permission, and service own-ch holds only permissions of the chart of authority',
        'an object permission under a chart key');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-tn', pg_temp.pdoc('own-tn', jsonb_build_array(pg_temp.p('task', 'view', 'Chart', 'chart'))),
        'membership:config_key_conflict',
        'own-tn/task:view: own-tn/task:view is a permission of the chart of authority, and service own-tn holds permissions of other planes',
        'a chart permission under a key of other planes');

    -- A first document that mixes both is refused at the second kind, and neither is written.
    v_fp := pg_temp.fingerprint();
    PERFORM pg_temp.refuse_decl(v_c1, 'own-mix1', pg_temp.pdoc('own-mix1', jsonb_build_array(
            pg_temp.p('a', 'view', 'Chart', 'chart'), pg_temp.p('b', 'create', 'Tenant', 'tenant'))),
        'membership:config_key_conflict',
        'own-mix1/b:create: own-mix1/b:create is a tenant permission, and service own-mix1 holds only permissions of the chart of authority',
        'a first document with a chart permission then a tenant one');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-mix2', pg_temp.pdoc('own-mix2', jsonb_build_array(
            pg_temp.p('a', 'create', 'Tenant', 'tenant'), pg_temp.p('b', 'view', 'Chart', 'chart'))),
        'membership:config_key_conflict',
        'own-mix2/b:view: own-mix2/b:view is a permission of the chart of authority, and service own-mix2 holds permissions of other planes',
        'a first document with a tenant permission then a chart one');
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key IN ('own-mix1', 'own-mix2'))
       OR EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key IN ('own-mix1', 'own-mix2')) THEN
        RAISE EXCEPTION 'a mixed first document must write neither of its permissions';
    END IF;
    -- the same with a permission of the object plane
    PERFORM pg_temp.refuse_decl(v_c1, 'own-mix3', pg_temp.pdoc('own-mix3', jsonb_build_array(
            pg_temp.p('a', 'view', 'Chart', 'chart'), pg_temp.p('b', 'view', 'Object', 'object'))),
        'membership:config_key_conflict',
        'own-mix3/b:view: own-mix3/b:view is a object permission, and service own-mix3 holds only permissions of the chart of authority',
        'a first document with a chart permission then an object one');
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'own-mix3')
       OR EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key = 'own-mix3') THEN
        RAISE EXCEPTION 'a first document mixing the chart and the object plane must write neither of its permissions';
    END IF;
    -- documents of one kind are accepted
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-only-chart"]'::jsonb, pg_temp.pdoc('own-only-chart', jsonb_build_array(
        pg_temp.p('a', 'view', 'One', 'chart'), pg_temp.p('b', 'view', 'Two', 'chart')))), 'a document of chart permissions only');
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-only-other"]'::jsonb, pg_temp.pdoc('own-only-other', jsonb_build_array(
        pg_temp.p('a', 'create', 'One', 'tenant'), pg_temp.p('b', 'view', 'Two', 'object')))), 'a document of other planes only');

    -- A retired permission still counts; a row with no plane does not.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-ch"]'::jsonb, pg_temp.pdoc('own-ch', jsonb_build_array(
        pg_temp.cur('own-ch', 'project', 'view') || '{"retired":true}'))), 'the declarer retiring its chart permission');
    IF (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = 'own-ch') IS NULL THEN
        RAISE EXCEPTION 'the chart permission should be retired';
    END IF;
    PERFORM pg_temp.refuse_decl(v_c1, 'own-ch', pg_temp.pdoc('own-ch', jsonb_build_array(pg_temp.p('task', 'create', 'Tenant', 'tenant'))),
        'membership:config_key_conflict',
        'own-ch/task:create: own-ch/task:create is a tenant permission, and service own-ch holds only permissions of the chart of authority',
        'a tenant permission under a key whose only chart permission is retired');
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-nul"]'::jsonb, pg_temp.pdoc('own-nul', jsonb_build_array(pg_temp.p('a', 'view', 'Old')))),
        'a key with one permission');
    UPDATE rolebyte.service_permission SET plane = NULL WHERE service_key = 'own-nul';
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-nul"]'::jsonb, pg_temp.pdoc('own-nul', jsonb_build_array(
        pg_temp.p('b', 'view', 'Chart', 'chart')))), 'a chart permission beside a row with no plane');

    -- Filling in a missing plane is held to the rule too: a row with no plane may not take a plane that
    -- does not fit what the key holds, while the key's chart row stands.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-fill"]'::jsonb, pg_temp.pdoc('own-fill', jsonb_build_array(pg_temp.p('a', 'view', 'Old')))),
        'a key with one permission');
    UPDATE rolebyte.service_permission SET plane = NULL WHERE service_key = 'own-fill';
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-fill"]'::jsonb, pg_temp.pdoc('own-fill', jsonb_build_array(
        pg_temp.p('b', 'view', 'Chart', 'chart')))), 'a chart permission beside a row with no plane');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-fill', pg_temp.pdoc('own-fill', jsonb_build_array(pg_temp.p('a', 'view', 'Old'))),
        'membership:config_key_conflict',
        'own-fill/a:view: own-fill/a:view is a object permission, and service own-fill holds only permissions of the chart of authority',
        'filling in an object plane under a key that holds the chart');
    IF (SELECT plane FROM rolebyte.service_permission WHERE service_key = 'own-fill' AND feature_key = 'a') IS NOT NULL THEN
        RAISE EXCEPTION 'the refused plane must not have been written';
    END IF;

    -- The deployment's registration is held to the same rule.
    PERFORM pg_temp.refuse_owner(pg_temp.pdoc('own-only-chart', jsonb_build_array(pg_temp.p('c', 'create', 'Tenant', 'tenant'))),
        'membership:config_key_conflict',
        'own-only-chart/c:create: own-only-chart/c:create is a tenant permission, and service own-only-chart holds only permissions of the chart of authority',
        'the deployment adding a tenant permission under a chart key');
    PERFORM pg_temp.refuse_owner(pg_temp.pdoc('own-only-other', jsonb_build_array(pg_temp.p('c', 'view', 'Chart', 'chart'))),
        'membership:config_key_conflict',
        'own-only-other/c:view: own-only-other/c:view is a permission of the chart of authority, and service own-only-other holds permissions of other planes',
        'the deployment adding a chart permission under a key of other planes');
    RAISE NOTICE 'unit.rolebyte_declaration_ownership: the chart plane passed';
END $$;

-- 3. A declaration reinstates only a retirement of its own client.
DO $$
DECLARE
    k      text := 'own-r';
    v_c1   text := 'svc:own-one';
    v_c2   text := 'svc:own-two';
    v_gone text := 'retired in the register; a declaration does not reinstate it';
    v      jsonb;
    v_ev   bigint;
    v_fp   text;
BEGIN
    PERFORM pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(
        pg_temp.p('r', 'one', 'One'), pg_temp.p('r', 'two', 'Two'), pg_temp.p('r', 'three', 'Three')))), 'three permissions');

    -- Retired by a direct update, then declared without the mark: still retired, unchanged with the detail, no event, twice.
    UPDATE rolebyte.service_permission SET retired_at = now() WHERE service_key = k AND act = 'one';
    FOR i IN 1..2 LOOP
        v_fp := pg_temp.perm_fingerprint();
        v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'one')))),
            'declaring a retired permission without the mark');
        IF pg_temp.report_line(v, k || '/r:one')->>'status' IS DISTINCT FROM 'unchanged'
           OR pg_temp.report_line(v, k || '/r:one')->>'detail' IS DISTINCT FROM v_gone
           OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'one') IS NULL
           OR pg_temp.perm_fingerprint() IS DISTINCT FROM v_fp THEN
            RAISE EXCEPTION 'a declaration should leave a retired permission retired and write nothing (run %): %', i, v;
        END IF;
    END LOOP;
    -- another client's unmarked entry reads the same
    v := pg_temp.good(pg_temp.decl(v_c2, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'one')))),
        'another client declaring a retired permission without the mark');
    IF pg_temp.report_line(v, k || '/r:one')->>'status' IS DISTINCT FROM 'unchanged'
       OR pg_temp.report_line(v, k || '/r:one')->>'detail' IS DISTINCT FROM v_gone THEN
        RAISE EXCEPTION 'another client should read a retired permission as unchanged with the detail: %', v;
    END IF;

    -- Retired by the deployment's registration: the same.
    PERFORM pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'two') || '{"retired":true}'))),
        'the deployment retiring a permission');
    IF (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'two') IS NULL THEN
        RAISE EXCEPTION 'the deployment should have retired the permission';
    END IF;
    v_fp := pg_temp.perm_fingerprint();
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'two')))),
        'declaring a permission the deployment retired');
    IF pg_temp.report_line(v, k || '/r:two')->>'status' IS DISTINCT FROM 'unchanged'
       OR pg_temp.report_line(v, k || '/r:two')->>'detail' IS DISTINCT FROM v_gone
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'two') IS NULL
       OR pg_temp.perm_fingerprint() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'a declaration should not reinstate what the deployment retired: %', v;
    END IF;

    -- The client's own mark retires it: the history line names the client, and the permission
    -- remembers it.
    v_ev := pg_temp.events('permissionRetired');
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'three') || '{"retired":true}'))),
        'a client retiring its own permission');
    IF pg_temp.report_line(v, k || '/r:three')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.report_line(v, k || '/r:three')->>'detail' IS DISTINCT FROM 'retired'
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'three') IS NULL
       OR (SELECT retired_by FROM rolebyte.service_permission WHERE service_key = k AND act = 'three') IS DISTINCT FROM v_c1
       OR pg_temp.events('permissionRetired') IS DISTINCT FROM v_ev + 1
       OR NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'permissionRetired' AND actor = v_c1
                       AND payload->>'service' = k AND payload->>'permission' = k || '/r:three') THEN
        RAISE EXCEPTION 'a client should retire its own permission, with its event: %', v;
    END IF;
    -- The same client declaring it without the mark brings it back, with its event.
    v_ev := pg_temp.events('permissionReinstated');
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'three')))),
        'declaring a permission the client retired without the mark');
    IF pg_temp.report_line(v, k || '/r:three')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.report_line(v, k || '/r:three')->>'detail' IS DISTINCT FROM 'retired'
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'three') IS NOT NULL
       OR (SELECT retired_by FROM rolebyte.service_permission WHERE service_key = k AND act = 'three') IS NOT NULL
       OR pg_temp.events('permissionReinstated') IS DISTINCT FROM v_ev + 1
       OR NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'permissionReinstated' AND actor = v_c1
                       AND payload->>'permission' = k || '/r:three') THEN
        RAISE EXCEPTION 'a client''s own retirement should be lifted by its own declaration, with its event: %', v;
    END IF;
    -- Retired by hand after that, it stays retired at the client's next declaration.
    UPDATE rolebyte.service_permission SET retired_at = now() WHERE service_key = k AND act = 'three';
    v_fp := pg_temp.perm_fingerprint();
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'three')))),
        'declaring a permission retired by hand after the client lifted its own retirement');
    IF pg_temp.report_line(v, k || '/r:three')->>'status' IS DISTINCT FROM 'unchanged'
       OR pg_temp.report_line(v, k || '/r:three')->>'detail' IS DISTINCT FROM v_gone
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'three') IS NULL
       OR pg_temp.perm_fingerprint() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'a retirement by hand should stand: %', v;
    END IF;

    -- The deployment's registration, without the mark, reinstates, with its event.
    v_ev := pg_temp.events('permissionReinstated');
    v := pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'three')))), 'the deployment reinstating');
    IF pg_temp.report_line(v, k || '/r:three')->>'status' IS DISTINCT FROM 'changed'
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'three') IS NOT NULL
       OR pg_temp.events('permissionReinstated') IS DISTINCT FROM v_ev + 1
       OR pg_temp.declarer(k, 'r', 'three') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'the deployment should reinstate with its event and leave the declarer: %', v;
    END IF;

    -- A declaration still retires a permission nobody declared, and claims it.
    PERFORM pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('r', 'four', 'Four')))), 'an owner-made permission');
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'four') || '{"retired":true}'))),
        'a client retiring a permission nobody declared');
    IF pg_temp.report_line(v, k || '/r:four')->>'detail' IS DISTINCT FROM 'declarer, retired'
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'four') IS NULL
       OR pg_temp.declarer(k, 'r', 'four') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'a client should claim and retire a permission nobody declared: %', v;
    END IF;

    -- The declarer of a retired permission changes its description: changed, and it stays retired.
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'one') || '{"description":"One, reworded"}'))),
        'the declarer changing a retired permission');
    IF pg_temp.report_line(v, k || '/r:one')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.report_line(v, k || '/r:one')->>'detail' IS DISTINCT FROM 'description; ' || v_gone
       OR (SELECT description FROM rolebyte.service_permission WHERE service_key = k AND act = 'one') IS DISTINCT FROM 'One, reworded'
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'one') IS NULL THEN
        RAISE EXCEPTION 'the declarer should change the description, the permission stay retired and the line say so: %', v;
    END IF;

    -- A claim of a retired permission also says it stays retired.
    PERFORM pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('r', 'seven', 'Seven') || '{"retired":true}'))),
        'the deployment adding a retired permission');
    IF (SELECT retired_by FROM rolebyte.service_permission WHERE service_key = k AND act = 'seven') IS NOT NULL
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'seven') IS NULL THEN
        RAISE EXCEPTION 'a permission the deployment adds retired is retired by nobody in particular';
    END IF;
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('r', 'seven', 'Seven, reworded')))),
        'a client claiming a retired permission');
    IF pg_temp.report_line(v, k || '/r:seven')->>'status' IS DISTINCT FROM 'changed'
       OR pg_temp.report_line(v, k || '/r:seven')->>'detail' IS DISTINCT FROM 'declarer, description; ' || v_gone
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'seven') IS NULL THEN
        RAISE EXCEPTION 'a claim of a retired permission should apply the change, keep it retired and say so: %', v;
    END IF;

    -- A permission inserted already retired by a client remembers the client; the deployment
    -- retiring it makes the retirement its own, with no event and no change, and it then stays
    -- retired at that client's next declaration.
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('r', 'five', 'Five') || '{"retired":true}'))),
        'a client declaring a new permission already retired');
    IF pg_temp.report_line(v, k || '/r:five')->>'status' IS DISTINCT FROM 'added'
       OR (SELECT retired_by FROM rolebyte.service_permission WHERE service_key = k AND act = 'five') IS DISTINCT FROM v_c1 THEN
        RAISE EXCEPTION 'a permission a client declares retired is retired by that client: %', v;
    END IF;
    v_ev := pg_temp.events('permissionRetired');
    v := pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'five') || '{"retired":true}'))),
        'the deployment retiring what a client retired');
    IF pg_temp.report_line(v, k || '/r:five')->>'status' IS DISTINCT FROM 'unchanged'
       OR (SELECT retired_by FROM rolebyte.service_permission WHERE service_key = k AND act = 'five') IS NOT NULL
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'five') IS NULL
       OR pg_temp.events('permissionRetired') IS DISTINCT FROM v_ev THEN
        RAISE EXCEPTION 'the deployment retiring a client''s retirement should make it its own, quietly: %', v;
    END IF;
    v_fp := pg_temp.perm_fingerprint();
    v := pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'five')))),
        'the client declaring what the deployment now holds retired');
    IF pg_temp.report_line(v, k || '/r:five')->>'status' IS DISTINCT FROM 'unchanged'
       OR pg_temp.report_line(v, k || '/r:five')->>'detail' IS DISTINCT FROM v_gone
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'five') IS NULL
       OR pg_temp.perm_fingerprint() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'a retirement the deployment took over should stand: %', v;
    END IF;

    -- The deployment's registration reinstating what a client retired leaves no trace of the client's retirement.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('r', 'eight', 'Eight') || '{"retired":true}'))),
        'a client declaring another permission retired');
    v := pg_temp.good(pg_temp.owner(pg_temp.pdoc(k, jsonb_build_array(pg_temp.cur(k, 'r', 'eight')))), 'the deployment reinstating what a client retired');
    IF pg_temp.report_line(v, k || '/r:eight')->>'status' IS DISTINCT FROM 'changed'
       OR (SELECT retired_at FROM rolebyte.service_permission WHERE service_key = k AND act = 'eight') IS NOT NULL
       OR (SELECT retired_by FROM rolebyte.service_permission WHERE service_key = k AND act = 'eight') IS NOT NULL THEN
        RAISE EXCEPTION 'the deployment reinstating should clear the client''s retirement: %', v;
    END IF;
    RAISE NOTICE 'unit.rolebyte_declaration_ownership: reinstating passed';
END $$;

-- 4. Reserved groups, and the groups a caller may define levels in.
DO $$
DECLARE
    k      text := 'own-gk';
    v_c1   text := 'svc:own-one';
    v      jsonb;
    v_fp   text;
    v_g    text;
BEGIN
    -- The deployment's role_define refuses the reserved groups, as it refuses `deployment`.
    CALL rolebyte.service_register('{"actor":"op:test","service":"own-grp"}'::jsonb, v);
    v_fp := pg_temp.fingerprint();
    FOREACH v_g IN ARRAY ARRAY['declare', 'declare-group'] LOOP
        v := NULL;
        CALL rolebyte.role_define(jsonb_build_object('actor', 'op:test', 'service', 'own-grp', 'group', v_g, 'level', 'read'), v);
        PERFORM pg_temp.said(v, 'membership:invalid',
            format('the group %s is reserved and is not a level anything may define', v_g), 'role_define on group ' || v_g);
        -- a declaration refuses them too, whether or not the caller lists them
        PERFORM pg_temp.refuse_decl(v_c1, 'own-grp', pg_temp.pdoc('own-grp', '[]'::jsonb,
                jsonb_build_array(jsonb_build_object('group', v_g, 'level', 'read'))),
            'membership:config_key_conflict', format('service own-grp may not declare group %s: the group is reserved', v_g),
            'a declaration of group ' || v_g);
        PERFORM pg_temp.refuse_decl(v_c1, 'own-grp', pg_temp.pdoc('own-grp', '[]'::jsonb,
                jsonb_build_array(jsonb_build_object('group', v_g, 'level', 'read'))),
            'membership:config_key_conflict', format('service own-grp may not declare group %s: the group is reserved', v_g),
            'a declaration of group ' || v_g || ' that lists it', to_jsonb(ARRAY[v_g]));
    END LOOP;
    IF EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE role_group IN ('declare', 'declare-group')) THEN
        RAISE EXCEPTION 'no level of a reserved group may exist';
    END IF;

    -- A group named like the key needs no list.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, '[]'::jsonb,
        jsonb_build_array(jsonb_build_object('group', k, 'level', 'read')))), 'a group named like the key');
    -- A foreign-named group is accepted when the caller lists it.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, '[]'::jsonb,
        jsonb_build_array(jsonb_build_object('group', 'ops-own', 'level', 'read'))), '["ops-own"]'::jsonb), 'a group the caller lists');
    IF NOT EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE service_key = k AND role_group = 'ops-own' AND role_level = 'read') THEN
        RAISE EXCEPTION 'the level of the listed group should exist';
    END IF;
    -- Unlisted and defined nowhere: forbidden, and neither a level nor a permission of the document is written.
    PERFORM pg_temp.refuse_decl(v_c1, k, pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('thing', 'view', 'Never written')),
            jsonb_build_array(jsonb_build_object('group', 'ops-none', 'level', 'read'))),
        'membership:forbidden', 'the caller may not declare group ops-none', 'a group nobody listed and nothing defines');
    IF EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE role_group = 'ops-none')
       OR EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key = k AND feature_key = 'thing') THEN
        RAISE EXCEPTION 'a forbidden group must leave no level and no permission';
    END IF;
    -- Unlisted but already defined under the key: accepted, and the new level is added.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, '[]'::jsonb,
        jsonb_build_array(jsonb_build_object('group', 'ops-own', 'level', 'write')))), 'a group the key already holds');
    IF (SELECT count(*) FROM rolebyte.role_definition WHERE service_key = k AND role_group = 'ops-own') <> 2 THEN
        RAISE EXCEPTION 'the group should now hold two levels under the key';
    END IF;
    -- Defined under another key, even when listed: a key conflict.
    PERFORM pg_temp.refuse_decl(v_c1, 'own-gz', pg_temp.pdoc('own-gz', '[]'::jsonb,
            jsonb_build_array(jsonb_build_object('group', 'ops-own', 'level', 'read'))),
        'membership:config_key_conflict', 'service own-gz may not declare group ops-own: a group belongs to one service',
        'a listed group another key defined', '["ops-own"]'::jsonb);
    -- The group membership: the register's own key may define in it, no other key may, listed or not.
    -- (undone afterwards, so no other file finds the service row, the level or the history it writes)
    BEGIN
        PERFORM pg_temp.good(pg_temp.decl(v_c1, '["rolebyte"]'::jsonb, pg_temp.pdoc('rolebyte', '[]'::jsonb,
            jsonb_build_array(jsonb_build_object('group', 'membership', 'level', 'own-probe')))), 'the group membership under the register''s key');
        IF NOT EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE service_key = 'rolebyte' AND role_group = 'membership' AND role_level = 'own-probe') THEN
            RAISE EXCEPTION 'the level of the group membership should exist under the register''s key';
        END IF;
        RAISE EXCEPTION 'undo' USING errcode = 'RB002';
    EXCEPTION
        WHEN sqlstate 'RB002' THEN NULL;
    END;
    IF EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE role_level = 'own-probe') THEN
        RAISE EXCEPTION 'the probe level should have been undone';
    END IF;
    PERFORM pg_temp.refuse_decl(v_c1, k, pg_temp.pdoc(k, '[]'::jsonb,
            jsonb_build_array(jsonb_build_object('group', 'membership', 'level', 'own-probe'))),
        'membership:config_key_conflict', 'service own-gk may not declare group membership: a group belongs to one service',
        'the group membership under another key that lists it', '["membership"]'::jsonb);
    PERFORM pg_temp.refuse_decl(v_c1, k, pg_temp.pdoc(k, '[]'::jsonb,
            jsonb_build_array(jsonb_build_object('group', 'membership', 'level', 'own-probe'))),
        'membership:config_key_conflict', 'service own-gk may not declare group membership: a group belongs to one service',
        'the group membership under another key without a list');

    -- `groups`: absent and null are an empty list; anything else that is not a list of strings is refused.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, '[]'::jsonb), 'null'::jsonb), 'groups that is null');
    PERFORM pg_temp.good(pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, '[]'::jsonb), '[]'::jsonb), 'groups that is empty');
    FOREACH v_g IN ARRAY ARRAY['"ops-own"', '[1]', '["ops-own", 5]', '{"ops-own": true}', '[null]'] LOOP
        v_fp := pg_temp.fingerprint();
        v := pg_temp.decl(v_c1, to_jsonb(ARRAY[k]), pg_temp.pdoc(k, jsonb_build_array(pg_temp.p('thing', 'view', 'Never written'))), v_g::jsonb);
        PERFORM pg_temp.said(v, 'membership:invalid', 'groups is a list of group names', 'groups ' || v_g);
        IF pg_temp.fingerprint() IS DISTINCT FROM v_fp THEN
            RAISE EXCEPTION 'groups % was refused but changed something', v_g;
        END IF;
    END LOOP;
    RAISE NOTICE 'unit.rolebyte_declaration_ownership: reserved groups and the group rule passed';
END $$;

-- A document of the given number of permissions (feature f<i>, act view) for one key.
CREATE OR REPLACE FUNCTION pg_temp.many(p_key text, p_from int, p_to int) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.pdoc(p_key, (SELECT jsonb_agg(pg_temp.p('f' || i, 'view')) FROM generate_series(p_from, p_to) i))
$$;

-- 5. Totals per service key.
DO $$
DECLARE
    v_c1 text := 'svc:own-one';
    v    jsonb;
    v_fp text;
BEGIN
    -- 999 held plus 1 new is accepted; 1000 held plus 1 new is refused with nothing written.
    PERFORM pg_temp.good(pg_temp.owner(pg_temp.many('own-t1', 1, 999)), 'the deployment adding 999 permissions');
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-t1"]'::jsonb, pg_temp.many('own-t1', 1000, 1000)), '999 held plus 1');
    IF (SELECT count(*) FROM rolebyte.service_permission WHERE service_key = 'own-t1') <> 1000 THEN
        RAISE EXCEPTION 'the key should hold 1000 permissions';
    END IF;
    PERFORM pg_temp.refuse_decl(v_c1, 'own-t1', pg_temp.many('own-t1', 1001, 1001),
        'membership:config_bad_document', 'service own-t1 would hold more than 1000 permissions', '1000 held plus 1');
    IF EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key = 'own-t1' AND feature_key = 'f1001') THEN
        RAISE EXCEPTION 'the refused permission must not be written';
    END IF;
    -- 1000 held, 500 of them sent again (and claimed): accepted.
    v := pg_temp.good(pg_temp.decl(v_c1, '["own-t1"]'::jsonb, pg_temp.many('own-t1', 1, 500)), '1000 held and 500 sent again');
    IF (SELECT count(*) FROM rolebyte.service_permission WHERE service_key = 'own-t1' AND declared_by = v_c1) <> 501 THEN
        RAISE EXCEPTION 'the 500 sent again and the one added earlier should be the client''s';
    END IF;
    -- The deployment's registration has no such limit: it adds the 1001st.
    PERFORM pg_temp.good(pg_temp.owner(pg_temp.many('own-t1', 1001, 1001)), 'the deployment adding the 1001st permission');
    IF (SELECT count(*) FROM rolebyte.service_permission WHERE service_key = 'own-t1') <> 1001 THEN
        RAISE EXCEPTION 'the deployment should be able to take the key past 1000';
    END IF;
    -- A key past the limit still accepts a declaration that adds nothing new, and refuses one that adds.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-t1"]'::jsonb, pg_temp.many('own-t1', 1, 10)),
        'a declaration repeating permissions of a key at 1001');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-t1', pg_temp.many('own-t1', 1002, 1002),
        'membership:config_bad_document', 'service own-t1 would hold more than 1000 permissions', 'a new permission for a key at 1001');

    -- A key whose permissions one client declared: sending half of them again changes nothing.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-t4"]'::jsonb, pg_temp.many('own-t4', 1, 500)), 'the first 500 of a client''s 1000');
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-t4"]'::jsonb, pg_temp.many('own-t4', 501, 1000)), 'the second 500 of a client''s 1000');
    v := pg_temp.good(pg_temp.decl(v_c1, '["own-t4"]'::jsonb, pg_temp.many('own-t4', 1, 500)), '500 of 1000 sent again by their client');
    IF jsonb_array_length(v->'data'->'permissions') <> 500
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v->'data'->'permissions') e WHERE e->>'status' IS DISTINCT FROM 'unchanged') THEN
        RAISE EXCEPTION 'every line of the 500 sent again should read unchanged: %', left(v::text, 300);
    END IF;

    -- Retired permissions count: 1000 held, 10 of them retired, plus 1 is refused.
    PERFORM pg_temp.good(pg_temp.owner(pg_temp.many('own-t2', 1, 1000)), 'the deployment adding 1000 permissions');
    UPDATE rolebyte.service_permission SET retired_at = now()
     WHERE service_key = 'own-t2' AND feature_key IN (SELECT 'f' || i FROM generate_series(1, 10) i);
    PERFORM pg_temp.refuse_decl(v_c1, 'own-t2', pg_temp.many('own-t2', 1001, 1001),
        'membership:config_bad_document', 'service own-t2 would hold more than 1000 permissions', '1000 held, 10 retired, plus 1');

    -- Levels: 99 held plus 1 is accepted, 100 held plus 1 is refused with nothing written, and the deployment adds the 101st.
    PERFORM pg_temp.good(pg_temp.owner(jsonb_build_object('services', jsonb_build_array(jsonb_build_object(
        'key', 'own-t3', 'roles', (SELECT jsonb_agg(jsonb_build_object('group', 'own-t3', 'level', 'l' || i))
                                     FROM generate_series(1, 99) i))))), 'the deployment adding 99 levels');
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-t3"]'::jsonb, pg_temp.pdoc('own-t3', '[]'::jsonb,
        jsonb_build_array(jsonb_build_object('group', 'own-t3', 'level', 'l100')))), '99 levels plus 1');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-t3', pg_temp.pdoc('own-t3', jsonb_build_array(pg_temp.p('thing', 'view', 'Never written')),
            jsonb_build_array(jsonb_build_object('group', 'own-t3', 'level', 'l101'))),
        'membership:config_bad_document', 'service own-t3 would hold more than 100 levels', '100 levels plus 1');
    IF EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE service_key = 'own-t3' AND role_level = 'l101')
       OR EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key = 'own-t3') THEN
        RAISE EXCEPTION 'a refused document must write neither its level nor its permission';
    END IF;
    PERFORM pg_temp.good(pg_temp.owner(jsonb_build_object('services', jsonb_build_array(jsonb_build_object(
        'key', 'own-t3', 'roles', jsonb_build_array(jsonb_build_object('group', 'own-t3', 'level', 'l101')))))),
        'the deployment adding the 101st level');
    IF (SELECT count(*) FROM rolebyte.role_definition WHERE service_key = 'own-t3') <> 101 THEN
        RAISE EXCEPTION 'the deployment should be able to take the key past 100 levels';
    END IF;
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-t3"]'::jsonb, pg_temp.pdoc('own-t3', '[]'::jsonb,
        jsonb_build_array(jsonb_build_object('group', 'own-t3', 'level', 'l1')))), 'a declaration repeating a level of a key at 101');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-t3', pg_temp.pdoc('own-t3', '[]'::jsonb,
            jsonb_build_array(jsonb_build_object('group', 'own-t3', 'level', 'l102'))),
        'membership:config_bad_document', 'service own-t3 would hold more than 100 levels', 'a new level for a key at 101');
    RAISE NOTICE 'unit.rolebyte_declaration_ownership: all assertions passed';
END $$;

-- 6. A document names a thing once, at most 20 labels sit on a permission, and every key is
-- checked against the grant before any group is judged.
DO $$
DECLARE
    v_c1 text := 'svc:own-one';
    v    jsonb;
BEGIN
    PERFORM pg_temp.refuse_decl(v_c1, 'own-d', jsonb_build_object('services', jsonb_build_array(
            jsonb_build_object('key', 'own-d', 'displayName', 'One'), jsonb_build_object('key', 'own-d', 'displayName', 'Two'))),
        'membership:config_bad_document', 'service own-d is named more than once in the document', 'a service named twice');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-d', pg_temp.pdoc('own-d', jsonb_build_array(
            pg_temp.p('item', 'view', 'One'), pg_temp.p('item', 'view', 'Two'))),
        'membership:config_bad_document', 'service own-d names the permission item:view more than once', 'a permission named twice');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-d', pg_temp.pdoc('own-d', '[]'::jsonb, jsonb_build_array(
            jsonb_build_object('group', 'own-d', 'level', 'read'), jsonb_build_object('group', 'own-d', 'level', 'read'))),
        'membership:config_bad_document', 'service own-d names the level own-d:read more than once', 'a level named twice');
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'own-d') THEN
        RAISE EXCEPTION 'a document naming a thing twice must write nothing';
    END IF;
    -- the same feature under another act, and the same level in another group, are not repeats
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-d"]'::jsonb, pg_temp.pdoc('own-d', jsonb_build_array(
            pg_temp.p('item', 'view'), pg_temp.p('item', 'edit'), pg_temp.p('other', 'view')),
        jsonb_build_array(jsonb_build_object('group', 'own-d', 'level', 'read'), jsonb_build_object('group', 'own-d', 'level', 'write'))
        )), 'permissions and levels that differ');

    -- Twenty labels on a permission are accepted, twenty-one refused; the deployment's registration is not bound.
    PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-e"]'::jsonb, pg_temp.pdoc('own-e', jsonb_build_array(
        pg_temp.p('item', 'view') || jsonb_build_object('labels',
            (SELECT jsonb_object_agg('a' || chr(97 + i), 'x') FROM generate_series(0, 19) i))))), '20 labels');
    IF (SELECT count(*) FROM rolebyte.service_permission p, jsonb_object_keys(p.labels) WHERE service_key = 'own-e') <> 20 THEN
        RAISE EXCEPTION 'the 20 labels should be stored';
    END IF;
    PERFORM pg_temp.refuse_decl(v_c1, 'own-e2', pg_temp.pdoc('own-e2', jsonb_build_array(
        pg_temp.p('item', 'view') || jsonb_build_object('labels',
            (SELECT jsonb_object_agg('a' || chr(97 + i), 'x') FROM generate_series(0, 20) i)))),
        'membership:config_bad_document', 'a permission of service own-e2 has more than 20 labels', '21 labels');
    PERFORM pg_temp.good(pg_temp.owner(pg_temp.pdoc('own-e2', jsonb_build_array(
        pg_temp.p('item', 'view') || jsonb_build_object('labels',
            (SELECT jsonb_object_agg('a' || chr(97 + i), 'x') FROM generate_series(0, 20) i))))), 'the deployment adding 21 labels');

    -- A key the caller may not declare is answered before any group of the document is judged.
    PERFORM pg_temp.refuse_decl(v_c1, 'own-ga', jsonb_build_object('services', jsonb_build_array(
            jsonb_build_object('key', 'own-gx', 'roles', jsonb_build_array(jsonb_build_object('group', 'ops-zz', 'level', 'read'))))),
        'membership:forbidden', 'the caller may not declare service own-gx', 'a key outside the grant with a group the caller may not use');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-ga', jsonb_build_object('services', jsonb_build_array(
            jsonb_build_object('key', 'own-gx', 'roles', jsonb_build_array(jsonb_build_object('group', 'declare', 'level', 'read'))))),
        'membership:forbidden', 'the caller may not declare service own-gx', 'a key outside the grant with a reserved group');
    PERFORM pg_temp.refuse_decl(v_c1, 'own-ga', jsonb_build_object('services', jsonb_build_array(
            jsonb_build_object('key', 'own-gx', 'roles', jsonb_build_array(jsonb_build_object('group', 'membership', 'level', 'read'))))),
        'membership:forbidden', 'the caller may not declare service own-gx', 'a key outside the grant with the group membership');
    RAISE NOTICE 'unit.rolebyte_declaration_ownership: one document, labels and order passed';
END $$;

-- Calls one register procedure and returns its data; any answer but a success is a failure of the test.
CREATE OR REPLACE FUNCTION pg_temp.run(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_proc, v;
    END IF;
    RETURN v->'data';
END $$;

-- The scope list of the subject's membership in a tenant.
CREATE OR REPLACE FUNCTION pg_temp.scopes(p_subject text, p_tenant text) RETURNS text[]
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', p_subject), v);
    RETURN COALESCE((SELECT array_agg(x) FROM jsonb_array_elements(v->'data'->'memberships') m,
                           jsonb_array_elements_text(m->'scopes') x
                      WHERE m->>'tenantId' = p_tenant), '{}');
END $$;

-- 7. What a company administrator holds does not return with a retired permission a declaration
-- left retired. Everything this makes is undone at the end, so no company stays behind.
DO $$
DECLARE
    v_c1     text := 'svc:own-one';
    v_admin  text := 'sub:' || util.generate_ulid();
    v_tenant text;
    v        jsonb;
BEGIN
    BEGIN
        PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-adm"]'::jsonb, pg_temp.pdoc('own-adm', jsonb_build_array(
            pg_temp.p('item', 'view', 'See'), pg_temp.p('item', 'edit', 'Change')))), 'a service with two permissions');
        v := pg_temp.run('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Own admin demo',
            'administrator', jsonb_build_object('subjectKey', v_admin, 'displayName', 'Anna Ozola')));
        v_tenant := v->'tenant'->>'id';
        PERFORM pg_temp.run('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_admin));
        PERFORM pg_temp.run('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_tenant, 'service', 'own-adm'));
        IF NOT (pg_temp.scopes(v_admin, v_tenant) @> ARRAY['own-adm/item:view', 'own-adm/item:edit']) THEN
            RAISE EXCEPTION 'the administrator should hold both permissions: %', pg_temp.scopes(v_admin, v_tenant);
        END IF;

        UPDATE rolebyte.service_permission SET retired_at = now() WHERE service_key = 'own-adm' AND act = 'edit';
        PERFORM pg_temp.good(pg_temp.decl(v_c1, '["own-adm"]'::jsonb, pg_temp.pdoc('own-adm', jsonb_build_array(
            pg_temp.cur('own-adm', 'item', 'view'), pg_temp.cur('own-adm', 'item', 'edit')))),
            'the client declaring again without the mark');
        IF 'own-adm/item:edit' = ANY (pg_temp.scopes(v_admin, v_tenant))
           OR NOT ('own-adm/item:view' = ANY (pg_temp.scopes(v_admin, v_tenant))) THEN
            RAISE EXCEPTION 'the administrator should hold the live permission and not the retired one: %', pg_temp.scopes(v_admin, v_tenant);
        END IF;
        RAISE EXCEPTION 'undo' USING errcode = 'RB003';
    EXCEPTION
        WHEN sqlstate 'RB003' THEN NULL;
    END;
    IF EXISTS (SELECT 1 FROM rolebyte.tenant WHERE name = 'Own admin demo')
       OR EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'own-adm') THEN
        RAISE EXCEPTION 'the administrator check should have been undone';
    END IF;
    RAISE NOTICE 'unit.rolebyte_declaration_ownership: administrator passed';
END $$;

-- Nothing of these services stays for another test file to read: a row with no plane,
-- a seeded permission or a thousand permissions would change what an export of the
-- vocabulary carries. (The history lines stay: that list only grows.)
DELETE FROM rolebyte.service_permission WHERE service_key LIKE 'own-%';
DELETE FROM rolebyte.role_definition WHERE service_key LIKE 'own-%';
DELETE FROM rolebyte.service_declaration WHERE service_key LIKE 'own-%';
DELETE FROM rolebyte.service WHERE key LIKE 'own-%';
