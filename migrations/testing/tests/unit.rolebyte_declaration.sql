-- Unit test: a service declares itself to the register.
-- A caller acting as a service, granted a list of service keys, sends one document
-- of services (key, display name, levels, permissions). A new key is accepted with
-- its levels and permissions, one history line each naming the declaring client
-- and one declaration row; the same document again changes nothing but the time of
-- the last declaration; a document naming a key the caller was not granted is
-- refused whole; two clients may declare the same key, each adding its own
-- permissions; a malformed document is refused with nothing written; a refused
-- line anywhere in the document leaves the lines before it unwritten; a later
-- document that leaves a permission out leaves it in place, and one that marks
-- it retired retires it; an empty list writes nothing.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_declaration.sql

-- Declares a document as a client granted the listed keys and returns the answer.
-- A refusal raised after a write (the structured error as an exception) is
-- returned as the structured error, so a test reads both the same way.
CREATE OR REPLACE FUNCTION pg_temp.declare(p_actor text, p_allowed jsonb, p_section jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    BEGIN
        CALL rolebyte.service_declare(jsonb_build_object(
            'actor', p_actor, 'allowed', p_allowed, 'section', p_section), v);
    EXCEPTION
        WHEN sqlstate 'P0001' THEN
            v := sqlerrm::jsonb;
    END;
    RETURN v;
END $$;

-- What the register holds, as one comparable text: the services, levels,
-- permissions, history lines and declaration rows (the times of a declaration
-- row included).
CREATE OR REPLACE FUNCTION pg_temp.fingerprint() RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.service t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.role_definition t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.service_permission t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.event t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.service_declaration t)))
$$;

-- The document must be refused with exactly this code, name this text, and change nothing.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_allowed jsonb, p_section jsonb, p_code text, p_names text, p_why text)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text := pg_temp.fingerprint();
BEGIN
    v := pg_temp.declare('svc:declare-test', p_allowed, p_section);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    IF p_names IS NOT NULL AND position(p_names IN coalesce(v->>'message', '')) = 0 THEN
        RAISE EXCEPTION '% was refused but the message does not name %: %', p_why, p_names, v;
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
END $$;

DO $$
DECLARE
    v        jsonb;
    v_doc    jsonb;
    v_events int;
    v_first  timestamptz;
    v_last   timestamptz;
    v_fp     text;
BEGIN
    -- 1. A new key with two levels and two permissions is accepted and everything exists.
    v_doc := '{"services":[{"key":"decl-a","displayName":"Declared A",
        "roles":[{"group":"decl-a","level":"read"},{"group":"decl-a","level":"write","description":"Change things"}],
        "permissions":[
          {"feature":"item","act":"view","description":"See an item","class":"ordinary","plane":"object",
           "labels":{"lv":"Skatīt ierakstu"}},
          {"feature":"item","act":"manage","description":"Manage items","class":"tenantConfiguration","plane":"object"}]}]}'::jsonb;
    v := pg_temp.declare('svc:declare-test', '["decl-a"]'::jsonb, v_doc);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'a granted new key should be accepted: %', v;
    END IF;
    IF v->'data'->'services'->0->>'status' IS DISTINCT FROM 'added'
       OR (SELECT count(*) FROM jsonb_array_elements(v->'data'->'roles') e WHERE e->>'status' = 'added') <> 2
       OR (SELECT count(*) FROM jsonb_array_elements(v->'data'->'permissions') e WHERE e->>'status' = 'added') <> 2 THEN
        RAISE EXCEPTION 'the report should say one service, two levels and two permissions added: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'decl-a' AND display_name = 'Declared A')
       OR (SELECT count(*) FROM rolebyte.role_definition WHERE service_key = 'decl-a') <> 2
       OR (SELECT count(*) FROM rolebyte.service_permission WHERE service_key = 'decl-a') <> 2 THEN
        RAISE EXCEPTION 'the service, its two levels and its two permissions should exist';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE actor = 'svc:declare-test'
            AND kind IN ('serviceRegistered', 'roleDefined', 'permissionDeclared')) < 5
       OR EXISTS (SELECT 1 FROM rolebyte.event WHERE payload->>'service' = 'decl-a' AND actor <> 'svc:declare-test') THEN
        RAISE EXCEPTION 'every history line of the declaration should name the declaring client';
    END IF;
    IF (SELECT count(*) FROM rolebyte.service_declaration WHERE service_key = 'decl-a' AND declared_by = 'svc:declare-test') <> 1 THEN
        RAISE EXCEPTION 'exactly one declaration row should exist for the key and the client';
    END IF;

    -- 2. The same document again: every line unchanged, no new event, the first time kept, the last moved.
    SELECT first_declared_at, last_declared_at INTO v_first, v_last
      FROM rolebyte.service_declaration WHERE service_key = 'decl-a' AND declared_by = 'svc:declare-test';
    SELECT count(*) INTO v_events FROM rolebyte.event;
    PERFORM pg_sleep(0.05);
    v := pg_temp.declare('svc:declare-test', '["decl-a"]'::jsonb, v_doc);
    IF v->>'result' IS DISTINCT FROM 'success'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements((v->'data'->'services') || (v->'data'->'roles') || (v->'data'->'permissions')) e
                   WHERE e->>'status' IS DISTINCT FROM 'unchanged') THEN
        RAISE EXCEPTION 'the same document again should report every line unchanged: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.event) <> v_events THEN
        RAISE EXCEPTION 'the same document again should add no history line';
    END IF;
    IF (SELECT count(*) FROM rolebyte.service_declaration WHERE service_key = 'decl-a') <> 1
       OR (SELECT first_declared_at FROM rolebyte.service_declaration
            WHERE service_key = 'decl-a' AND declared_by = 'svc:declare-test') IS DISTINCT FROM v_first THEN
        RAISE EXCEPTION 'the first declaration time should be kept';
    END IF;
    IF (SELECT last_declared_at FROM rolebyte.service_declaration
         WHERE service_key = 'decl-a' AND declared_by = 'svc:declare-test') IS NOT DISTINCT FROM v_last
       OR (SELECT last_declared_at FROM rolebyte.service_declaration
            WHERE service_key = 'decl-a' AND declared_by = 'svc:declare-test') < v_last THEN
        RAISE EXCEPTION 'the last declaration time should move later';
    END IF;

    -- 3. One granted key and one not: refused as forbidden, naming the key, and nothing is written.
    PERFORM pg_temp.refused('["decl-b"]'::jsonb,
        '{"services":[{"key":"decl-b","displayName":"B","permissions":[{"feature":"item","act":"view","class":"ordinary","plane":"object"}]},
                      {"key":"decl-other","displayName":"Other"}]}'::jsonb,
        'membership:forbidden', 'decl-other', 'a document with a key the caller was not granted');
    PERFORM pg_temp.refused('[]'::jsonb, v_doc, 'membership:forbidden', 'decl-a', 'a caller granted nothing');
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key IN ('decl-b', 'decl-other')) THEN
        RAISE EXCEPTION 'the granted key before the refused one must not have been written';
    END IF;

    -- 5. Two clients granted the same key each add their own permissions; both stay.
    v := pg_temp.declare('svc:declare-first', '["decl-c"]'::jsonb,
        '{"services":[{"key":"decl-c","displayName":"C","permissions":[
            {"feature":"item","act":"view","class":"ordinary","plane":"object"}]}]}'::jsonb);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'the first client should be accepted: %', v;
    END IF;
    v_fp := (SELECT string_agg(t::text, ',' ORDER BY t::text) FROM rolebyte.service_permission t WHERE service_key = 'decl-c');
    v := pg_temp.declare('svc:declare-second', '["decl-c"]'::jsonb,
        '{"services":[{"key":"decl-c","displayName":"C","permissions":[
            {"feature":"item","act":"edit","class":"ordinary","plane":"object"}]}]}'::jsonb);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'the second client should be accepted: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.service_permission WHERE service_key = 'decl-c'
            AND act IN ('view', 'edit')) <> 2
       OR NOT EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key = 'decl-c' AND act = 'view' AND retired_at IS NULL) THEN
        RAISE EXCEPTION 'the key should hold the permissions of both clients';
    END IF;
    IF (SELECT count(*) FROM rolebyte.service_declaration WHERE service_key = 'decl-c'
            AND declared_by IN ('svc:declare-first', 'svc:declare-second')) <> 2 THEN
        RAISE EXCEPTION 'each client should have its own declaration row';
    END IF;
    IF position((SELECT string_agg(t::text, ',' ORDER BY t::text)
                   FROM rolebyte.service_permission t WHERE service_key = 'decl-c' AND act = 'view') IN v_fp) = 0 THEN
        RAISE EXCEPTION 'the second client''s document should leave the first client''s permission as it was';
    END IF;

    -- 10. Each malformed shape is refused as a bad document, with nothing written.
    PERFORM pg_temp.refused('["decl-d"]'::jsonb, '[]'::jsonb, 'membership:config_bad_document', NULL,
        'a section that is not an object');
    PERFORM pg_temp.refused('["decl-d"]'::jsonb, '"services"'::jsonb, 'membership:config_bad_document', NULL,
        'a section that is a string');
    PERFORM pg_temp.refused('["decl-d"]'::jsonb, '{"services":{"key":"decl-d"}}'::jsonb, 'membership:config_bad_document', NULL,
        'services that is not a list');
    PERFORM pg_temp.refused('["decl-d"]'::jsonb, '{"services":[{"displayName":"No key"}]}'::jsonb,
        'membership:config_bad_document', 'key', 'an entry with no key');
    PERFORM pg_temp.refused('["decl-d"]'::jsonb, '{"services":[{"key":"decl-d","roles":{"group":"decl-d","level":"read"}}]}'::jsonb,
        'membership:config_bad_document', 'decl-d', 'roles that is not a list');
    PERFORM pg_temp.refused('["decl-d"]'::jsonb, '{"services":[{"key":"decl-d","permissions":"all"}]}'::jsonb,
        'membership:config_bad_document', 'decl-d', 'permissions that is not a list');

    -- 11. A member the register does not know: at the top, in a service entry, in a role entry.
    PERFORM pg_temp.refused('["decl-d"]'::jsonb, '{"services":[{"key":"decl-d"}],"identities":[]}'::jsonb,
        'membership:config_bad_document', 'identities', 'an unknown member at the top');
    PERFORM pg_temp.refused('["decl-d"]'::jsonb, '{"services":[{"key":"decl-d","modules":["x"]}]}'::jsonb,
        'membership:config_bad_document', 'modules', 'an unknown member in a service entry');
    PERFORM pg_temp.refused('["decl-d"]'::jsonb,
        '{"services":[{"key":"decl-d","roles":[{"group":"decl-d","level":"read","rank":3}]}]}'::jsonb,
        'membership:config_bad_document', 'rank', 'an unknown member in a role entry');
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'decl-d') THEN
        RAISE EXCEPTION 'no malformed document may have written its service';
    END IF;

    -- 12. A valid entry, then a permission whose class differs from the registered one:
    -- refused, and the valid entry before it is not written.
    PERFORM pg_temp.refused('["decl-e", "decl-a"]'::jsonb,
        '{"services":[{"key":"decl-e","displayName":"E","permissions":[
            {"feature":"item","act":"view","class":"ordinary","plane":"object"}]},
          {"key":"decl-a","permissions":[
            {"feature":"item","act":"manage","class":"ordinary","plane":"object"}]}]}'::jsonb,
        'membership:config_key_conflict', 'decl-a/item:manage', 'a permission declared in another class');
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'decl-e')
       OR EXISTS (SELECT 1 FROM rolebyte.service_declaration WHERE service_key = 'decl-e') THEN
        RAISE EXCEPTION 'the valid entry before the refused one must not be written';
    END IF;

    -- 13. A later document that leaves a permission out leaves it in place and not retired.
    v := pg_temp.declare('svc:declare-test', '["decl-a"]'::jsonb,
        '{"services":[{"key":"decl-a","displayName":"Declared A","permissions":[
            {"feature":"item","act":"view","description":"See an item","class":"ordinary","plane":"object",
             "labels":{"lv":"Skatīt ierakstu"}}]}]}'::jsonb);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'a document with fewer permissions should be accepted: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.service_permission
                    WHERE service_key = 'decl-a' AND feature_key = 'item' AND act = 'manage' AND retired_at IS NULL) THEN
        RAISE EXCEPTION 'a permission left out of a later document should stay, and not be retired';
    END IF;

    -- 14. A later document marking it retired: changed, retired, and still listed.
    v := pg_temp.declare('svc:declare-test', '["decl-a"]'::jsonb,
        '{"services":[{"key":"decl-a","permissions":[
            {"feature":"item","act":"manage","class":"tenantConfiguration","plane":"object","retired":true}]}]}'::jsonb);
    IF v->>'result' IS DISTINCT FROM 'success'
       OR (SELECT count(*) FROM jsonb_array_elements(v->'data'->'permissions') e WHERE e->>'status' = 'changed') <> 1 THEN
        RAISE EXCEPTION 'retiring a permission should report one line changed: %', v;
    END IF;
    IF (SELECT retired_at FROM rolebyte.service_permission
         WHERE service_key = 'decl-a' AND feature_key = 'item' AND act = 'manage') IS NULL THEN
        RAISE EXCEPTION 'the permission should be retired';
    END IF;
    IF (SELECT count(*) FROM rolebyte.service_permission WHERE service_key = 'decl-a') <> 2 THEN
        RAISE EXCEPTION 'a retired permission stays listed';
    END IF;

    -- 15. An empty list is accepted, writes nothing and answers an empty report.
    v_fp := pg_temp.fingerprint();
    v := pg_temp.declare('svc:declare-test', '[]'::jsonb, '{"services":[]}'::jsonb);
    IF v->>'result' IS DISTINCT FROM 'success'
       OR jsonb_array_length(v->'data'->'services') <> 0
       OR jsonb_array_length(v->'data'->'roles') <> 0
       OR jsonb_array_length(v->'data'->'permissions') <> 0 THEN
        RAISE EXCEPTION 'an empty list should answer an empty report: %', v;
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'an empty list should write nothing';
    END IF;

    -- A caller that is not a service, and a malformed list of granted keys, are refused.
    v_doc := '{"services":[{"key":"decl-a"}]}'::jsonb;
    v_fp := pg_temp.fingerprint();
    v := pg_temp.declare('sub:someone', '["decl-a"]'::jsonb, v_doc);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION 'a person as the actor should be refused invalid: %', v;
    END IF;
    v := pg_temp.declare(NULL, '["decl-a"]'::jsonb, v_doc);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION 'no actor should be refused invalid: %', v;
    END IF;
    v := pg_temp.declare('svc:', '["decl-a"]'::jsonb, v_doc);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION 'an empty service subject should be refused invalid: %', v;
    END IF;
    v := pg_temp.declare('svc:declare-test', '"decl-a"'::jsonb, v_doc);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION 'granted keys that are not a list should be refused invalid: %', v;
    END IF;
    v := pg_temp.declare('svc:declare-test', NULL, v_doc);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION 'no granted keys should be refused invalid: %', v;
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'a refused caller should write nothing';
    END IF;

END $$;

-- A document of one service entry with the given roles.
CREATE OR REPLACE FUNCTION pg_temp.doc(p_key text, p_roles jsonb) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_build_object('services', jsonb_build_array(
        jsonb_build_object('key', p_key, 'displayName', p_key, 'roles', p_roles)))
$$;

-- One role entry.
CREATE OR REPLACE FUNCTION pg_temp.role(p_group jsonb, p_level jsonb) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_build_array(jsonb_build_object('group', p_group, 'level', p_level))
$$;

-- The document must be accepted, and its answer must carry no refused line.
CREATE OR REPLACE FUNCTION pg_temp.accepted(p_allowed jsonb, p_section jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.declare('svc:declare-test', p_allowed, p_section);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% should be accepted: %', p_why, left(v::text, 300);
    END IF;
    RETURN v;
END $$;

-- The document must be refused with this code, and the message must not contain
-- the text that was sent (a malformed key, group or level is never repeated).
CREATE OR REPLACE FUNCTION pg_temp.refused_silently(p_allowed jsonb, p_section jsonb, p_code text, p_absent text, p_why text)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text := pg_temp.fingerprint();
BEGIN
    v := pg_temp.declare('svc:declare-test', p_allowed, p_section);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, left(v::text, 300);
    END IF;
    IF position(p_absent IN v::text) > 0 THEN
        RAISE EXCEPTION '% was refused but the answer repeats what was sent: %', p_why, left(v::text, 300);
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
END $$;

DO $$
DECLARE
    v      jsonb;
    v_sfx  text := substr(md5(clock_timestamp()::text), 1, 8);
    v_k    text;
    v_fp   text;
    v_doc  jsonb;
    v_n    int;
    v_bad  text;
BEGIN
    -- 22. A level or a group that is not one lower-case word is refused as a bad
    -- document naming the service and the member, never repeating the value, and
    -- nothing is written. Each of these would otherwise be rendered into a token.
    v_k := 'shape-' || v_sfx;
    FOREACH v_bad IN ARRAY ARRAY['read membership:admin', 'read' || chr(9) || 'write', 'read:write', 'read/write', 'Read', 'read write', 'read' || chr(10)] LOOP
        PERFORM pg_temp.refused_silently(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_k), to_jsonb(v_bad))),
            'membership:config_bad_document', v_bad, format('a level %L', v_bad));
        PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_k), to_jsonb(v_bad))),
            'membership:config_bad_document', 'service ' || v_k || ' has a level', format('a level %L names service and member', v_bad));
        PERFORM pg_temp.refused_silently(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_bad), to_jsonb('read'::text))),
            'membership:config_bad_document', v_bad, format('a group %L', v_bad));
        PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_bad), to_jsonb('read'::text))),
            'membership:config_bad_document', 'service ' || v_k || ' has a group', format('a group %L names service and member', v_bad));
    END LOOP;
    -- a name that begins with a digit or a hyphen, an empty one, and a level that is a number
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_k), to_jsonb('1read'::text))),
        'membership:config_bad_document', 'service ' || v_k || ' has a level', 'a level that begins with a digit');
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_k), to_jsonb(''::text))),
        'membership:config_bad_document', 'service ' || v_k || ' has a level', 'an empty level');
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_k), to_jsonb(5))),
        'membership:config_bad_document', 'service ' || v_k || ' has a level', 'a level that is a number');
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(5), to_jsonb('read'::text))),
        'membership:config_bad_document', 'service ' || v_k || ' has a group', 'a group that is a number');
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = v_k) THEN
        RAISE EXCEPTION 'no refused document may have written its service';
    END IF;

    -- 23. Boundaries of a level and of a description: 64 and 256 characters are
    -- accepted, 65 and 257 refused. Characters are counted, not bytes: the 256
    -- characters of the description are two bytes each.
    v_k := 'bound-' || v_sfx;
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_k), to_jsonb('a' || repeat('b', 64)))),
        'membership:config_bad_document', 'service ' || v_k || ' has a level', 'a level of 65 characters');
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb('a' || repeat('b', 64)), to_jsonb('read'::text))),
        'membership:config_bad_document', 'service ' || v_k || ' has a group', 'a group of 65 characters');
    PERFORM pg_temp.accepted(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb(v_k), to_jsonb('a' || repeat('b', 63)))),
        'a level of 64 characters');
    IF NOT EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE service_key = v_k AND role_level = 'a' || repeat('b', 63)) THEN
        RAISE EXCEPTION 'the level of 64 characters should exist';
    END IF;
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]),
        pg_temp.doc(v_k, jsonb_build_array(jsonb_build_object('group', v_k, 'level', 'write', 'description', repeat('ā', 257)))),
        'membership:config_bad_document', 'service ' || v_k || ' has a description', 'a role description of 257 characters');
    PERFORM pg_temp.accepted(to_jsonb(ARRAY[v_k]),
        pg_temp.doc(v_k, jsonb_build_array(jsonb_build_object('group', v_k, 'level', 'write', 'description', repeat('ā', 256)))),
        'a role description of 256 two-byte characters');
    IF (SELECT char_length(description) FROM rolebyte.role_definition WHERE service_key = v_k AND role_level = 'write') <> 256 THEN
        RAISE EXCEPTION 'the description of 256 characters should be stored whole';
    END IF;
    -- a display name of 256 and 257
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k || '-n']),
        jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_k || '-n', 'displayName', repeat('ā', 257)))),
        'membership:config_bad_document', 'the display name of service ' || v_k || '-n', 'a display name of 257 characters');
    PERFORM pg_temp.accepted(to_jsonb(ARRAY[v_k || '-n']),
        jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_k || '-n', 'displayName', repeat('ā', 256)))),
        'a display name of 256 characters');
    -- a permission's description and a label's value
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]),
        jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_k, 'permissions', jsonb_build_array(
            jsonb_build_object('feature', 'item', 'act', 'view', 'class', 'ordinary', 'plane', 'object', 'description', repeat('ā', 257)))))),
        'membership:config_bad_document', 'a permission of service ' || v_k || ' has a description', 'a permission description of 257 characters');
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]),
        jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_k, 'permissions', jsonb_build_array(
            jsonb_build_object('feature', 'item', 'act', 'view', 'class', 'ordinary', 'plane', 'object',
                               'labels', jsonb_build_object('lv', repeat('ā', 257))))))),
        'membership:config_bad_document', 'a permission of service ' || v_k || ' has a label', 'a label of 257 characters');
    PERFORM pg_temp.accepted(to_jsonb(ARRAY[v_k]),
        jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_k, 'permissions', jsonb_build_array(
            jsonb_build_object('feature', 'item', 'act', 'view', 'class', 'ordinary', 'plane', 'object',
                               'description', repeat('ā', 256), 'labels', jsonb_build_object('lv', repeat('ā', 256))))))),
        'a permission description and a label of 256 characters');

    -- 24. A group belongs to one service key.
    -- The group `membership` is the register's own, even where nothing conflicts.
    v_k := 'acme-' || v_sfx;
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb('membership'::text), to_jsonb('reader'::text))),
        'membership:config_key_conflict', 'service ' || v_k || ' may not declare group membership', 'the group membership under another key');
    -- a group another key already defined (decl-a defined the group decl-a above)
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), pg_temp.doc(v_k, pg_temp.role(to_jsonb('decl-a'::text), to_jsonb('read'::text))),
        'membership:config_key_conflict', 'service ' || v_k || ' may not declare group decl-a', 'a group defined under another key');
    -- two keys of one document naming one group
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k || '-1', v_k || '-2']),
        jsonb_build_object('services', jsonb_build_array(
            jsonb_build_object('key', v_k || '-1', 'roles', pg_temp.role(to_jsonb('shared-' || v_sfx), to_jsonb('read'::text))),
            jsonb_build_object('key', v_k || '-2', 'roles', pg_temp.role(to_jsonb('shared-' || v_sfx), to_jsonb('write'::text))))),
        'membership:config_key_conflict', 'service ' || v_k || '-2 may not declare group shared-' || v_sfx, 'two keys naming one group');
    -- a group of its own is accepted, and the repeat changes nothing
    v_doc := pg_temp.doc(v_k, pg_temp.role(to_jsonb('own-' || v_sfx), to_jsonb('read'::text)));
    PERFORM pg_temp.accepted(to_jsonb(ARRAY[v_k]), v_doc, 'a group of its own');
    v_fp := pg_temp.fingerprint();
    v := pg_temp.accepted(to_jsonb(ARRAY[v_k]), v_doc, 'the repeat of a group of its own');
    IF EXISTS (SELECT 1 FROM jsonb_array_elements((v->'data'->'services') || (v->'data'->'roles')) e WHERE e->>'status' IS DISTINCT FROM 'unchanged') THEN
        RAISE EXCEPTION 'the repeat of a group of its own should report every line unchanged: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.role_definition WHERE role_group = 'own-' || v_sfx) <> 1 THEN
        RAISE EXCEPTION 'the group of its own should hold exactly one level';
    END IF;

    -- 25. Limits of one call.
    -- 50 roles accepted, 51 refused
    v_k := 'roles-' || v_sfx;
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]),
        pg_temp.doc(v_k, (SELECT jsonb_agg(jsonb_build_object('group', v_k, 'level', 'l' || i)) FROM generate_series(1, 51) i)),
        'membership:config_bad_document', 'service ' || v_k || ' declares at most 50 roles', '51 roles');
    PERFORM pg_temp.accepted(to_jsonb(ARRAY[v_k]),
        pg_temp.doc(v_k, (SELECT jsonb_agg(jsonb_build_object('group', v_k, 'level', 'l' || i)) FROM generate_series(1, 50) i)),
        '50 roles');
    IF (SELECT count(*) FROM rolebyte.role_definition WHERE service_key = v_k) <> 50 THEN
        RAISE EXCEPTION '50 roles should exist';
    END IF;
    -- 500 permissions accepted, 501 refused
    v_k := 'perms-' || v_sfx;
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]),
        jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_k, 'permissions',
            (SELECT jsonb_agg(jsonb_build_object('feature', 'f' || i, 'act', 'view', 'class', 'ordinary', 'plane', 'object'))
               FROM generate_series(1, 501) i)))),
        'membership:config_bad_document', 'service ' || v_k || ' declares at most 500 permissions', '501 permissions');
    PERFORM pg_temp.accepted(to_jsonb(ARRAY[v_k]),
        jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_k, 'permissions',
            (SELECT jsonb_agg(jsonb_build_object('feature', 'f' || i, 'act', 'view', 'class', 'ordinary', 'plane', 'object'))
               FROM generate_series(1, 500) i)))),
        '500 permissions');
    IF (SELECT count(*) FROM rolebyte.service_permission WHERE service_key = v_k) <> 500 THEN
        RAISE EXCEPTION '500 permissions should exist';
    END IF;
    -- 50 services accepted, 51 refused
    PERFORM pg_temp.refused((SELECT jsonb_agg('svc-' || v_sfx || '-' || i) FROM generate_series(1, 51) i),
        jsonb_build_object('services', (SELECT jsonb_agg(jsonb_build_object('key', 'svc-' || v_sfx || '-' || i)) FROM generate_series(1, 51) i)),
        'membership:config_bad_document', 'at most 50 services', '51 services');
    PERFORM pg_temp.accepted((SELECT jsonb_agg('svc-' || v_sfx || '-' || i) FROM generate_series(1, 50) i),
        jsonb_build_object('services', (SELECT jsonb_agg(jsonb_build_object('key', 'svc-' || v_sfx || '-' || i)) FROM generate_series(1, 50) i)),
        '50 services');
    IF (SELECT count(*) FROM rolebyte.service WHERE key LIKE 'svc-' || v_sfx || '-%') <> 50 THEN
        RAISE EXCEPTION '50 services should exist';
    END IF;
    -- a section just over 262144 bytes: labels of 256 characters, one more at a time
    v_k := 'size-' || v_sfx;
    v_n := 900;
    LOOP
        v_doc := jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_k, 'permissions', jsonb_build_array(
            jsonb_build_object('feature', 'item', 'act', 'view', 'class', 'ordinary', 'plane', 'object',
                'labels', (SELECT jsonb_object_agg('k' || i, repeat('x', 256)) FROM generate_series(1, v_n) i))))));
        EXIT WHEN octet_length(v_doc::text) > 262144;
        v_n := v_n + 1;
    END LOOP;
    IF octet_length(v_doc::text) > 262144 + 400 THEN
        RAISE EXCEPTION 'the document should be just over the limit, not % bytes', octet_length(v_doc::text);
    END IF;
    PERFORM pg_temp.refused(to_jsonb(ARRAY[v_k]), v_doc, 'membership:config_bad_document', '262144 bytes', 'a section just over 262144 bytes');

    -- 26. A malformed service key is refused without the key in the answer.
    FOREACH v_bad IN ARRAY ARRAY['a' || repeat('b', 64), 'bad key ' || v_sfx, 'bad' || chr(7) || 'key' || v_sfx, 'Upper' || v_sfx] LOOP
        PERFORM pg_temp.refused_silently(to_jsonb(ARRAY[v_bad]), jsonb_build_object('services', jsonb_build_array(jsonb_build_object('key', v_bad))),
            'membership:config_bad_document', v_bad, format('a service key of %s characters', char_length(v_bad)));
    END LOOP;

    -- The deployment's own act of defining a role refuses the same shapes: a space,
    -- a tab, a colon or a slash in a group or a level.
    v_fp := pg_temp.fingerprint();
    FOREACH v_bad IN ARRAY ARRAY['a b', 'a' || chr(9) || 'b', 'a:b', 'a/b'] LOOP
        v := NULL;
        CALL rolebyte.role_define(jsonb_build_object('actor', 'op:test', 'service', 'decl-a', 'group', 'decl-a', 'level', v_bad), v);
        IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
            RAISE EXCEPTION 'role_define should refuse the level %: %', v_bad, v;
        END IF;
        v := NULL;
        CALL rolebyte.role_define(jsonb_build_object('actor', 'op:test', 'service', 'decl-a', 'group', v_bad, 'level', 'read'), v);
        IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
            RAISE EXCEPTION 'role_define should refuse the group %: %', v_bad, v;
        END IF;
    END LOOP;
    IF pg_temp.fingerprint() IS DISTINCT FROM v_fp THEN
        RAISE EXCEPTION 'a refused role_define should write nothing';
    END IF;

    RAISE NOTICE 'unit.rolebyte_declaration: all assertions passed';
END $$;
