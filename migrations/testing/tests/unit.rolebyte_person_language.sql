-- Unit test: a person's own language. One choice per person, kept on the person
-- rather than on any membership: set, read, changed, cleared, each change a line of
-- the register's history that belongs to no tenant, and a set that changes nothing
-- writing nothing. Only a language the app speaks is taken, or null; the member
-- must be there; only a person's key; only a person who is an active member of an
-- active tenant; a refusal writes nothing. Another person is never touched, and a
-- set holds the person's own lock to the end of its transaction, so two sets of one
-- person take turns.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_person_language.sql

-- Calls one register procedure and answers its whole answer, a refusal included —
-- one raised after a write as well, which is then undone with the call.
CREATE OR REPLACE FUNCTION pg_temp.call(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    RETURN v;
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RETURN SQLERRM::jsonb;
END $$;

-- The call must succeed; answers its data.
CREATE OR REPLACE FUNCTION pg_temp.ok(p_proc text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.call(p_proc, p_in);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN v->'data';
END $$;

-- Every person's stored language as it is stored: a row's physical place changes
-- with any write, even one that leaves every value as it was, so an unchanged
-- fingerprint means nothing was written.
CREATE OR REPLACE FUNCTION pg_temp.rows() RETURNS text
LANGUAGE sql AS $$
    SELECT COALESCE(string_agg(subject_key || ':' || ctid::text || ':' || COALESCE(language, '-'), ','
                               ORDER BY subject_key), '')
      FROM rolebyte.person_setting;
$$;

-- Every line of the history so far, by id.
CREATE OR REPLACE FUNCTION pg_temp.lines() RETURNS text[]
LANGUAGE sql AS $$
    SELECT COALESCE(array_agg(id), '{}') FROM rolebyte.event;
$$;

-- The lines written since `p_before`.
CREATE OR REPLACE FUNCTION pg_temp.after(p_before text[]) RETURNS SETOF rolebyte.event
LANGUAGE sql AS $$
    SELECT * FROM rolebyte.event WHERE NOT (id = ANY (p_before));
$$;

-- The call must be refused with the code, and write nothing at all.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_rows  text   := pg_temp.rows();
    v_lines text[] := pg_temp.lines();
    v       jsonb;
BEGIN
    v := pg_temp.call(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% is refused %: %', p_why, p_code, v;
    END IF;
    IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
        RAISE EXCEPTION '% was refused and still wrote a language', p_why;
    END IF;
    IF (SELECT count(*) FROM pg_temp.after(v_lines)) IS DISTINCT FROM 0::bigint THEN
        RAISE EXCEPTION '% was refused and still wrote a line', p_why;
    END IF;
END $$;

-- The one line an act wrote: a person's language line, belonging to no tenant and
-- no membership, naming who acted, whose language it is, what it became and what
-- it was — and nothing else.
CREATE OR REPLACE FUNCTION pg_temp.one_line(p_before text[], p_actor text, p_subject text,
                                            p_to jsonb, p_from jsonb, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_n bigint;
    e   rolebyte.event;
BEGIN
    SELECT count(*) INTO v_n FROM pg_temp.after(p_before);
    IF v_n IS DISTINCT FROM 1::bigint THEN
        RAISE EXCEPTION '%: one line, found %', p_why, v_n;
    END IF;
    SELECT * INTO e FROM pg_temp.after(p_before);
    IF e.kind IS DISTINCT FROM 'personLanguageSet' THEN
        RAISE EXCEPTION '%: the line is a personLanguageSet, not %', p_why, e.kind;
    END IF;
    IF e.tenant_id IS NOT NULL THEN
        RAISE EXCEPTION '%: the line belongs to no tenant, found %', p_why, e.tenant_id;
    END IF;
    IF e.user_id IS NOT NULL THEN
        RAISE EXCEPTION '%: the line is about no membership, found %', p_why, e.user_id;
    END IF;
    IF e.actor IS DISTINCT FROM p_actor THEN
        RAISE EXCEPTION '%: the line names who acted, %, found %', p_why, p_actor, e.actor;
    END IF;
    IF e.payload->'subjectKey' IS DISTINCT FROM to_jsonb(p_subject) THEN
        RAISE EXCEPTION '%: the line names whose language it is: %', p_why, e.payload;
    END IF;
    IF e.payload->'language' IS DISTINCT FROM p_to THEN
        RAISE EXCEPTION '%: the language became %: %', p_why, p_to, e.payload;
    END IF;
    IF e.payload->'from' IS DISTINCT FROM p_from THEN
        RAISE EXCEPTION '%: the language was %: %', p_why, p_from, e.payload;
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(e.payload)) IS DISTINCT FROM 3::bigint THEN
        RAISE EXCEPTION '%: the line carries subjectKey, language and from, nothing else: %', p_why, e.payload;
    END IF;
END $$;

-- A person's language as the read answers it: `language` is always there, a
-- language or JSON null.
CREATE OR REPLACE FUNCTION pg_temp.language_of(p_subject text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.ok('person_language_get', jsonb_build_object('subjectKey', p_subject), 'read a language');
BEGIN
    IF NOT (v ? 'language') THEN
        RAISE EXCEPTION 'the read always answers language: %', v;
    END IF;
    RETURN v->'language';
END $$;

-- The advisory locks this session holds.
CREATE OR REPLACE FUNCTION pg_temp.advisory_locks() RETURNS bigint
LANGUAGE sql AS $$
    SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted;
$$;

DO $$
DECLARE
    v_anna    text := 'sub:' || util.generate_ulid();
    v_bela    text := 'sub:' || util.generate_ulid();
    v_cilda   text := 'sub:' || util.generate_ulid();
    v_ilze    text := 'sub:' || util.generate_ulid();
    v_maris   text := 'sub:' || util.generate_ulid();
    v_peteris text := 'sub:' || util.generate_ulid();
    v_rasma   text := 'sub:' || util.generate_ulid();
    v_toms    text := 'sub:' || util.generate_ulid();
    v_juris   text := 'sub:' || util.generate_ulid();
    v_vilis   text := 'sub:' || util.generate_ulid();
    v_edge    text := 'svc:language-test-edge';
    v_ta      text;
    v_tb      text;
    v_tc      text;
    v_ilze_b  text;
    v_toms_a  text;
    v_subject text;
    v_tenant  text;
    v_before  text[];
    v_rows    text;
    v_locks   bigint;
    v         jsonb;
BEGIN
    -- ---------------------------------------------------------------- fixture
    -- Ilze is an active member of A and was revoked in B; Māris, Pēteris and Rasma
    -- are active in A. Toms's access in A ended; Juris was invited to A and never
    -- signed in; Cilda administers C, which is suspended; Vilis is nobody's member.
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Language A',
        'administrator', jsonb_build_object('subjectKey', v_anna, 'displayName', 'Anna Ozola')), 'open A');
    v_ta := v->'tenant'->>'id';
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Language B',
        'administrator', jsonb_build_object('subjectKey', v_bela, 'displayName', 'Bēla Liepa')), 'open B');
    v_tb := v->'tenant'->>'id';
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Language C',
        'administrator', jsonb_build_object('subjectKey', v_cilda, 'displayName', 'Cilda Egle')), 'open C');
    v_tc := v->'tenant'->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_anna), 'Anna signs in');
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_bela), 'Bēla signs in');
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_cilda), 'Cilda signs in');
    UPDATE rolebyte.tenant SET status = 'suspended' WHERE id = v_tc;

    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_ilze,
        'displayName', 'Ilze Krūmiņa'), 'invite Ilze to A');
    v_ilze_b := pg_temp.ok('user_invite', jsonb_build_object('actor', v_bela, 'tenantId', v_tb, 'subjectKey', v_ilze,
        'displayName', 'Ilze Krūmiņa'), 'invite Ilze to B')->>'id';
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_maris,
        'displayName', 'Māris Kalns'), 'invite Māris');
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_peteris,
        'displayName', 'Pēteris Ozols'), 'invite Pēteris');
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_rasma,
        'displayName', 'Rasma Liepa'), 'invite Rasma');
    v_toms_a := pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_toms,
        'displayName', 'Toms Egle'), 'invite Toms')->>'id';
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_juris,
        'displayName', 'Juris Kalns'), 'invite Juris');
    FOREACH v_subject IN ARRAY ARRAY[v_ilze, v_maris, v_peteris, v_rasma, v_toms] LOOP
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_subject), 'a sign-in');
    END LOOP;
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_bela, 'tenantId', v_tb, 'userId', v_ilze_b), 'Ilze leaves B');
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'userId', v_toms_a), 'Toms leaves A');

    -- ------------------------------------- (0) the table holds a person's key only
    BEGIN
        INSERT INTO rolebyte.person_setting (subject_key, language) VALUES (v_edge, 'en');
        RAISE EXCEPTION 'a service account''s key was stored as a person''s';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        INSERT INTO rolebyte.person_setting (subject_key, language) VALUES ('sub:not-a-person-id', 'en');
        RAISE EXCEPTION 'a person key whose value is not a platform subject was stored';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        INSERT INTO rolebyte.person_setting (subject_key, language) VALUES ('SUB:' || util.generate_ulid(), 'en');
        RAISE EXCEPTION 'a key whose tag differs only in case was stored';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    -- ... and every person's key is, whatever language it is given: which languages
    -- the app speaks is the procedures' to say, so the table names none.
    v_subject := 'sub:' || util.generate_ulid();
    INSERT INTO rolebyte.person_setting (subject_key, language) VALUES (v_subject, 'de');
    DELETE FROM rolebyte.person_setting WHERE subject_key = v_subject;

    -- -------------------------------------- (1) nobody has chosen: the read is null
    IF pg_temp.language_of(v_ilze) IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'a person who never chose reads null: %', pg_temp.language_of(v_ilze);
    END IF;

    -- --------------- (2) clearing what was never chosen writes nothing and answers null
    v_rows := pg_temp.rows();
    v_before := pg_temp.lines();
    v := pg_temp.ok('person_language_set', jsonb_build_object('actor', v_maris, 'subjectKey', v_maris,
        'language', NULL), 'Māris clears nothing');
    IF v->'language' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'clearing answers null: %', v;
    END IF;
    IF pg_temp.rows() IS DISTINCT FROM v_rows OR (SELECT count(*) FROM pg_temp.after(v_before)) <> 0 THEN
        RAISE EXCEPTION 'clearing a language never chosen wrote something';
    END IF;

    -- ------------------------------------------------------------- (3) set, read
    v_before := pg_temp.lines();
    v := pg_temp.ok('person_language_set', jsonb_build_object('actor', v_maris, 'subjectKey', v_maris,
        'language', 'en'), 'Māris chooses English');
    IF v->'language' IS DISTINCT FROM '"en"'::jsonb THEN
        RAISE EXCEPTION 'a set answers the language: %', v;
    END IF;
    PERFORM pg_temp.one_line(v_before, v_maris, v_maris, '"en"', 'null', 'Māris chooses English');

    v_before := pg_temp.lines();
    v := pg_temp.ok('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', 'lv'), 'Ilze chooses Latvian');
    IF v->'language' IS DISTINCT FROM '"lv"'::jsonb THEN
        RAISE EXCEPTION 'a set answers the language: %', v;
    END IF;
    IF pg_temp.language_of(v_ilze) IS DISTINCT FROM '"lv"'::jsonb THEN
        RAISE EXCEPTION 'Ilze reads Latvian: %', pg_temp.language_of(v_ilze);
    END IF;
    PERFORM pg_temp.one_line(v_before, v_ilze, v_ilze, '"lv"', 'null', 'Ilze chooses Latvian');

    -- ------------------- (4) a change is one line, from what it was to what it became.
    -- Who acted and whose language it is are each kept, so a line written by
    -- somebody else for the person still says whose it is.
    v_before := pg_temp.lines();
    v := pg_temp.ok('person_language_set', jsonb_build_object('actor', 'op:test', 'subjectKey', v_ilze,
        'language', 'en'), 'Ilze''s language changed to English');
    IF v->'language' IS DISTINCT FROM '"en"'::jsonb OR pg_temp.language_of(v_ilze) IS DISTINCT FROM '"en"'::jsonb THEN
        RAISE EXCEPTION 'Ilze reads English: % / %', v, pg_temp.language_of(v_ilze);
    END IF;
    PERFORM pg_temp.one_line(v_before, 'op:test', v_ilze, '"en"', '"lv"', 'Ilze''s change to English');

    -- ------------------------------------------- (5) the same again writes nothing
    v_rows := pg_temp.rows();
    v_before := pg_temp.lines();
    v := pg_temp.ok('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', 'en'), 'Ilze chooses English again');
    IF v->'language' IS DISTINCT FROM '"en"'::jsonb THEN
        RAISE EXCEPTION 'the same again answers the language: %', v;
    END IF;
    IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
        RAISE EXCEPTION 'the same language again wrote the row';
    END IF;
    IF (SELECT count(*) FROM pg_temp.after(v_before)) IS DISTINCT FROM 0::bigint THEN
        RAISE EXCEPTION 'the same language again wrote a line';
    END IF;

    -- -------------------------------------------------- (6) refusals write nothing
    -- Ilze holds English throughout: every one of these would have moved it.
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', 'de'), 'membership:invalid', 'a language the app does not speak');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', ''), 'membership:invalid', 'an empty language');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', 'EN'), 'membership:invalid', 'the language held, in another case');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', 'LV'), 'membership:invalid', 'a language in another case');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', ' lv'), 'membership:invalid', 'a language with a space before it');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze),
        'membership:invalid', 'a call leaving the language out');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', 5), 'membership:invalid', 'a number');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', false), 'membership:invalid', 'a truth value');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', jsonb_build_array('lv')), 'membership:invalid', 'a list');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', jsonb_build_object('code', 'lv')), 'membership:invalid', 'an object');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('subjectKey', v_ilze, 'language', 'lv'),
        'membership:invalid', 'a call naming nobody who acted');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', ' ', 'subjectKey', v_ilze, 'language', 'lv'),
        'membership:invalid', 'a blank actor');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'language', 'lv'),
        'membership:invalid', 'a call naming no person');
    IF pg_temp.language_of(v_ilze) IS DISTINCT FROM '"en"'::jsonb THEN
        RAISE EXCEPTION 'after every refusal Ilze still reads English: %', pg_temp.language_of(v_ilze);
    END IF;

    -- ---------------------------------------------- (7) a person's key, and only that
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_edge, 'subjectKey', v_edge,
        'language', 'lv'), 'membership:invalid', 'a service account''s key');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', 'sub:not-a-person-id',
        'language', 'lv'), 'membership:invalid', 'a person key whose value is not a platform subject');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_ilze,
        'subjectKey', 'SUB:' || substr(v_ilze, 5), 'language', 'lv'), 'membership:invalid', 'a tag in another case');
    PERFORM pg_temp.refused('person_language_get', jsonb_build_object('subjectKey', v_edge),
        'membership:invalid', 'reading a service account''s language');
    PERFORM pg_temp.refused('person_language_get', jsonb_build_object('subjectKey', 'sub:not-a-person-id'),
        'membership:invalid', 'reading a key that is not a platform subject');
    PERFORM pg_temp.refused('person_language_get', '{}'::jsonb,
        'membership:invalid', 'reading nobody''s language');

    -- ------------------- (8) only an active member of an active tenant keeps one
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_vilis, 'subjectKey', v_vilis,
        'language', 'lv'), 'membership:notMember', 'a person nobody invited');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_toms, 'subjectKey', v_toms,
        'language', 'lv'), 'membership:notMember', 'a person revoked everywhere');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_juris, 'subjectKey', v_juris,
        'language', 'lv'), 'membership:notMember', 'a person invited and never signed in');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_cilda, 'subjectKey', v_cilda,
        'language', 'lv'), 'membership:notMember', 'a person only in a suspended tenant');
    PERFORM pg_temp.refused('person_language_set', jsonb_build_object('actor', v_toms, 'subjectKey', v_toms,
        'language', NULL), 'membership:notMember', 'a person revoked everywhere clearing');

    -- ------------------------------------------------ (9) cleared: a line to null
    v_before := pg_temp.lines();
    v := pg_temp.ok('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', NULL), 'Ilze clears her language');
    IF v->'language' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'clearing answers null: %', v;
    END IF;
    IF pg_temp.language_of(v_ilze) IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'Ilze reads null once cleared: %', pg_temp.language_of(v_ilze);
    END IF;
    PERFORM pg_temp.one_line(v_before, v_ilze, v_ilze, 'null', '"en"', 'Ilze clears her language');

    v_rows := pg_temp.rows();
    v_before := pg_temp.lines();
    PERFORM pg_temp.ok('person_language_set', jsonb_build_object('actor', v_ilze, 'subjectKey', v_ilze,
        'language', NULL), 'Ilze clears it again');
    IF pg_temp.rows() IS DISTINCT FROM v_rows OR (SELECT count(*) FROM pg_temp.after(v_before)) <> 0 THEN
        RAISE EXCEPTION 'clearing a cleared language wrote something';
    END IF;

    -- ----------------------------------------- (10) another person is never touched
    IF pg_temp.language_of(v_maris) IS DISTINCT FROM '"en"'::jsonb THEN
        RAISE EXCEPTION 'Māris still reads English after all of Ilze''s acts: %', pg_temp.language_of(v_maris);
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'personLanguageSet' AND payload->>'subjectKey' = v_maris)
       IS DISTINCT FROM 1::bigint THEN
        RAISE EXCEPTION 'Māris has exactly his one line';
    END IF;
    IF pg_temp.language_of(v_peteris) IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'Pēteris never chose: %', pg_temp.language_of(v_peteris);
    END IF;

    -- --------------------------------------- (11) the lines are in no tenant's history
    IF EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'personLanguageSet' AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'a language line belongs to a tenant';
    END IF;
    FOREACH v_tenant IN ARRAY ARRAY[v_ta, v_tb] LOOP
        v := pg_temp.ok('history', jsonb_build_object('tenantId', v_tenant, 'limit', '500'), 'a tenant''s history');
        IF jsonb_array_length(v->'events') IS NOT DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'the tenant''s history was read, and is not empty';
        END IF;
        IF EXISTS (SELECT 1 FROM jsonb_array_elements(v->'events') e WHERE e->>'kind' = 'personLanguageSet') THEN
            RAISE EXCEPTION 'a tenant''s history shows a person''s language: %', v;
        END IF;
    END LOOP;
    v := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'actor', v_ilze), 'Ilze''s story in A');
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(v->'events') e WHERE e->>'kind' = 'personLanguageSet') THEN
        RAISE EXCEPTION 'a person''s story in a tenant shows their language: %', v;
    END IF;

    -- --------------- (12) a set holds the person's own lock to the end of its transaction
    -- One lock per person: a second person's set takes another, and the same
    -- person's again takes none it does not already hold.
    v_locks := pg_temp.advisory_locks();
    PERFORM pg_temp.ok('person_language_set', jsonb_build_object('actor', v_peteris, 'subjectKey', v_peteris,
        'language', 'lv'), 'Pēteris chooses Latvian');
    IF pg_temp.advisory_locks() IS DISTINCT FROM v_locks + 1 THEN
        RAISE EXCEPTION 'a set holds its person''s lock until its transaction ends: % then %', v_locks, pg_temp.advisory_locks();
    END IF;
    PERFORM pg_temp.ok('person_language_set', jsonb_build_object('actor', v_rasma, 'subjectKey', v_rasma,
        'language', 'en'), 'Rasma chooses English');
    IF pg_temp.advisory_locks() IS DISTINCT FROM v_locks + 2 THEN
        RAISE EXCEPTION 'another person''s set holds a lock of its own: % then %', v_locks, pg_temp.advisory_locks();
    END IF;
    PERFORM pg_temp.ok('person_language_set', jsonb_build_object('actor', v_peteris, 'subjectKey', v_peteris,
        'language', 'en'), 'Pēteris changes to English');
    IF pg_temp.advisory_locks() IS DISTINCT FROM v_locks + 2 THEN
        RAISE EXCEPTION 'the same person''s set takes the same lock: % then %', v_locks, pg_temp.advisory_locks();
    END IF;

    RAISE NOTICE 'unit.rolebyte_person_language: all assertions passed';
END $$;
