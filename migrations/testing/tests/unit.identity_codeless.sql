-- Unit test: identity.upsert without a national identity code — a person who
-- signs in through their organisation's directory.
--
-- Such a login carries a name and the directory's identifiers, no national code.
-- It is resolved by its credential handle (`idp_sub`): a known handle lands on its
-- person, an unknown one creates a person with no code. Nothing else is matched
-- on, so a codeless person stays a separate person from a card person until a
-- deliberate link — which is not this procedure.
--
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL
-- them regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a
-- failed assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.identity_codeless.sql
--
-- Every code here is assembled from its parts at run time, so the file carries no
-- string that reads as somebody's personal code.

DO $$
DECLARE
    v            jsonb;
    v_dir_sub    text;                                            -- the codeless person
    v_card_sub   text;                                            -- a person keyed on a code
    v_third_sub  text;                                            -- a second codeless person
    v_late_sub   text;                                            -- the codeless person's later card login
    v_null_1     text;
    v_null_2     text;
    v_code       text := 'PNOLV-' || '000000' || '-' || '00051';   -- as a card certificate spells it
    v_stored     text := 'PNOLV-' || '00000000051';                -- the one stored spelling
    v_code_2     text := 'PNOLV-' || '000000' || '-' || '00052';   -- another person's code
    v_stored_2   text := 'PNOLV-' || '00000000052';
    v_bare       text := '000000' || '-' || '00051';               -- no country anywhere
    v_n          integer;
BEGIN
    -- (1) Codeless create: a login with no code and an unknown handle makes a new
    --     person — created true, a subject of the platform's shape, NO code on the
    --     row, exactly one credential, the profile as the login sent it.
    CALL identity.upsert(jsonb_build_object(
        'idp_sub', 'idp-unit-dir-1', 'login_method', 'upstream',
        'name', 'Directory Person', 'given_name', 'Directory', 'family_name', 'Person'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'a login without a code was refused: %', v;
    END IF;
    IF (v->'data'->>'created')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'the first codeless login should report created=true: %', v;
    END IF;
    v_dir_sub := v->'data'->>'internal_sub';
    IF v_dir_sub IS NULL OR v_dir_sub !~ '^[0-9A-HJKMNP-TV-Z]{26}$' THEN
        RAISE EXCEPTION 'the codeless person did not get a subject of the platform''s shape: %', v;
    END IF;
    IF (SELECT national_id FROM identity.person WHERE person_sub = v_dir_sub) IS NOT NULL THEN
        RAISE EXCEPTION 'a login that carried no code stored one: %',
            (SELECT national_id FROM identity.person WHERE person_sub = v_dir_sub);
    END IF;
    IF (SELECT name FROM identity.person WHERE person_sub = v_dir_sub) IS DISTINCT FROM 'Directory Person' THEN
        RAISE EXCEPTION 'the codeless person''s profile is not what the login sent: %',
            (SELECT name FROM identity.person WHERE person_sub = v_dir_sub);
    END IF;
    SELECT count(*) INTO v_n FROM identity.credential WHERE person_sub = v_dir_sub;
    IF v_n <> 1 THEN
        RAISE EXCEPTION 'the codeless login did not attach exactly one credential: % row(s)', v_n;
    END IF;
    IF (SELECT login_method FROM identity.credential WHERE idp_sub = 'idp-unit-dir-1') IS DISTINCT FROM 'upstream' THEN
        RAISE EXCEPTION 'the credential does not carry the login method it came from';
    END IF;

    -- (2) Codeless repeat login: the same handle lands on the SAME person, created
    --     false, still one person and one credential; the profile is refreshed
    --     from the login, as it is for every login; still no code.
    CALL identity.upsert(jsonb_build_object(
        'idp_sub', 'idp-unit-dir-1', 'login_method', 'upstream',
        'name', 'Directory Person Renamed', 'given_name', 'Directory', 'family_name', 'Renamed'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'the repeat codeless login was refused: %', v;
    END IF;
    IF (v->'data'->>'created')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'a repeat codeless login reported created=true — it made a second person: %', v;
    END IF;
    IF v->'data'->>'internal_sub' IS DISTINCT FROM v_dir_sub THEN
        RAISE EXCEPTION 'the repeat login landed on a different person: % vs %', v->'data'->>'internal_sub', v_dir_sub;
    END IF;
    SELECT count(*) INTO v_n FROM identity.credential WHERE person_sub = v_dir_sub;
    IF v_n <> 1 THEN
        RAISE EXCEPTION 'the repeat login changed the credential count: %', v_n;
    END IF;
    IF (SELECT name FROM identity.person WHERE person_sub = v_dir_sub) IS DISTINCT FROM 'Directory Person Renamed' THEN
        RAISE EXCEPTION 'the repeat login did not refresh the profile: %',
            (SELECT name FROM identity.person WHERE person_sub = v_dir_sub);
    END IF;
    IF (SELECT national_id FROM identity.person WHERE person_sub = v_dir_sub) IS NOT NULL THEN
        RAISE EXCEPTION 'a repeat codeless login stored a code';
    END IF;

    -- (3) Read back by the credential and by the subject: identity.get answers the
    --     person, and the code it reports is null — absent, not an empty string
    --     pretending to be a code.
    CALL identity.get(jsonb_build_object('idp_sub', 'idp-unit-dir-1'), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR v->'data'->>'internal_sub' IS DISTINCT FROM v_dir_sub THEN
        RAISE EXCEPTION 'identity.get by the codeless credential did not answer the person: %', v;
    END IF;
    IF v->'data'->'serial_number' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'identity.get reported a code for a codeless person: %', v->'data'->'serial_number';
    END IF;
    IF v->'data'->>'name' IS DISTINCT FROM 'Directory Person Renamed' THEN
        RAISE EXCEPTION 'identity.get did not answer the refreshed profile: %', v;
    END IF;
    CALL identity.get(jsonb_build_object('internal_sub', v_dir_sub), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR v->'data'->'serial_number' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'identity.get by the subject did not answer the codeless person: %', v;
    END IF;

    -- (4) The code path is unchanged: a login WITH a code is keyed on the code
    --     exactly as before — the first login creates, a second method with the
    --     same code lands on the same person, the row holds the canonical
    --     spelling, a code that cannot be canonicalised is refused with
    --     identity:invalid without being echoed (and is not a codeless create),
    --     and a login with no handle is refused whatever else it carries.
    CALL identity.upsert(jsonb_build_object(
        'idp_sub', 'idp-unit-dir-card-1', 'serial_number', v_code, 'login_method', 'web_eid',
        'name', 'Card Person', 'given_name', 'Card', 'family_name', 'Person'), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'created')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'the first card login did not create the person: %', v;
    END IF;
    v_card_sub := v->'data'->>'internal_sub';
    IF (SELECT national_id FROM identity.person WHERE person_sub = v_card_sub) IS DISTINCT FROM v_stored THEN
        RAISE EXCEPTION 'the code was not stored in its canonical spelling: %',
            (SELECT national_id FROM identity.person WHERE person_sub = v_card_sub);
    END IF;
    CALL identity.upsert(jsonb_build_object(
        'idp_sub', 'idp-unit-dir-card-2', 'serial_number', lower(v_code), 'login_method', 'mobile',
        'name', 'Card Person', 'given_name', 'Card', 'family_name', 'Person'), v);
    IF (v->'data'->>'created')::boolean IS NOT FALSE OR v->'data'->>'internal_sub' IS DISTINCT FROM v_card_sub THEN
        RAISE EXCEPTION 'a second method with the same code did not land on the same person: %', v;
    END IF;
    CALL identity.upsert(jsonb_build_object(
        'idp_sub', 'idp-unit-dir-card-3', 'serial_number', v_bare, 'login_method', 'web_eid'), v);
    IF v->>'code' IS DISTINCT FROM 'identity:invalid' THEN
        RAISE EXCEPTION 'a bare code with no country should be refused with identity:invalid, not treated as no code: %', v;
    END IF;
    IF position(v_bare IN v->>'message') > 0 THEN
        RAISE EXCEPTION 'the refusal echoed the code it refused: %', v;
    END IF;
    IF EXISTS (SELECT 1 FROM identity.credential WHERE idp_sub = 'idp-unit-dir-card-3') THEN
        RAISE EXCEPTION 'a refused login left a credential behind';
    END IF;
    CALL identity.upsert(jsonb_build_object('serial_number', v_code, 'name', 'Nobody'), v);
    IF v->>'code' IS DISTINCT FROM 'identity:invalid' THEN
        RAISE EXCEPTION 'a login with no handle should be refused with identity:invalid: %', v;
    END IF;
    CALL identity.upsert(jsonb_build_object('name', 'Nobody'), v);
    IF v->>'code' IS DISTINCT FROM 'identity:invalid' THEN
        RAISE EXCEPTION 'a login with neither handle nor code should be refused, not created: %', v;
    END IF;
    SELECT count(*) INTO v_n FROM identity.person WHERE name = 'Nobody';
    IF v_n <> 0 THEN
        RAISE EXCEPTION 'a refused login left % person row(s) behind', v_n;
    END IF;

    -- (5) Code-then-directory stays two persons: the card person arriving through
    --     the directory — the same name, a new handle, no code — is a NEW person.
    --     Nothing is matched on a name, and the card person is untouched.
    CALL identity.upsert(jsonb_build_object(
        'idp_sub', 'idp-unit-dir-2', 'login_method', 'upstream',
        'name', 'Card Person', 'given_name', 'Card', 'family_name', 'Person'), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'created')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'the directory login of a card person''s namesake did not create a person: %', v;
    END IF;
    v_third_sub := v->'data'->>'internal_sub';
    IF v_third_sub = v_card_sub OR v_third_sub = v_dir_sub THEN
        RAISE EXCEPTION 'a codeless login was matched to an existing person by something other than its handle: %', v_third_sub;
    END IF;
    SELECT count(*) INTO v_n FROM identity.person WHERE name = 'Card Person';
    IF v_n <> 2 THEN
        RAISE EXCEPTION 'expected the card person and the directory person as two rows, found %', v_n;
    END IF;
    IF (SELECT national_id FROM identity.person WHERE person_sub = v_card_sub) IS DISTINCT FROM v_stored THEN
        RAISE EXCEPTION 'the card person''s code was disturbed by another person''s codeless login';
    END IF;
    SELECT count(*) INTO v_n FROM identity.credential WHERE person_sub = v_card_sub;
    IF v_n <> 2 THEN
        RAISE EXCEPTION 'the card person''s credentials changed: %', v_n;
    END IF;

    -- (6) Directory-then-code stays two persons too: the codeless person's later
    --     card login — a code, a new handle — is keyed on the code and makes a
    --     person of its own. No link happens here; the codeless row is untouched.
    CALL identity.upsert(jsonb_build_object(
        'idp_sub', 'idp-unit-dir-card-4', 'serial_number', v_code_2, 'login_method', 'web_eid',
        'name', 'Directory Person Renamed', 'given_name', 'Directory', 'family_name', 'Renamed'), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'created')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'the codeless person''s later card login did not create a person of its own: %', v;
    END IF;
    v_late_sub := v->'data'->>'internal_sub';
    IF v_late_sub = v_dir_sub THEN
        RAISE EXCEPTION 'a card login was linked to a codeless person by its name';
    END IF;
    IF (SELECT national_id FROM identity.person WHERE person_sub = v_dir_sub) IS NOT NULL THEN
        RAISE EXCEPTION 'the codeless person gained a code from somebody else''s login';
    END IF;
    SELECT count(*) INTO v_n FROM identity.credential WHERE person_sub = v_dir_sub;
    IF v_n <> 1 THEN
        RAISE EXCEPTION 'the codeless person''s credentials changed: %', v_n;
    END IF;

    -- (7) A codeless login on a handle that already belongs to a CODED person lands
    --     on that person and leaves the code alone: a login that does not carry
    --     the code never blanks it.
    CALL identity.upsert(jsonb_build_object(
        'idp_sub', 'idp-unit-dir-card-1', 'login_method', 'web_eid',
        'name', 'Card Person', 'given_name', 'Card', 'family_name', 'Person'), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'created')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'a codeless login on a known handle did not land on its person: %', v;
    END IF;
    IF v->'data'->>'internal_sub' IS DISTINCT FROM v_card_sub THEN
        RAISE EXCEPTION 'a codeless login on the card person''s handle answered somebody else: %', v;
    END IF;
    IF (SELECT national_id FROM identity.person WHERE person_sub = v_card_sub) IS DISTINCT FROM v_stored THEN
        RAISE EXCEPTION 'a login that carried no code blanked the code the row held: %',
            (SELECT national_id FROM identity.person WHERE person_sub = v_card_sub);
    END IF;

    -- (8) The column itself. Without a code the row is insertable and two codeless
    --     rows coexist (the unique key does not compare empty codes); a present
    --     code is still refused unless canonical, and still belongs to exactly one
    --     person — the constraints kept their strict side.
    INSERT INTO identity.person (national_id) VALUES (NULL) RETURNING person_sub INTO v_null_1;
    INSERT INTO identity.person (national_id) VALUES (NULL) RETURNING person_sub INTO v_null_2;
    IF v_null_1 IS NULL OR v_null_2 IS NULL OR v_null_1 = v_null_2 THEN
        RAISE EXCEPTION 'two persons without a code could not coexist';
    END IF;
    BEGIN
        INSERT INTO identity.person (national_id) VALUES ('PNOLV-' || '000000' || '-' || '00053');
        RAISE EXCEPTION 'the database accepted a non-canonical code — making the column nullable loosened the check';
    EXCEPTION
        WHEN check_violation THEN NULL;   -- refused at the door, as before
    END;
    BEGIN
        INSERT INTO identity.person (national_id) VALUES (v_stored);
        RAISE EXCEPTION 'the same code was stored for a second person — the unique key is gone';
    EXCEPTION
        WHEN unique_violation THEN NULL;  -- one code, one person, as before
    END;

    -- Clean up so the test leaves nothing behind.
    DELETE FROM identity.person
     WHERE person_sub IN (v_dir_sub, v_card_sub, v_third_sub, v_late_sub, v_null_1, v_null_2);

    RAISE NOTICE 'unit.identity_codeless: PASS';
END $$;
