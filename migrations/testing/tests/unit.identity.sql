-- Unit test: identity.upsert + identity.get round-trip.
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL
-- them regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a
-- failed assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.identity.sql

DO $$
DECLARE
    v jsonb;
    v_sub text;
    v_spell_sub text;
    v_foreign_sub text;
BEGIN
    -- First-ever login for this person -> created = true, a person id returned.
    CALL identity.upsert(
        '{"idp_sub":"idp-unit-1","serial_number":"PNOLV-00000000001","login_method":"web_eid","given_name":"Test","family_name":"Person"}'::jsonb,
        v);
    IF v->>'result' is distinct from 'success' THEN
        RAISE EXCEPTION 'upsert did not succeed: %', v;
    END IF;
    IF (v->'data'->>'created')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'first upsert should report created=true: %', v;
    END IF;
    v_sub := v->'data'->>'internal_sub';

    -- A second method for the SAME person (same national id) -> created = false,
    -- SAME person id (dedupe across auth methods).
    CALL identity.upsert(
        '{"idp_sub":"idp-unit-2","serial_number":"PNOLV-00000000001","login_method":"mobile"}'::jsonb,
        v);
    IF (v->'data'->>'created')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'adding a method to a known person should report created=false: %', v;
    END IF;
    IF v->'data'->>'internal_sub' is distinct from v_sub THEN
        RAISE EXCEPTION 'same person resolved to a different subject: % vs %', v->'data'->>'internal_sub', v_sub;
    END IF;

    -- get by the second credential handle resolves back to the same person.
    CALL identity.get('{"idp_sub":"idp-unit-2"}'::jsonb, v);
    if v->>'result' is distinct from 'success' then raise exception 'identity.get failed: %', v; end if;
    IF v->'data'->>'internal_sub' is distinct from v_sub THEN
        RAISE EXCEPTION 'get by idp_sub did not resolve to the person: %', v;
    END IF;
    IF v->'data'->>'serial_number' is distinct from 'PNOLV-00000000001' THEN
        RAISE EXCEPTION 'get returned the wrong national id: %', v;
    END IF;

    -- Missing national id is rejected (validate-before-write).
    CALL identity.upsert('{"idp_sub":"idp-unit-3"}'::jsonb, v);
    IF v->>'result' is distinct from 'error' THEN
        RAISE EXCEPTION 'upsert without a national id should be rejected: %', v;
    END IF;

    -- ---------------------------------------------------------------------
    -- One person, whichever way their code is written. This is the failure the
    -- canonical column exists to end: the same human arriving with a different
    -- spelling used to become a second person, with a second subject, and the
    -- documents signed under one were unreachable from the other.
    -- ---------------------------------------------------------------------
    CALL identity.upsert(
        ('{"idp_sub":"idp-unit-spell-1","serial_number":"PNOLV-' || '000000' || '-' || '00002' ||
          '","login_method":"web_eid"}')::jsonb, v);
    IF v->>'result' is distinct from 'success' THEN
        RAISE EXCEPTION 'a hyphenated code was refused instead of canonicalised: %', v;
    END IF;
    v_spell_sub := v->'data'->>'internal_sub';

    -- The same person, code written without the separator, arriving on another
    -- method: the same subject, and NOT a create.
    CALL identity.upsert(
        ('{"idp_sub":"idp-unit-spell-2","serial_number":"PNOLV-' || '00000000002' ||
          '","login_method":"mobile"}')::jsonb, v);
    IF v->'data'->>'internal_sub' is distinct from v_spell_sub THEN
        RAISE EXCEPTION 'two spellings of one code produced two people: % vs %',
            v->'data'->>'internal_sub', v_spell_sub;
    END IF;
    IF (v->'data'->>'created')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'a known person, reached by another spelling, was reported as created: %', v;
    END IF;

    -- ...and the row is stored in the one canonical spelling, not as it arrived.
    IF (SELECT national_id FROM identity.person WHERE person_sub = v_spell_sub)
       IS DISTINCT FROM 'PNOLV-' || '00000000002' THEN
        RAISE EXCEPTION 'the stored code is not the canonical spelling: %',
            (SELECT national_id FROM identity.person WHERE person_sub = v_spell_sub);
    END IF;

    -- A code with no country in it is refused rather than filed under a guess.
    CALL identity.upsert('{"idp_sub":"idp-unit-spell-3","serial_number":"000000-00002"}'::jsonb, v);
    IF v->>'result' is distinct from 'error' THEN
        RAISE EXCEPTION 'a bare code with no country should be refused, not guessed at: %', v;
    END IF;

    -- ---------------------------------------------------------------------
    -- The constraint, not the procedure, is what makes the invariant true. A
    -- write path that bypasses `upsert` and stores a non-canonical spelling must
    -- be refused by the database itself — that is the guarantee that covers code
    -- nobody has written yet.
    -- ---------------------------------------------------------------------
    BEGIN
        INSERT INTO identity.person (national_id) VALUES ('PNOLV-' || '000000' || '-' || '00003');
        RAISE EXCEPTION 'the database accepted a non-canonical national_id — the constraint is not doing its job';
    EXCEPTION
        WHEN check_violation THEN NULL;   -- refused at the door, as intended
    END;

    -- The same for a code carrying an identity type this platform does not know.
    BEGIN
        INSERT INTO identity.person (national_id) VALUES ('VATLV-' || '00000000003');
        RAISE EXCEPTION 'the database accepted an unknown identity type';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;

    -- A foreign code with the SAME digits is a different person, and is stored.
    INSERT INTO identity.person (national_id) VALUES ('PNOEE-' || '00000000002')
        RETURNING person_sub INTO v_foreign_sub;
    IF v_foreign_sub IS NULL OR v_foreign_sub = v_spell_sub THEN
        RAISE EXCEPTION 'the same digits in another country did not make a separate person';
    END IF;

    -- Clean up so the test is idempotent across re-runs.
    DELETE FROM identity.person WHERE person_sub IN (v_sub, v_spell_sub, v_foreign_sub);

    RAISE NOTICE 'unit.identity: PASS';
END $$;
