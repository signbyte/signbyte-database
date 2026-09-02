-- Unit test: identity.upsert + identity.get round-trip.
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL
-- them regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a
-- failed assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.identity.sql

DO $$
DECLARE
    v jsonb;
    v_sub text;
BEGIN
    -- First-ever login for this person -> created = true, a person id returned.
    CALL identity.upsert(
        '{"idp_sub":"idp-unit-1","serial_number":"PNOLV-000000-00001","login_method":"web_eid","given_name":"Test","family_name":"Person"}'::jsonb,
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
        '{"idp_sub":"idp-unit-2","serial_number":"PNOLV-000000-00001","login_method":"mobile"}'::jsonb,
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
    IF v->'data'->>'serial_number' is distinct from 'PNOLV-000000-00001' THEN
        RAISE EXCEPTION 'get returned the wrong national id: %', v;
    END IF;

    -- Missing national id is rejected (validate-before-write).
    CALL identity.upsert('{"idp_sub":"idp-unit-3"}'::jsonb, v);
    IF v->>'result' is distinct from 'error' THEN
        RAISE EXCEPTION 'upsert without a national id should be rejected: %', v;
    END IF;

    -- Clean up so the test is idempotent across re-runs.
    DELETE FROM identity.person WHERE person_sub = v_sub;

    RAISE NOTICE 'unit.identity: PASS';
END $$;
