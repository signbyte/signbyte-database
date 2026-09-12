-- Unit test: an envelope remembers where it came from, and each signer where to go back.
--
-- A document system can start an envelope for its own user and hand the signer to the
-- portal by link. The portal must then be able to name the requester and offer the way
-- back — so create_envelope stores the requester's registered name, its default return
-- address and its own reference, and add_slot stores a per-signer return override. An
-- envelope started in the portal has none of these, and the read must say so with NULLs
-- rather than invented values.
--
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL them
-- regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a failed
-- assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.envelope_origin.sql

DO $$
DECLARE
    v       jsonb;
    v_owner text := 'unit-origin-owner';
    v_env   text;
    v_plain text;
    v_slot  text;
    v_env_j jsonb;
    v_slots jsonb;
BEGIN
    -- ------------------------------------------------------------ (1) with an origin
    CALL envelope.create_envelope(jsonb_build_object(
        'owner', v_owner, 'title', 'delivery contract', 'order_policy', 'sequential',
        'origin_name', 'Acme DMS',
        'origin_return_url', 'https://dms.example/return',
        'origin_ref', 'contracts/2026-117'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'create_envelope with an origin failed: %', v;
    END IF;
    v_env := v->'data'->>'id';

    -- A slot with its own return, and one without.
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 1,
        'return_url', 'https://dms.example/contracts/2026-117'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'add_slot with a return_url failed: %', v;
    END IF;
    v_slot := v->'data'->>'id';
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 2), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'add_slot without a return_url failed: %', v;
    END IF;

    -- The read carries all of it back, exactly as stored.
    CALL envelope.get_envelope(jsonb_build_object('id', v_env, 'owner', v_owner), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'get_envelope failed: %', v;
    END IF;
    v_env_j := v->'data'->'envelope';
    IF v_env_j->>'origin_name' IS DISTINCT FROM 'Acme DMS' THEN
        RAISE EXCEPTION 'origin_name not carried back: %', v_env_j;
    END IF;
    IF v_env_j->>'origin_return_url' IS DISTINCT FROM 'https://dms.example/return' THEN
        RAISE EXCEPTION 'origin_return_url not carried back: %', v_env_j;
    END IF;
    IF v_env_j->>'origin_ref' IS DISTINCT FROM 'contracts/2026-117' THEN
        RAISE EXCEPTION 'origin_ref not carried back: %', v_env_j;
    END IF;

    v_slots := v->'data'->'slots';
    IF (SELECT s->>'return_url' FROM jsonb_array_elements(v_slots) s WHERE s->>'id' = v_slot)
       IS DISTINCT FROM 'https://dms.example/contracts/2026-117' THEN
        RAISE EXCEPTION 'slot return_url not carried back: %', v_slots;
    END IF;
    IF (SELECT s->>'return_url' FROM jsonb_array_elements(v_slots) s WHERE (s->>'order_index')::int = 2)
       IS NOT NULL THEN
        RAISE EXCEPTION 'a slot without a return_url must read NULL, not a value: %', v_slots;
    END IF;

    -- ------------------------------------------------------------ (2) without an origin
    -- An envelope started in the portal: nothing is invented for it.
    CALL envelope.create_envelope(jsonb_build_object(
        'owner', v_owner, 'title', 'started in the portal'), v);
    v_plain := v->'data'->>'id';
    CALL envelope.get_envelope(jsonb_build_object('id', v_plain, 'owner', v_owner), v);
    v_env_j := v->'data'->'envelope';
    IF v_env_j->>'origin_name' IS NOT NULL
       OR v_env_j->>'origin_return_url' IS NOT NULL
       OR v_env_j->>'origin_ref' IS NOT NULL THEN
        RAISE EXCEPTION 'an envelope without an origin must read NULL origin fields: %', v_env_j;
    END IF;

    -- (3) Empty strings are not values: they store as NULL, like every optional field here.
    CALL envelope.create_envelope(jsonb_build_object(
        'owner', v_owner, 'title', 'empty origin', 'origin_name', '', 'origin_ref', ''), v);
    v_plain := v->'data'->>'id';
    CALL envelope.get_envelope(jsonb_build_object('id', v_plain, 'owner', v_owner), v);
    v_env_j := v->'data'->'envelope';
    IF v_env_j->>'origin_name' IS NOT NULL OR v_env_j->>'origin_ref' IS NOT NULL THEN
        RAISE EXCEPTION 'empty origin strings must store as NULL: %', v_env_j;
    END IF;

    RAISE NOTICE 'unit.envelope_origin: all assertions passed';
END $$;
