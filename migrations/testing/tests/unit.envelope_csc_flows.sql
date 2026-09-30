-- Unit test: a signer slot names the CSC flow by how the eID card is read.
--
-- The single `csc` flow became `cscEidScan` (the card read by a phone) and
-- `cscEidPlugin` (the card in a reader, through the provider's extension). add_slot
-- accepts both and refuses `csc` for anything new, while the table still holds a
-- `csc` slot written before the split: history is never rewritten.
--
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL them
-- regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a failed
-- assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.envelope_csc_flows.sql

DO $$
DECLARE
    v       jsonb;
    v_owner text := 'unit-csc-flows-owner';
    v_env   text;
    v_other text;
BEGIN
    CALL envelope.create_envelope(jsonb_build_object('owner', v_owner, 'title', 'csc flows'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'create_envelope failed: %', v;
    END IF;
    v_env := v->'data'->>'id';

    -- Both card routes are accepted.
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 1, 'flow', 'cscEidScan'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'add_slot with cscEidScan failed: %', v;
    END IF;
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 2, 'flow', 'cscEidPlugin'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'add_slot with cscEidPlugin failed: %', v;
    END IF;

    -- The retired single flow is refused for a new slot, with the precise error. On an
    -- envelope of its own, so the flow check is the only thing that can refuse it.
    CALL envelope.create_envelope(jsonb_build_object('owner', v_owner, 'title', 'retired csc'), v);
    v_other := v->'data'->>'id';
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_other, 'owner', v_owner, 'order_index', 1, 'flow', 'csc'), v);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'envelope:invalid' THEN
        RAISE EXCEPTION 'add_slot with the retired csc must be refused as envelope:invalid: %', v;
    END IF;

    -- A slot written before the split is still a legal stored value.
    UPDATE envelope.signer_slot SET flow = 'csc' WHERE envelope_id = v_env AND order_index = 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the slot to age was not found';
    END IF;
END
$$;
