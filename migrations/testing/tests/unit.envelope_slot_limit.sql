-- Unit test: envelope.add_slot enforces the signer count, and enforces it by
-- COUNTING ROWS rather than by bounding order_index.
--
-- The distinction is the whole test. Callers number their slots as they please —
-- the signing wizard sends 0 and 1, the end-to-end harness sends 1 and 2 — so a
-- guard written as "reject order_index >= 2" would refuse a second signer that is
-- perfectly inside the limit, and break work that succeeds today. Anyone tempted to
-- simplify the guard into an index check will fail the third case below.
--
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL
-- them regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a
-- failed assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.envelope_slot_limit.sql

DO $$
DECLARE
    v       jsonb;
    v_owner text := 'unit-slotlimit-owner';
    v_env   text;
    v_alt   text;
    v_n     integer;
BEGIN
    -- ---------------------------------------------------------------- fixture
    CALL envelope.create_envelope(jsonb_build_object(
        'owner', v_owner, 'title', 'slot limit', 'order_policy', 'parallel'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'create_envelope failed: %', v;
    END IF;
    v_env := v->'data'->>'id';

    -- (1) Two signers are the edition's shape: both land.
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 1, 'max_signer_slots', 2), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'first signer refused: %', v;
    END IF;
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 2, 'max_signer_slots', 2), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'second signer refused: %', v;
    END IF;

    -- (2) The third signer is refused, with its own code so the service can answer
    --     422 with a reason of its own instead of a generic validation failure.
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 3, 'max_signer_slots', 2), v);
    IF v->>'code' IS DISTINCT FROM 'envelope:slot_limit' THEN
        RAISE EXCEPTION 'third signer should be refused with envelope:slot_limit, got: %', v;
    END IF;

    -- (3) THE CASE THAT MATTERS: two signers numbered 1 and 2 are two signers, not
    --     three. An index bound would have refused the slot at index 2 in step (1);
    --     here the same shape is asserted from a clean envelope, and a slot at a far
    --     higher index is admitted because only the COUNT decides.
    CALL envelope.create_envelope(jsonb_build_object(
        'owner', v_owner, 'title', 'sparse indices', 'order_policy', 'parallel'), v);
    v_alt := v->'data'->>'id';
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_alt, 'owner', v_owner, 'order_index', 4, 'max_signer_slots', 2), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'a signer at order_index 4 must be admitted (count, not index): %', v;
    END IF;
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_alt, 'owner', v_owner, 'order_index', 9, 'max_signer_slots', 2), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'a second signer at order_index 9 must be admitted: %', v;
    END IF;

    -- (4) Approvers and observers are not signers and are not counted: an envelope
    --     may carry them beside its two signers.
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 5,
        'role', 'observer', 'max_signer_slots', 2), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'an observer beside two signers must be admitted: %', v;
    END IF;
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 6,
        'role', 'approver', 'max_signer_slots', 2), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'an approver beside two signers must be admitted: %', v;
    END IF;
    -- …and the signer limit still holds with them in place.
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 7, 'max_signer_slots', 2), v);
    IF v->>'code' IS DISTINCT FROM 'envelope:slot_limit' THEN
        RAISE EXCEPTION 'non-signer slots must not raise the signer count: %', v;
    END IF;

    -- (5) The limit travels with the call, so the calling service owns the number —
    --     a call carrying a larger one admits the slot the default refuses.
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 8, 'max_signer_slots', 3), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'a call carrying a larger limit must admit the third signer: %', v;
    END IF;

    -- (6) Fail closed: a call that omits the limit gets the edition default, not
    --     "unlimited". Two signers on a fresh envelope, then a refusal.
    CALL envelope.create_envelope(jsonb_build_object(
        'owner', v_owner, 'title', 'default limit', 'order_policy', 'parallel'), v);
    v_alt := v->'data'->>'id';
    CALL envelope.add_slot(jsonb_build_object('envelope_id', v_alt, 'owner', v_owner, 'order_index', 1), v);
    CALL envelope.add_slot(jsonb_build_object('envelope_id', v_alt, 'owner', v_owner, 'order_index', 2), v);
    CALL envelope.add_slot(jsonb_build_object('envelope_id', v_alt, 'owner', v_owner, 'order_index', 3), v);
    IF v->>'code' IS DISTINCT FROM 'envelope:slot_limit' THEN
        RAISE EXCEPTION 'a call omitting max_signer_slots must fail closed at the default: %', v;
    END IF;

    -- (7) Nothing was written by a refusal.
    SELECT count(*) INTO v_n FROM envelope.signer_slot WHERE envelope_id = v_alt;
    IF v_n <> 2 THEN
        RAISE EXCEPTION 'a refused add must write nothing: expected 2 slots, found %', v_n;
    END IF;

    RAISE NOTICE 'unit.envelope_slot_limit: all assertions passed';
END $$;
