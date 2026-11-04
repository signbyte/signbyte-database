-- Unit test: the `legacyEid` signing flow is accepted on a signer slot and on a signing job.
--
-- `legacyEid` signs with the eID card in the person's browser through the eParaksts
-- provider's own plugin. envelope.add_slot, signing.save_job and
-- signing.insert_signature accept it, and the tables' flow checks store it; a
-- misspelling is refused with each procedure's precise error, so the lists are exact
-- names, not a pattern.
--
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL them
-- regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a failed
-- assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.legacy_eid_flow.sql

DO $$
DECLARE
    v       jsonb;
    v_owner text := 'unit-legacy-eid-owner';
    v_env   text;
    v_other text;
    v_slot  text;
    v_job   text := util.generate_ulid();
BEGIN
    -- A signer slot names the flow.
    CALL envelope.create_envelope(jsonb_build_object('owner', v_owner, 'title', 'legacy eid'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'create_envelope failed: %', v;
    END IF;
    v_env := v->'data'->>'id';

    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_env, 'owner', v_owner, 'order_index', 1, 'flow', 'legacyEid'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'add_slot with legacyEid failed: %', v;
    END IF;
    SELECT id INTO v_slot FROM envelope.signer_slot
     WHERE envelope_id = v_env AND order_index = 1 AND flow = 'legacyEid';
    IF v_slot IS NULL THEN
        RAISE EXCEPTION 'the legacyEid slot was not stored';
    END IF;

    -- A misspelling is refused, on an envelope of its own so the flow check is the only
    -- thing that can refuse it.
    CALL envelope.create_envelope(jsonb_build_object('owner', v_owner, 'title', 'misspelt'), v);
    v_other := v->'data'->>'id';
    CALL envelope.add_slot(jsonb_build_object(
        'envelope_id', v_other, 'owner', v_owner, 'order_index', 1, 'flow', 'legacyEID'), v);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'envelope:invalid' THEN
        RAISE EXCEPTION 'add_slot with legacyEID must be refused as envelope:invalid: %', v;
    END IF;

    -- A signing job uses the flow, carrying the sign-in it came from.
    CALL signing.save_job(jsonb_build_object(
        'job_id', v_job, 'envelope_id', v_env, 'slot_id', v_slot, 'flow', 'legacyEid',
        'sig_format', 'XAdES', 'caller_sub', v_owner, 'login_method', 'legacyEid', 'loa', 'high'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'save_job with legacyEid failed: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM signing.signing_job
                    WHERE job_id = v_job AND flow = 'legacyEid' AND login_method = 'legacyEid') THEN
        RAISE EXCEPTION 'the legacyEid job was not stored with its flow and sign-in';
    END IF;

    CALL signing.save_job(jsonb_build_object(
        'job_id', util.generate_ulid(), 'envelope_id', v_env, 'slot_id', v_slot, 'flow', 'legacyEID',
        'sig_format', 'XAdES', 'caller_sub', v_owner), v);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'signing:invalid' THEN
        RAISE EXCEPTION 'save_job with legacyEID must be refused as signing:invalid: %', v;
    END IF;

    -- The signature it produced records the flow that delivered it.
    CALL signing.insert_signature(jsonb_build_object(
        'job_id', v_job, 'envelope_id', v_env, 'slot_id', v_slot, 'flow_used', 'legacyEid',
        'sig_format', 'XAdES', 'login_method', 'legacyEid', 'loa', 'high'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'insert_signature with legacyEid failed: %', v;
    END IF;

    CALL signing.insert_signature(jsonb_build_object(
        'job_id', v_job, 'envelope_id', v_env, 'slot_id', v_slot, 'flow_used', 'legacyEID',
        'sig_format', 'XAdES'), v);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'signing:invalid' THEN
        RAISE EXCEPTION 'insert_signature with legacyEID must be refused as signing:invalid: %', v;
    END IF;
END
$$;
