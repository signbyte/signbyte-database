-- R: repeatable migration — the signflow store API (`signing` + `validation`).
--
-- These back the store.Store interface the signflow service uses. They run as
-- the owner role (owner of the tables), so the EXECUTE-only `signing_public` role
-- drives them without any table privileges. Each:
--   * uses the uniform JSONB envelope `(pi_data jsonb, INOUT po_data jsonb)`,
--   * pins `search_path` ending in pg_temp (SECURITY DEFINER hardening),
--   * returns a structured result via util.result_success / util.result_error with
--     `<domain>:<reason>` codes (`:not_found` → 404, else 422),
--   * validates BEFORE any write (Pattern A: return) and, on any unexpected error
--     after a write, re-raises a structured error with SQLSTATE P0001 (Pattern B) so
--     the transaction ROLLS BACK.
--
-- The procedures: save_job, reconcile_job, insert_signature,
-- validation.store_report; get_job + get_signature are thin reads (status
-- reconciliation / re-validation), and record_validation links a normalized
-- validation result back onto the signature_record. The orchestration logic stays
-- in Go — these are thin persistence/read wrappers. Re-applied whenever
-- the checksum changes.

-- signing.save_job — persist the slot↔jobId mapping BEFORE the redirect.
-- pi_data = { job_id, envelope_id, slot_id, flow, sig_format, caller_sub, [state],
--             [login_method], [loa] }.
CREATE OR REPLACE PROCEDURE signing.save_job(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_job    text := pi_data->>'job_id';
    v_env    text := pi_data->>'envelope_id';
    v_slot   text := pi_data->>'slot_id';
    v_flow   text := pi_data->>'flow';
    v_format text := pi_data->>'sig_format';
    v_caller text := pi_data->>'caller_sub';
    v_state  text := COALESCE(pi_data->>'state', 'PREPARING');
BEGIN
    IF v_job IS NULL OR v_job = '' THEN
        po_data := util.result_error('signing:invalid', 'job_id is required'); RETURN;
    END IF;
    IF v_env IS NULL OR v_env = '' OR v_slot IS NULL OR v_slot = '' THEN
        po_data := util.result_error('signing:invalid', 'envelope_id and slot_id are required'); RETURN;
    END IF;
    -- The null test is not redundant: this value is read straight from the
    -- request, so an absent key arrives as NULL, and NULL NOT IN (...)
    -- evaluates to NULL rather than true — without it the branch never fires
    -- for a missing field, and the caller gets whatever the write fails with
    -- instead of the precise refusal this check exists to give.
    IF v_flow IS NULL OR v_flow NOT IN ('webEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'csc') THEN
        po_data := util.result_error('signing:invalid', 'invalid flow'); RETURN;
    END IF;
    IF v_format IS NULL OR v_format NOT IN ('PAdES', 'XAdES') THEN
        po_data := util.result_error('signing:invalid', 'sig_format must be PAdES or XAdES'); RETURN;
    END IF;
    IF v_caller IS NULL OR v_caller = '' THEN
        po_data := util.result_error('signing:invalid', 'caller_sub is required'); RETURN;
    END IF;

    INSERT INTO signing.signing_job (job_id, envelope_id, slot_id, flow, sig_format, state, caller_sub, login_method, loa)
    VALUES (v_job, v_env, v_slot, v_flow, v_format, v_state, v_caller,
            NULLIF(pi_data->>'login_method', ''), NULLIF(pi_data->>'loa', ''));

    po_data := util.result_success(jsonb_build_object('job_id', v_job));
EXCEPTION
    WHEN unique_violation THEN
        po_data := util.result_error('signing:duplicate', 'job already exists');
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('signing:save_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- signing.reconcile_job — idempotent job-state update on return/callback.
-- pi_data = { job_id, state }.
CREATE OR REPLACE PROCEDURE signing.reconcile_job(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_job   text := pi_data->>'job_id';
    v_state text := pi_data->>'state';
    v_found text;
BEGIN
    IF v_job IS NULL OR v_job = '' THEN
        po_data := util.result_error('signing:invalid', 'job_id is required'); RETURN;
    END IF;
    IF v_state IS NULL OR v_state = '' THEN
        po_data := util.result_error('signing:invalid', 'state is required'); RETURN;
    END IF;

    UPDATE signing.signing_job SET state = v_state WHERE job_id = v_job RETURNING job_id INTO v_found;
    IF v_found IS NULL THEN
        po_data := util.result_error('signing:not_found', 'job not found'); RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('job_id', v_found, 'state', v_state));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('signing:reconcile_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- signing.get_job — read one job by id (thin read, for status reconciliation).
-- pi_data = { job_id }.
CREATE OR REPLACE PROCEDURE signing.get_job(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_job text := pi_data->>'job_id';
    v_row jsonb;
BEGIN
    IF v_job IS NULL OR v_job = '' THEN
        po_data := util.result_error('signing:invalid', 'job_id is required'); RETURN;
    END IF;

    SELECT to_jsonb(j) INTO v_row FROM signing.signing_job j WHERE j.job_id = v_job;
    IF v_row IS NULL THEN
        po_data := util.result_error('signing:not_found', 'job not found'); RETURN;
    END IF;

    po_data := util.result_success(v_row);
END
$$;

-- signing.get_signature — read one signature_record by id (thin read). Used by
-- on-demand re-validation to resolve the signed-document ref + (via the job) the
-- owning caller. pi_data = { id }.
CREATE OR REPLACE PROCEDURE signing.get_signature(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_id  text := pi_data->>'id';
    v_row jsonb;
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('signing:invalid', 'id is required'); RETURN;
    END IF;

    SELECT to_jsonb(s) INTO v_row FROM signing.signature_record s WHERE s.id = v_id;
    IF v_row IS NULL THEN
        po_data := util.result_error('signing:not_found', 'signature not found'); RETURN;
    END IF;

    po_data := util.result_success(v_row);
END
$$;

-- signing.record_validation — link a normalized validation answer back onto the
-- signature_record: the validation pass/fail, the report ref, and the legal-meaning
-- level. Idempotent (a re-validation overwrites the prior link).
-- pi_data = { signature_id, [validation_id], validated, [level] }.
CREATE OR REPLACE PROCEDURE signing.record_validation(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_sig       text    := pi_data->>'signature_id';
    v_vid       text    := NULLIF(pi_data->>'validation_id', '');
    v_validated boolean := COALESCE((pi_data->>'validated')::boolean, false);
    v_level     text    := NULLIF(pi_data->>'level', '');
    v_found     text;
BEGIN
    IF v_sig IS NULL OR v_sig = '' THEN
        po_data := util.result_error('signing:invalid', 'signature_id is required'); RETURN;
    END IF;

    UPDATE signing.signature_record
       SET validation_id = v_vid,
           validated     = v_validated,
           level         = COALESCE(v_level, level)
     WHERE id = v_sig
     RETURNING id INTO v_found;
    IF v_found IS NULL THEN
        po_data := util.result_error('signing:not_found', 'signature not found'); RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('id', v_found));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('signing:record_validation_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- signing.insert_signature — record a signature_record (one per applied
-- signature; co-signing adds a second row).
-- pi_data = { job_id, envelope_id, slot_id, flow_used, sig_format, [level],
--             [signed_document_ref], [timestamp_ref], [validated], [validation_id],
--             [preservation_class], [login_method], [loa] }.
CREATE OR REPLACE PROCEDURE signing.insert_signature(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_job    text := pi_data->>'job_id';
    v_env    text := pi_data->>'envelope_id';
    v_slot   text := pi_data->>'slot_id';
    v_flow   text := pi_data->>'flow_used';
    v_format text := pi_data->>'sig_format';
    v_presv  text := COALESCE(pi_data->>'preservation_class', 'none');
    v_id     text;
BEGIN
    IF v_job IS NULL OR v_job = '' OR v_env IS NULL OR v_env = '' OR v_slot IS NULL OR v_slot = '' THEN
        po_data := util.result_error('signing:invalid', 'job_id, envelope_id and slot_id are required'); RETURN;
    END IF;
    -- The null test is not redundant: this value is read straight from the
    -- request, so an absent key arrives as NULL, and NULL NOT IN (...)
    -- evaluates to NULL rather than true — without it the branch never fires
    -- for a missing field, and the caller gets whatever the write fails with
    -- instead of the precise refusal this check exists to give.
    IF v_flow IS NULL OR v_flow NOT IN ('webEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'csc') THEN
        po_data := util.result_error('signing:invalid', 'invalid flow_used'); RETURN;
    END IF;
    IF v_format IS NULL OR v_format NOT IN ('PAdES', 'XAdES') THEN
        po_data := util.result_error('signing:invalid', 'sig_format must be PAdES or XAdES'); RETURN;
    END IF;
    IF v_presv NOT IN ('none', 'b_lt', 'preservation') THEN
        po_data := util.result_error('signing:invalid', 'invalid preservation_class'); RETURN;
    END IF;

    INSERT INTO signing.signature_record (
        job_id, envelope_id, slot_id, flow_used, sig_format, level,
        signed_document_ref, timestamp_ref, validated, validation_id, preservation_class,
        login_method, loa
    )
    VALUES (
        v_job, v_env, v_slot, v_flow, v_format,
        NULLIF(pi_data->>'level', ''),
        NULLIF(pi_data->>'signed_document_ref', ''),
        NULLIF(pi_data->>'timestamp_ref', ''),
        COALESCE((pi_data->>'validated')::boolean, false),
        NULLIF(pi_data->>'validation_id', ''),
        v_presv,
        NULLIF(pi_data->>'login_method', ''),
        NULLIF(pi_data->>'loa', '')
    )
    RETURNING id INTO v_id;

    po_data := util.result_success(jsonb_build_object('id', v_id));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('signing:insert_signature_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- validation.store_report — persist the Orchestrator-normalized
-- result (the full signature-details field set; the verbatim provider report is
-- never stored). The signer serial/registration is stored in the clear; masking
-- is a UI-only presentation concern and the reveal is not audited.
-- pi_data = { signature_id, verdict, [format], [level], [result_s3_ref], [signer],
--             [signer_serial], [organization], [container_form], [signing_time],
--             [revocation_time], [max_validity_time], [signed_files],
--             [warnings], [errors] }.
-- Times are RFC 3339 strings (empty → NULL); signed_files/warnings/errors are JSON
-- text arrays (absent → NULL, [] → an explicit empty set).
CREATE OR REPLACE PROCEDURE validation.store_report(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = validation, util, pg_temp
AS $$
DECLARE
    v_sig     text := pi_data->>'signature_id';
    v_verdict text := pi_data->>'verdict';
    v_id      text;
BEGIN
    IF v_sig IS NULL OR v_sig = '' THEN
        po_data := util.result_error('validation:invalid', 'signature_id is required'); RETURN;
    END IF;
    IF v_verdict IS NULL OR v_verdict NOT IN ('PASSED', 'INDETERMINATE', 'FAILED') THEN
        po_data := util.result_error('validation:invalid', 'verdict must be PASSED, INDETERMINATE or FAILED'); RETURN;
    END IF;

    INSERT INTO validation.report (
        signature_id, verdict, format, level, result_s3_ref,
        signer, signer_serial, organization, container_form,
        signing_time, revocation_time, max_validity_time,
        signed_files, warnings, errors
    )
    VALUES (
        v_sig,
        v_verdict,
        NULLIF(pi_data->>'format', ''),
        NULLIF(pi_data->>'level', ''),
        NULLIF(pi_data->>'result_s3_ref', ''),
        NULLIF(pi_data->>'signer', ''),
        NULLIF(pi_data->>'signer_serial', ''),
        NULLIF(pi_data->>'organization', ''),
        NULLIF(pi_data->>'container_form', ''),
        NULLIF(pi_data->>'signing_time', '')::timestamptz,
        NULLIF(pi_data->>'revocation_time', '')::timestamptz,
        NULLIF(pi_data->>'max_validity_time', '')::timestamptz,
        pi_data->'signed_files',
        pi_data->'warnings',
        pi_data->'errors'
    )
    RETURNING id INTO v_id;

    po_data := util.result_success(jsonb_build_object('id', v_id));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('validation:store_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- signing.acquire_chain_lock — atomically claim the single active-signer slot for a
-- chain (the PAdES co-sign concurrency gate). pi_data = { chain_key, holder_slot,
-- holder_ref, [ttl_seconds] }. Returns { acquired, holder_slot }: acquired=true when
-- the chain is free, its lock has expired, or the caller's own slot already holds it
-- (idempotent re-begin); acquired=false (with the current holder_slot) when another
-- slot holds an unexpired lock. Atomic — the claim is a single upsert.
CREATE OR REPLACE PROCEDURE signing.acquire_chain_lock(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_key   text := pi_data->>'chain_key';
    v_slot  text := pi_data->>'holder_slot';
    v_ref   text := pi_data->>'holder_ref';
    v_ttl   int  := COALESCE((pi_data->>'ttl_seconds')::int, 300);
    v_owner text;
BEGIN
    IF v_key IS NULL OR v_key = '' THEN
        po_data := util.result_error('signing:invalid', 'chain_key is required'); RETURN;
    END IF;
    IF v_slot IS NULL OR v_slot = '' THEN
        po_data := util.result_error('signing:invalid', 'holder_slot is required'); RETURN;
    END IF;

    INSERT INTO signing.chain_lock (chain_key, holder_slot, holder_ref, expires_at)
    VALUES (v_key, v_slot, COALESCE(v_ref, ''), now() + make_interval(secs => v_ttl))
    ON CONFLICT (chain_key) DO UPDATE
        SET holder_slot = EXCLUDED.holder_slot,
            holder_ref  = EXCLUDED.holder_ref,
            expires_at  = EXCLUDED.expires_at
        WHERE signing.chain_lock.expires_at < now()
           OR signing.chain_lock.holder_slot = EXCLUDED.holder_slot
    RETURNING holder_slot INTO v_owner;

    IF v_owner IS NOT NULL THEN
        po_data := util.result_success(jsonb_build_object('acquired', true, 'holder_slot', v_owner));
    ELSE
        -- Conflict with the WHERE unmet: another slot holds an unexpired lock.
        SELECT holder_slot INTO v_owner FROM signing.chain_lock WHERE chain_key = v_key;
        po_data := util.result_success(jsonb_build_object('acquired', false, 'holder_slot', v_owner));
    END IF;
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('signing:lock_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- signing.release_chain_lock — release the caller's own hold on a chain. A no-op if
-- another slot already took the chain over after a TTL expiry (only the current
-- holder's row is deleted). pi_data = { chain_key, holder_slot }.
CREATE OR REPLACE PROCEDURE signing.release_chain_lock(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_key  text := pi_data->>'chain_key';
    v_slot text := pi_data->>'holder_slot';
BEGIN
    IF v_key IS NULL OR v_key = '' OR v_slot IS NULL OR v_slot = '' THEN
        po_data := util.result_error('signing:invalid', 'chain_key and holder_slot are required'); RETURN;
    END IF;
    DELETE FROM signing.chain_lock WHERE chain_key = v_key AND holder_slot = v_slot;
    po_data := util.result_success(jsonb_build_object('released', true));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('signing:lock_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- signing.chain_lock_status — read whether a chain is currently locked (an unexpired
-- lock exists), for the "wait until the chain frees" long-poll a blocked co-signer
-- runs. pi_data = { chain_key }. Returns { locked, holder_slot } (holder_slot is ""
-- when free). An expired lock reads as free (the TTL backstop).
CREATE OR REPLACE PROCEDURE signing.chain_lock_status(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = signing, util, pg_temp
AS $$
DECLARE
    v_key  text := pi_data->>'chain_key';
    v_slot text;
BEGIN
    IF v_key IS NULL OR v_key = '' THEN
        po_data := util.result_error('signing:invalid', 'chain_key is required'); RETURN;
    END IF;
    SELECT holder_slot INTO v_slot
      FROM signing.chain_lock
     WHERE chain_key = v_key AND expires_at > now();
    po_data := util.result_success(jsonb_build_object('locked', v_slot IS NOT NULL, 'holder_slot', COALESCE(v_slot, '')));
END
$$;

-- ---------------------------------------------------------------------------
-- EXECUTE grants — lock every procedure down, then grant only to signing_public.
-- ---------------------------------------------------------------------------
REVOKE ALL ON PROCEDURE signing.save_job(jsonb, jsonb)             FROM PUBLIC;
REVOKE ALL ON PROCEDURE signing.reconcile_job(jsonb, jsonb)        FROM PUBLIC;
REVOKE ALL ON PROCEDURE signing.get_job(jsonb, jsonb)              FROM PUBLIC;
REVOKE ALL ON PROCEDURE signing.get_signature(jsonb, jsonb)        FROM PUBLIC;
REVOKE ALL ON PROCEDURE signing.record_validation(jsonb, jsonb)    FROM PUBLIC;
REVOKE ALL ON PROCEDURE signing.insert_signature(jsonb, jsonb)     FROM PUBLIC;
REVOKE ALL ON PROCEDURE signing.acquire_chain_lock(jsonb, jsonb)   FROM PUBLIC;
REVOKE ALL ON PROCEDURE signing.release_chain_lock(jsonb, jsonb)   FROM PUBLIC;
REVOKE ALL ON PROCEDURE signing.chain_lock_status(jsonb, jsonb)    FROM PUBLIC;
REVOKE ALL ON PROCEDURE validation.store_report(jsonb, jsonb)      FROM PUBLIC;

GRANT EXECUTE ON PROCEDURE signing.save_job(jsonb, jsonb)            TO signing_public;
GRANT EXECUTE ON PROCEDURE signing.reconcile_job(jsonb, jsonb)       TO signing_public;
GRANT EXECUTE ON PROCEDURE signing.get_job(jsonb, jsonb)             TO signing_public;
GRANT EXECUTE ON PROCEDURE signing.get_signature(jsonb, jsonb)       TO signing_public;
GRANT EXECUTE ON PROCEDURE signing.record_validation(jsonb, jsonb)   TO signing_public;
GRANT EXECUTE ON PROCEDURE signing.insert_signature(jsonb, jsonb)    TO signing_public;
GRANT EXECUTE ON PROCEDURE signing.acquire_chain_lock(jsonb, jsonb)  TO signing_public;
GRANT EXECUTE ON PROCEDURE signing.release_chain_lock(jsonb, jsonb)  TO signing_public;
GRANT EXECUTE ON PROCEDURE signing.chain_lock_status(jsonb, jsonb)   TO signing_public;
GRANT EXECUTE ON PROCEDURE validation.store_report(jsonb, jsonb)     TO signing_public;
