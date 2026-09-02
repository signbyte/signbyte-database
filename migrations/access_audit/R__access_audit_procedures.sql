-- R: repeatable migration — the access_audit store API (7 procedures).
--
-- These back the store.Store interface the access-audit service uses. They run
-- as the migrating role (the owner of the tables), so the EXECUTE-only
-- `access_audit_public` service role drives them without any table privileges.
-- Each:
--   * uses the uniform JSONB envelope `(pi_data jsonb, INOUT po_data jsonb)`,
--   * pins `search_path` ending in pg_temp (SECURITY DEFINER hardening),
--   * returns a structured result via util.result_success / util.result_error
--     with `<domain>:<reason>` error codes,
--   * validates BEFORE any write (returning early on bad input) and, on any
--     unexpected error after a write, re-raises a structured error with SQLSTATE
--     P0001 so the transaction ROLLS BACK rather than committing a partial write.
--
-- The SEAL is computed by the SERVICE (which holds the Vault HMAC key) over the
-- record's canonical bytes and passed in; the DB only stores it. Likewise the
-- checkpoint seal is computed by the service from the per-period seals returned
-- by `seals_for_period`. The DB never holds the HMAC key.
-- Re-applied automatically whenever the checksum changes.

-- access_audit.append_record — append one GDPR access record (idempotent on
-- event_id, so an outbox retry never duplicates).
-- pi_data = { "record": <broker.Envelope>, "seal": <hex>,
--             "source_service": <authenticated caller>, "system": <tenant> }.
CREATE OR REPLACE PROCEDURE access_audit.append_record(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = access_audit, util, pg_temp
AS $$
DECLARE
    v_rec       jsonb := pi_data->'record';
    v_event_id  text  := v_rec->>'event_id';
    v_seal      text  := pi_data->>'seal';
    v_occurred  timestamptz;
    v_subjects  text[];
    v_row_id    text;
BEGIN
    -- Pattern A validation (before any write).
    IF v_rec IS NULL OR jsonb_typeof(v_rec) <> 'object' THEN
        po_data := util.result_error('access_audit:invalid', 'record object is required');
        RETURN;
    END IF;
    IF v_event_id IS NULL OR v_event_id = '' THEN
        po_data := util.result_error('access_audit:invalid', 'record.event_id is required');
        RETURN;
    END IF;
    IF COALESCE(v_rec->>'event_type', '') = '' THEN
        po_data := util.result_error('access_audit:invalid', 'record.event_type is required');
        RETURN;
    END IF;
    IF COALESCE(v_rec->>'outcome', '') = '' THEN
        po_data := util.result_error('access_audit:invalid', 'record.outcome is required');
        RETURN;
    END IF;
    IF v_seal IS NULL OR v_seal = '' THEN
        po_data := util.result_error('access_audit:invalid', 'seal is required');
        RETURN;
    END IF;

    v_occurred := COALESCE((v_rec->>'occurred_at')::timestamptz, now());
    v_subjects := ARRAY(SELECT jsonb_array_elements_text(COALESCE(v_rec->'data_subjects', '[]'::jsonb)));

    WITH ins AS (
        INSERT INTO access_audit.access_record (
            event_id, occurred_at, retention_period, event_type, operation, outcome,
            actor_id, actor_type, data_subjects, resource_type, resource_id,
            lawful_basis, purpose, source_service, system, seal, content
        )
        VALUES (
            v_event_id,
            v_occurred,
            date_trunc('month', v_occurred)::date,
            v_rec->>'event_type',
            v_rec->>'operation',
            v_rec->>'outcome',
            v_rec#>>'{actor,id}',
            v_rec#>>'{actor,type}',
            v_subjects,
            v_rec#>>'{resource,type}',
            v_rec#>>'{resource,id}',
            v_rec->>'lawful_basis',
            v_rec->>'purpose',
            NULLIF(pi_data->>'source_service', ''),
            COALESCE(NULLIF(pi_data->>'system', ''), 'default'),
            v_seal,
            v_rec
        )
        ON CONFLICT (event_id) DO NOTHING
        RETURNING row_id
    )
    SELECT row_id INTO v_row_id FROM ins;

    IF v_row_id IS NULL THEN
        -- Duplicate delivery (outbox retry): return the existing row, not an error.
        SELECT row_id INTO v_row_id FROM access_audit.access_record WHERE event_id = v_event_id;
        po_data := util.result_success(jsonb_build_object('recordId', v_row_id, 'eventId', v_event_id, 'duplicate', true));
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('recordId', v_row_id, 'eventId', v_event_id, 'duplicate', false));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:append_record_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- access_audit.records_by_subject — every access record concerning a data
-- subject, for DSAR (Art. 15). Returns the verbatim envelope + stored seal so
-- the service can re-verify integrity and compile the export.
-- pi_data = { "subject": <ref>, "from": <ts?>, "to": <ts?>, "limit": <int?> }.
CREATE OR REPLACE PROCEDURE access_audit.records_by_subject(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = access_audit, util, pg_temp
AS $$
DECLARE
    v_subject text := pi_data->>'subject';
    v_from    timestamptz := (pi_data->>'from')::timestamptz;
    v_to      timestamptz := (pi_data->>'to')::timestamptz;
    v_limit   int := LEAST(GREATEST(COALESCE((pi_data->>'limit')::int, 1000), 1), 10000);
    v_records jsonb;
    v_count   bigint;
BEGIN
    IF v_subject IS NULL OR v_subject = '' THEN
        po_data := util.result_error('access_audit:invalid', 'subject is required');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(jsonb_build_object('content', content, 'seal', seal, 'seq', seq)), '[]'::jsonb),
           count(*)
      INTO v_records, v_count
    FROM (
        SELECT content, seal, seq
        FROM access_audit.access_record
        WHERE v_subject = ANY(data_subjects)
          AND (v_from IS NULL OR occurred_at >= v_from)
          AND (v_to   IS NULL OR occurred_at <= v_to)
        ORDER BY occurred_at, seq
        LIMIT v_limit
    ) q;

    po_data := util.result_success(jsonb_build_object('subject', v_subject, 'records', v_records, 'count', v_count));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:records_by_subject_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- access_audit.seals_for_period — the per-row seals of one retention period,
-- ordered by event_id (deterministic), for the service to compute / re-derive
-- the period checkpoint. pi_data = { "period": <date> }.
CREATE OR REPLACE PROCEDURE access_audit.seals_for_period(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = access_audit, util, pg_temp
AS $$
DECLARE
    v_period date := (pi_data->>'period')::date;
    v_seals  jsonb;
    v_count  bigint;
BEGIN
    IF v_period IS NULL THEN
        po_data := util.result_error('access_audit:invalid', 'period is required');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(seal ORDER BY event_id), '[]'::jsonb), count(*)
      INTO v_seals, v_count
    FROM access_audit.access_record
    WHERE retention_period = v_period;

    po_data := util.result_success(jsonb_build_object('period', v_period, 'seals', v_seals, 'count', v_count));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:seals_for_period_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- access_audit.save_checkpoint — persist a period's sealed checkpoint
-- (write-once; a re-run on an already-checkpointed period is a no-op).
-- pi_data = { "period": <date>, "row_count": <int>, "checkpoint_seal": <hex> }.
CREATE OR REPLACE PROCEDURE access_audit.save_checkpoint(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = access_audit, util, pg_temp
AS $$
DECLARE
    v_period date := (pi_data->>'period')::date;
    v_count  bigint := COALESCE((pi_data->>'row_count')::bigint, 0);
    v_seal   text := pi_data->>'checkpoint_seal';
    v_created boolean;
BEGIN
    IF v_period IS NULL THEN
        po_data := util.result_error('access_audit:invalid', 'period is required');
        RETURN;
    END IF;
    IF v_seal IS NULL OR v_seal = '' THEN
        po_data := util.result_error('access_audit:invalid', 'checkpoint_seal is required');
        RETURN;
    END IF;

    WITH ins AS (
        INSERT INTO access_audit.checkpoint (retention_period, row_count, checkpoint_seal)
        VALUES (v_period, v_count, v_seal)
        ON CONFLICT (retention_period) DO NOTHING
        RETURNING 1
    )
    SELECT count(*) > 0 INTO v_created FROM ins;

    po_data := util.result_success(jsonb_build_object('period', v_period, 'created', v_created));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:save_checkpoint_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- access_audit.load_checkpoint — the stored checkpoint for a period (for verify),
-- or {"checkpoint": null}. pi_data = { "period": <date> }.
CREATE OR REPLACE PROCEDURE access_audit.load_checkpoint(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = access_audit, util, pg_temp
AS $$
DECLARE
    v_period date := (pi_data->>'period')::date;
    v_cp     jsonb;
BEGIN
    IF v_period IS NULL THEN
        po_data := util.result_error('access_audit:invalid', 'period is required');
        RETURN;
    END IF;

    SELECT jsonb_build_object(
               'period', retention_period,
               'rowCount', row_count,
               'checkpointSeal', checkpoint_seal,
               'sealedAt', sealed_at)
      INTO v_cp
    FROM access_audit.checkpoint
    WHERE retention_period = v_period;

    po_data := util.result_success(jsonb_build_object('checkpoint', v_cp));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:load_checkpoint_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- access_audit.periods_pending_checkpoint — distinct retention periods strictly
-- before `before` (normally the first of the current month) that hold records
-- but have no checkpoint yet. The retention sweep checkpoints these closed
-- periods before purging. pi_data = { "before": <date> }.
CREATE OR REPLACE PROCEDURE access_audit.periods_pending_checkpoint(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = access_audit, util, pg_temp
AS $$
DECLARE
    v_before  date := (pi_data->>'before')::date;
    v_periods jsonb;
BEGIN
    IF v_before IS NULL THEN
        po_data := util.result_error('access_audit:invalid', 'before is required');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(p ORDER BY p), '[]'::jsonb) INTO v_periods
    FROM (
        SELECT DISTINCT ar.retention_period AS p
        FROM access_audit.access_record ar
        WHERE ar.retention_period < v_before
          AND NOT EXISTS (SELECT 1 FROM access_audit.checkpoint c WHERE c.retention_period = ar.retention_period)
    ) q;

    po_data := util.result_success(jsonb_build_object('periods', v_periods));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:periods_pending_checkpoint_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- access_audit.set_legal_hold — place (hold=true) or clear (hold=false) a legal
-- hold on a data subject; held subjects' records are skipped by purge.
-- pi_data = { "subject": <ref>, "hold": <bool>, "reason": <text>, "placed_by": <ref> }.
CREATE OR REPLACE PROCEDURE access_audit.set_legal_hold(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = access_audit, util, pg_temp
AS $$
DECLARE
    v_subject text := pi_data->>'subject';
    v_hold    boolean := COALESCE((pi_data->>'hold')::boolean, true);
BEGIN
    IF v_subject IS NULL OR v_subject = '' THEN
        po_data := util.result_error('access_audit:invalid', 'subject is required');
        RETURN;
    END IF;

    IF v_hold THEN
        INSERT INTO access_audit.legal_hold (subject, reason, placed_by)
        VALUES (v_subject, COALESCE(pi_data->>'reason', ''), COALESCE(pi_data->>'placed_by', ''))
        ON CONFLICT (subject) DO UPDATE
            SET reason = EXCLUDED.reason, placed_by = EXCLUDED.placed_by, placed_at = now();
    ELSE
        DELETE FROM access_audit.legal_hold WHERE subject = v_subject;
    END IF;

    po_data := util.result_success(jsonb_build_object('subject', v_subject, 'hold', v_hold));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:set_legal_hold_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- access_audit.purge_expired — delete records in retention periods strictly
-- older than the cutoff, EXCEPT records touching a legally-held subject. This is
-- the only path allowed to DELETE (it sets the session-local guard the
-- append-only trigger checks). The fact of purge is reported back so the service
-- can emit the purge audit/security event.
-- pi_data = { "cutoff": <date> }  (the oldest period to RETAIN; older is purged).
CREATE OR REPLACE PROCEDURE access_audit.purge_expired(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = access_audit, util, pg_temp
AS $$
DECLARE
    v_cutoff   date := (pi_data->>'cutoff')::date;
    v_purged   bigint := 0;
    v_retained bigint := 0;
BEGIN
    IF v_cutoff IS NULL THEN
        po_data := util.result_error('access_audit:invalid', 'cutoff is required');
        RETURN;
    END IF;

    -- Count what is retained under legal hold (before deleting the rest).
    SELECT count(*) INTO v_retained
    FROM access_audit.access_record ar
    WHERE ar.retention_period < v_cutoff
      AND EXISTS (SELECT 1 FROM access_audit.legal_hold h WHERE h.subject = ANY(ar.data_subjects));

    -- Permit the guard trigger to allow DELETE for this transaction only.
    PERFORM set_config('access_audit.allow_purge', 'on', true);

    WITH del AS (
        DELETE FROM access_audit.access_record ar
        WHERE ar.retention_period < v_cutoff
          AND NOT EXISTS (SELECT 1 FROM access_audit.legal_hold h WHERE h.subject = ANY(ar.data_subjects))
        RETURNING 1
    )
    SELECT count(*) INTO v_purged FROM del;

    PERFORM set_config('access_audit.allow_purge', 'off', true);

    po_data := util.result_success(jsonb_build_object(
        'cutoff', v_cutoff, 'purged', v_purged, 'retainedUnderHold', v_retained));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:purge_expired_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- Ownership: every procedure runs as the table owner (the migrating role).

-- EXECUTE-only: revoke from PUBLIC, grant only to the service role.
REVOKE ALL ON PROCEDURE access_audit.append_record(jsonb, jsonb)      FROM PUBLIC;
REVOKE ALL ON PROCEDURE access_audit.records_by_subject(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE access_audit.seals_for_period(jsonb, jsonb)   FROM PUBLIC;
REVOKE ALL ON PROCEDURE access_audit.save_checkpoint(jsonb, jsonb)    FROM PUBLIC;
REVOKE ALL ON PROCEDURE access_audit.load_checkpoint(jsonb, jsonb)    FROM PUBLIC;
REVOKE ALL ON PROCEDURE access_audit.periods_pending_checkpoint(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE access_audit.set_legal_hold(jsonb, jsonb)     FROM PUBLIC;
REVOKE ALL ON PROCEDURE access_audit.purge_expired(jsonb, jsonb)      FROM PUBLIC;

GRANT EXECUTE ON PROCEDURE access_audit.append_record(jsonb, jsonb)      TO access_audit_public;
GRANT EXECUTE ON PROCEDURE access_audit.records_by_subject(jsonb, jsonb) TO access_audit_public;
GRANT EXECUTE ON PROCEDURE access_audit.seals_for_period(jsonb, jsonb)   TO access_audit_public;
GRANT EXECUTE ON PROCEDURE access_audit.save_checkpoint(jsonb, jsonb)    TO access_audit_public;
GRANT EXECUTE ON PROCEDURE access_audit.load_checkpoint(jsonb, jsonb)    TO access_audit_public;
GRANT EXECUTE ON PROCEDURE access_audit.periods_pending_checkpoint(jsonb, jsonb) TO access_audit_public;
GRANT EXECUTE ON PROCEDURE access_audit.set_legal_hold(jsonb, jsonb)     TO access_audit_public;
GRANT EXECUTE ON PROCEDURE access_audit.purge_expired(jsonb, jsonb)      TO access_audit_public;
