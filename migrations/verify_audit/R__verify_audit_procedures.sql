-- R: repeatable migration — the verify_audit store API (2 procedures).
--
-- These back the audit service's verify-evidence surface. They run as the
-- migrating role (the owner of the tables), so the EXECUTE-only service role
-- drives them without any table privileges. Each uses the uniform JSONB
-- envelope `(pi_data jsonb, INOUT po_data jsonb)`, pins `search_path` ending
-- in pg_temp, returns util.result_success / util.result_error with
-- `<domain>:<reason>` codes, and validates BEFORE any write.
-- Re-applied automatically whenever the checksum changes.

-- verify_audit.record_event — append one abuse-evidence event.
-- pi_data = { "event": { "ts", "ip", "userAgent", "sizeBytes", "sha256",
--                        "verdict", "correlationId", "sessionId" },
--             "source_service": <authenticated caller> }.
CREATE OR REPLACE PROCEDURE verify_audit.record_event(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = verify_audit, util, pg_temp
AS $$
DECLARE
    v_ev       jsonb := pi_data->'event';
    v_occurred timestamptz;
    v_row_id   text;
BEGIN
    -- Pattern A validation (before any write).
    IF v_ev IS NULL OR jsonb_typeof(v_ev) <> 'object' THEN
        po_data := util.result_error('verify_audit:invalid', 'event object is required');
        RETURN;
    END IF;
    IF COALESCE(v_ev->>'verdict', '') = '' THEN
        po_data := util.result_error('verify_audit:invalid', 'event.verdict is required');
        RETURN;
    END IF;

    v_occurred := COALESCE((v_ev->>'ts')::timestamptz, now());

    INSERT INTO verify_audit.verify_event (
        occurred_at, ip, user_agent, size_bytes, sha256, verdict,
        correlation_id, session_id, source_service
    )
    VALUES (
        v_occurred,
        NULLIF(v_ev->>'ip', ''),
        NULLIF(v_ev->>'userAgent', ''),
        COALESCE((v_ev->>'sizeBytes')::bigint, 0),
        NULLIF(v_ev->>'sha256', ''),
        v_ev->>'verdict',
        NULLIF(v_ev->>'correlationId', ''),
        NULLIF(v_ev->>'sessionId', ''),
        NULLIF(pi_data->>'source_service', '')
    )
    RETURNING row_id INTO v_row_id;

    po_data := util.result_success(jsonb_build_object('eventId', v_row_id));
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('verify_audit:record_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- verify_audit.sweep_retention — delete events older than the retention
-- window. pi_data = { "retention_days": int }. The window is proportionality
-- for the personal data (IP / user agent) the evidence carries.
CREATE OR REPLACE PROCEDURE verify_audit.sweep_retention(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = verify_audit, util, pg_temp
AS $$
DECLARE
    v_days   int := (pi_data->>'retention_days')::int;
    v_cutoff timestamptz;
    v_purged bigint;
BEGIN
    IF v_days IS NULL OR v_days < 1 THEN
        po_data := util.result_error('verify_audit:invalid', 'retention_days (>= 1) is required');
        RETURN;
    END IF;

    v_cutoff := now() - make_interval(days => v_days);

    -- Unlock the append-only guard for this transaction only.
    PERFORM set_config('verify_audit.allow_purge', 'on', true);

    DELETE FROM verify_audit.verify_event WHERE occurred_at < v_cutoff;
    GET DIAGNOSTICS v_purged = ROW_COUNT;

    PERFORM set_config('verify_audit.allow_purge', '', true);

    po_data := util.result_success(jsonb_build_object(
        'cutoff', to_char(v_cutoff AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'purged', v_purged));
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('verify_audit:sweep_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- The EXECUTE-only service role drives exactly these two procedures.
-- PostgreSQL grants EXECUTE on a new procedure to PUBLIC by default, so the
-- REVOKE is what actually closes it: without these two lines every role able to
-- connect could call record_event (write an audit row) and sweep_retention
-- (delete audit rows by retention) — evidence forging and evidence destruction,
-- in the schema whose only purpose is evidence. The GRANT alone adds nothing.
REVOKE ALL ON PROCEDURE verify_audit.record_event(jsonb, jsonb)    FROM PUBLIC;
REVOKE ALL ON PROCEDURE verify_audit.sweep_retention(jsonb, jsonb) FROM PUBLIC;

GRANT EXECUTE ON PROCEDURE verify_audit.record_event(jsonb, jsonb)    TO access_audit_public;
GRANT EXECUTE ON PROCEDURE verify_audit.sweep_retention(jsonb, jsonb) TO access_audit_public;
