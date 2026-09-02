-- R: repeatable migration — the eidas_audit store API.
--
-- These back the store.Store interface the eidas-audit service uses. They run as
-- the migrating role (the owner of the table), so the EXECUTE-only `eidas_audit_public`
-- service role drives them without any table privileges. Each:
--   * uses the uniform JSONB envelope `(pi_data jsonb, INOUT po_data jsonb)`,
--   * pins `search_path` ending in pg_temp (SECURITY DEFINER hardening),
--   * returns a structured result via util.result_success / util.result_error
--     with `<domain>:<reason>` error codes,
--   * validates BEFORE any write (Pattern A: return) and, on any unexpected error
--     after a write, re-raises a structured error with SQLSTATE P0001 (Pattern B)
--     so the transaction ROLLS BACK.
--
-- The HASH-CHAIN is built in Go (the sink): it reads `chain_head`, computes
-- hash = SHA-256(canonical(event) || prev_hash), and passes prev_hash + hash into
-- `append_event`. The DB VERIFIES the linkage (prev_hash == current head) and
-- stores the values; it does not recompute the hash (verification of the whole
-- chain is a Go-side walk). The sink takes `lock_chain` first, in the same transaction,
-- so read-head → append is atomic across replicas. Re-applied by Flyway whenever the
-- checksum changes.

-- eidas_audit.append_event — append one signing-evidence event to the hash-chain
-- (idempotent on event_id, so a JetStream redelivery never duplicates).
-- pi_data = { "event": <broker.Envelope>, "prev_hash": <hex|"">, "hash": <hex>,
--             "source_service": <publishing service> }.
CREATE OR REPLACE PROCEDURE eidas_audit.append_event(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = eidas_audit, util, pg_temp
AS $$
DECLARE
    v_event      jsonb := pi_data->'event';
    v_event_id   text  := v_event->>'event_id';
    v_hash       text  := pi_data->>'hash';
    v_prev       text  := COALESCE(pi_data->>'prev_hash', '');
    v_occurred   timestamptz;
    v_categories text[];
    v_subjects   text[];
    v_head       text;
    v_row_id     text;
BEGIN
    -- Pattern A validation (before any write).
    IF v_event IS NULL OR jsonb_typeof(v_event) <> 'object' THEN
        po_data := util.result_error('eidas_audit:invalid', 'event object is required');
        RETURN;
    END IF;
    IF v_event_id IS NULL OR v_event_id = '' THEN
        po_data := util.result_error('eidas_audit:invalid', 'event.event_id is required');
        RETURN;
    END IF;
    IF COALESCE(v_event->>'event_type', '') = '' THEN
        po_data := util.result_error('eidas_audit:invalid', 'event.event_type is required');
        RETURN;
    END IF;
    IF COALESCE(v_event->>'outcome', '') = '' THEN
        po_data := util.result_error('eidas_audit:invalid', 'event.outcome is required');
        RETURN;
    END IF;
    IF v_hash IS NULL OR v_hash = '' THEN
        po_data := util.result_error('eidas_audit:invalid', 'hash is required');
        RETURN;
    END IF;

    -- Serialize chain appends so the head read below is stable for this insert
    -- (a multi-replica consumer cannot interleave two appends on the same chain).
    PERFORM pg_advisory_xact_lock(hashtext('eidas_audit.audit_event_chain'));

    -- Idempotency: a redelivered event is success, not an error.
    SELECT row_id INTO v_row_id FROM eidas_audit.audit_event WHERE event_id = v_event_id;
    IF v_row_id IS NOT NULL THEN
        po_data := util.result_success(jsonb_build_object('eventId', v_event_id, 'rowId', v_row_id, 'duplicate', true));
        RETURN;
    END IF;

    -- Chain linkage check against the current head.
    SELECT hash INTO v_head FROM eidas_audit.audit_event ORDER BY seq DESC LIMIT 1;
    IF v_head IS NULL THEN
        IF v_prev <> '' THEN
            po_data := util.result_error('eidas_audit:chain_mismatch', 'genesis event must carry an empty prev_hash');
            RETURN;
        END IF;
    ELSIF v_prev <> v_head THEN
        -- Stale head (the chain advanced since the sink read it): the sink retries
        -- with the new head. A persistent mismatch indicates tampering / a bug.
        po_data := util.result_error('eidas_audit:chain_mismatch', 'prev_hash does not match the current chain head');
        RETURN;
    END IF;

    v_occurred   := COALESCE((v_event->>'occurred_at')::timestamptz, now());
    v_categories := ARRAY(SELECT jsonb_array_elements_text(COALESCE(v_event->'category', '[]'::jsonb)));
    v_subjects   := ARRAY(SELECT jsonb_array_elements_text(COALESCE(v_event->'data_subjects', '[]'::jsonb)));

    INSERT INTO eidas_audit.audit_event (
        event_id, occurred_at, source_service, event_type, categories, operation, outcome,
        actor_id, actor_type, actor_assurance, resource_type, resource_id,
        correlation_id, trace_id, ip, device, data_subjects, prev_hash, hash, content
    )
    VALUES (
        v_event_id,
        v_occurred,
        NULLIF(pi_data->>'source_service', ''),
        v_event->>'event_type',
        v_categories,
        v_event->>'operation',
        v_event->>'outcome',
        v_event#>>'{actor,id}',
        v_event#>>'{actor,type}',
        v_event#>>'{actor,assurance}',
        v_event#>>'{resource,type}',
        v_event#>>'{resource,id}',
        v_event->>'correlation_id',
        v_event->>'trace_id',
        v_event->>'ip',
        v_event->>'device',
        v_subjects,
        v_prev,
        v_hash,
        v_event
    )
    RETURNING row_id INTO v_row_id;

    po_data := util.result_success(jsonb_build_object('eventId', v_event_id, 'rowId', v_row_id, 'duplicate', false, 'hash', v_hash));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('eidas_audit:append_event_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- eidas_audit.chain_head — the current chain head (latest hash + seq), or
-- {"head": null} for an empty chain (genesis). The sink reads this to build the
-- next link. pi_data = {} (single global chain).
CREATE OR REPLACE PROCEDURE eidas_audit.chain_head(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = eidas_audit, util, pg_temp
AS $$
DECLARE
    v_head jsonb;
BEGIN
    SELECT jsonb_build_object('hash', hash, 'seq', seq, 'eventId', event_id)
      INTO v_head
    FROM eidas_audit.audit_event
    ORDER BY seq DESC
    LIMIT 1;

    po_data := util.result_success(jsonb_build_object('head', v_head));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('eidas_audit:chain_head_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- eidas_audit.lock_chain — take the chain's append lock for the rest of the caller's
-- transaction. The sink builds a link in two steps (read the head, then append with
-- prev_hash = that head); two appenders doing that concurrently both read the same head,
-- and the second is refused as a chain_mismatch — correct, but wasteful, and under
-- sustained concurrency the refusals outnumber the appends. Calling this first, inside
-- one transaction with chain_head and append_event, makes read-then-append atomic: the
-- lock is the same one append_event takes (re-entrant within the transaction), it is
-- released at commit or rollback, and nothing else changes. pi_data = {}.
CREATE OR REPLACE PROCEDURE eidas_audit.lock_chain(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = eidas_audit, util, pg_temp
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('eidas_audit.audit_event_chain'));

    po_data := util.result_success(jsonb_build_object('locked', true));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('eidas_audit:lock_chain_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- eidas_audit.get_event — fetch one event (verbatim envelope + chain links) by
-- event_id, for the future verify / read API. pi_data = { "event_id": <ulid> }.
CREATE OR REPLACE PROCEDURE eidas_audit.get_event(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = eidas_audit, util, pg_temp
AS $$
DECLARE
    v_event_id text := pi_data->>'event_id';
    v_row      jsonb;
BEGIN
    IF v_event_id IS NULL OR v_event_id = '' THEN
        po_data := util.result_error('eidas_audit:invalid', 'event_id is required');
        RETURN;
    END IF;

    SELECT jsonb_build_object(
               'rowId', row_id, 'seq', seq, 'eventId', event_id,
               'prevHash', prev_hash, 'hash', hash, 'content', content)
      INTO v_row
    FROM eidas_audit.audit_event
    WHERE event_id = v_event_id;

    IF v_row IS NULL THEN
        po_data := util.result_error('eidas_audit:not_found', 'no audit event for that event_id');
        RETURN;
    END IF;

    po_data := util.result_success(v_row);
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('eidas_audit:get_event_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- eidas_audit.sweep_retention — DEFERRED (skeleton stub). eIDAS-audit is legal
-- evidence with a long/indefinite retention, so for the MVP this is a no-op that
-- reports nothing was purged. When implemented it will drop whole closed
-- partitions older than a policy TTL (setting `eidas_audit.allow_purge` for the
-- guard trigger) and emit a purge audit event. pi_data = { ... }.
CREATE OR REPLACE PROCEDURE eidas_audit.sweep_retention(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = eidas_audit, util, pg_temp
AS $$
BEGIN
    po_data := util.result_success(jsonb_build_object('deferred', true, 'purged', 0));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('eidas_audit:sweep_retention_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- Ownership: every procedure runs as the table owner (the migrating role).

-- EXECUTE-only: revoke from PUBLIC, grant only to the service role.
REVOKE ALL ON PROCEDURE eidas_audit.append_event(jsonb, jsonb)    FROM PUBLIC;
REVOKE ALL ON PROCEDURE eidas_audit.chain_head(jsonb, jsonb)      FROM PUBLIC;
REVOKE ALL ON PROCEDURE eidas_audit.lock_chain(jsonb, jsonb)      FROM PUBLIC;
REVOKE ALL ON PROCEDURE eidas_audit.get_event(jsonb, jsonb)       FROM PUBLIC;
REVOKE ALL ON PROCEDURE eidas_audit.sweep_retention(jsonb, jsonb) FROM PUBLIC;

GRANT EXECUTE ON PROCEDURE eidas_audit.append_event(jsonb, jsonb)    TO eidas_audit_public;
GRANT EXECUTE ON PROCEDURE eidas_audit.chain_head(jsonb, jsonb)      TO eidas_audit_public;
GRANT EXECUTE ON PROCEDURE eidas_audit.lock_chain(jsonb, jsonb)      TO eidas_audit_public;
GRANT EXECUTE ON PROCEDURE eidas_audit.get_event(jsonb, jsonb)       TO eidas_audit_public;
GRANT EXECUTE ON PROCEDURE eidas_audit.sweep_retention(jsonb, jsonb) TO eidas_audit_public;
