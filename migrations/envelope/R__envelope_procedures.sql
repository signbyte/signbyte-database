-- R: repeatable migration — the envelope store API (`envelope` schema).
--
-- These back the store.Store interface the envelope service uses. They run as
-- the table owner (the migrating role), so the EXECUTE-only `envelope_public` role drives
-- them without any table privileges. Each:
--   * uses the uniform JSONB envelope `(pi_data jsonb, INOUT po_data jsonb)`,
--   * pins `search_path` ending in pg_temp (SECURITY DEFINER hardening),
--   * returns a structured result via util.result_success / util.result_error with
--     `<domain>:<reason>` codes (`:not_found` → 404, else 422),
--   * validates BEFORE any write (Pattern A: return) and, on any unexpected error
--     after a write, re-raises a structured error with SQLSTATE P0001 (Pattern B) so
--     the transaction ROLLS BACK.
--
-- The split: apply_transition is THICK apply + THIN decide — Go
-- decides the target status, the proc applies it atomically with the optimistic
-- `version` CAS + the CHECK(status) so a transition can't be lost/doubled. The rest
-- are thin persistence/read wrappers; the orchestration logic stays in Go.
--
-- USER-FACING procs take `owner` (the caller's person sub) and grant the OWNER full
-- access (no IDOR — `:not_found` for absent-or-not-owned). The signer-side procs
-- (get_envelope, slot_eligible, set_slot_job, decline_slot) additionally take the
-- caller's authenticated eIDAS `caller_serial` and grant a PARTICIPANT (the co-signer
-- leg): a caller whose serial matches a slot's identity_ref on a NON-DRAFT
-- envelope may READ the envelope (any slot matches) and ACT on THAT slot (eligibility /
-- job / decline) — and nothing else. A non-match stays `:not_found` (no enumeration),
-- and an empty caller_serial never matches (so a NULL identity_ref grants nobody). The
-- orchestrator CALLBACK proc `mark_slot_signed` is NOT owner-scoped (signflow, not the
-- owner, calls it) — keyed by (envelope_id, slot_id) and idempotent.

-- envelope.create_envelope — create a draft envelope.
-- pi_data = { owner, [tenant_id], [title], [order_policy], [profile], [expiry] }.
CREATE OR REPLACE PROCEDURE envelope.create_envelope(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_owner  text := pi_data->>'owner';
    v_policy text := COALESCE(NULLIF(pi_data->>'order_policy', ''), 'parallel');
    v_id     text;
BEGIN
    IF v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'owner is required'); RETURN;
    END IF;
    IF v_policy NOT IN ('parallel', 'sequential') THEN
        po_data := util.result_error('envelope:invalid', 'order_policy must be parallel or sequential'); RETURN;
    END IF;

    INSERT INTO envelope.envelope (owner, tenant_id, title, order_policy, profile, expiry)
    VALUES (
        v_owner,
        NULLIF(pi_data->>'tenant_id', ''),
        NULLIF(pi_data->>'title', ''),
        v_policy,
        NULLIF(pi_data->>'profile', ''),
        CASE WHEN NULLIF(pi_data->>'expiry', '') IS NULL THEN NULL ELSE (pi_data->>'expiry')::timestamptz END
    )
    RETURNING id INTO v_id;

    po_data := util.result_success(jsonb_build_object('id', v_id, 'status', 'draft', 'version', 0));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:create_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.get_envelope — one envelope + its slots + document refs. The OWNER may read
-- it; a PARTICIPANT (caller_serial matches a slot's identity_ref on a non-draft envelope)
-- may also read it. Fail-closed: a non-match is `:not_found`.
-- pi_data = { id, owner, [caller_serial] }.
CREATE OR REPLACE PROCEDURE envelope.get_envelope(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_id     text := pi_data->>'id';
    v_owner  text := pi_data->>'owner';
    v_serial text := NULLIF(pi_data->>'caller_serial', '');
    v_row    jsonb;
BEGIN
    IF v_id IS NULL OR v_id = '' OR v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'id and owner are required'); RETURN;
    END IF;

    SELECT jsonb_build_object(
        'envelope', to_jsonb(e),
        'slots', COALESCE((
            SELECT jsonb_agg(to_jsonb(s) ORDER BY s.order_index)
            FROM envelope.signer_slot s WHERE s.envelope_id = e.id), '[]'::jsonb),
        'documents', COALESCE((
            SELECT jsonb_agg(to_jsonb(d) ORDER BY d.added_at)
            FROM envelope.envelope_document d WHERE d.envelope_id = e.id), '[]'::jsonb)
    )
    INTO v_row
    FROM envelope.envelope e
    WHERE e.id = v_id
      AND (
          e.owner = v_owner
          OR (v_serial IS NOT NULL AND e.status <> 'draft' AND EXISTS (
              SELECT 1 FROM envelope.signer_slot s2
              WHERE s2.envelope_id = e.id AND s2.identity_ref = v_serial))
      );

    IF v_row IS NULL THEN
        po_data := util.result_error('envelope:not_found', 'envelope not found'); RETURN;
    END IF;

    po_data := util.result_success(v_row);
END
$$;

-- envelope.list_envelopes — the caller's envelopes, keyset-paged (ULID id DESC).
-- pi_data = { owner, [limit], [cursor], [include_expired] }.  cursor = the last id
-- of the prior page. Expired envelopes are excluded by default (mirroring the
-- document listing): once retention has expired an envelope, the durable record
-- (history / audit) is its home, and serving it in the live listing renders a
-- workflow that can no longer be acted on. Pass include_expired=true to see them.
CREATE OR REPLACE PROCEDURE envelope.list_envelopes(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_owner   text    := pi_data->>'owner';
    v_limit   integer := LEAST(COALESCE((pi_data->>'limit')::integer, 50), 200);
    v_cursor  text    := NULLIF(pi_data->>'cursor', '');
    v_expired boolean := COALESCE((pi_data->>'include_expired')::boolean, false);
    v_rows    jsonb;
BEGIN
    IF v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'owner is required'); RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id DESC), '[]'::jsonb)
    INTO v_rows
    FROM (
        SELECT e.id, e.owner, e.tenant_id, e.title, e.status, e.order_policy,
               e.profile, e.expiry, e.version, e.created_at, e.updated_at,
               -- The envelope's document refs (document-store ids), so a
               -- listing consumer can tell which documents an envelope covers
               -- without fetching each envelope's detail view.
               (SELECT COALESCE(jsonb_agg(ed.document_id ORDER BY ed.document_id), '[]'::jsonb)
                  FROM envelope.envelope_document ed
                 WHERE ed.envelope_id = e.id)                      AS doc_ids,
               -- Progress projection for the owner's listing: how many of the
               -- envelope's slots have signed, and whether it is the owner's turn.
               (SELECT count(*) FROM envelope.signer_slot s
                 WHERE s.envelope_id = e.id)                       AS slot_count,
               (SELECT count(*) FROM envelope.signer_slot s
                 WHERE s.envelope_id = e.id AND s.status = 'signed') AS signed_count,
               -- your_turn: the envelope is actionable AND the owner has an outstanding,
               -- order-eligible slot of their own (identity_ref IS NULL — a slot bound to
               -- no counterparty). Parallel: any such slot; sequential: only once every
               -- lower-order slot is signed (mirrors list_signing_tasks for the co-signer).
               (e.status IN ('sent', 'in_progress') AND EXISTS (
                   SELECT 1 FROM envelope.signer_slot s
                   WHERE s.envelope_id = e.id
                     AND s.identity_ref IS NULL
                     AND s.status IN ('draft', 'sent', 'in_progress')
                     AND (e.order_policy = 'parallel' OR NOT EXISTS (
                         SELECT 1 FROM envelope.signer_slot lo
                         WHERE lo.envelope_id = e.id
                           AND lo.order_index < s.order_index
                           AND lo.status <> 'signed'))
               ))                                                  AS your_turn
        FROM envelope.envelope e
        WHERE e.owner = v_owner
          AND (v_expired OR e.status <> 'expired')
          AND (v_cursor IS NULL OR e.id < v_cursor)
        ORDER BY e.id DESC
        LIMIT v_limit
    ) t;

    po_data := util.result_success(jsonb_build_object('envelopes', v_rows));
END
$$;

-- envelope.find_envelopes_for_document — the envelopes covering ONE document that the
-- CALLER may see: the OWNER always; a PARTICIPANT (caller_serial matches a slot's
-- identity_ref) on a non-draft envelope. Newest first. Lets a document-centric view
-- resolve "which envelope carries this document?" without listing everything — and it
-- works for a participant revisiting a completed document, who is neither the owner
-- nor holds an outstanding signing task. Read-only.
-- pi_data = { owner, [caller_serial], document_id, [limit] }.
CREATE OR REPLACE PROCEDURE envelope.find_envelopes_for_document(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_owner  text    := pi_data->>'owner';
    v_serial text    := NULLIF(pi_data->>'caller_serial', '');
    v_doc    text    := pi_data->>'document_id';
    v_limit  integer := LEAST(COALESCE((pi_data->>'limit')::integer, 10), 50);
    v_rows   jsonb;
BEGIN
    IF v_owner IS NULL OR v_owner = '' OR v_doc IS NULL OR v_doc = '' THEN
        po_data := util.result_error('envelope:invalid', 'owner and document_id are required'); RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id DESC), '[]'::jsonb)
    INTO v_rows
    FROM (
        SELECT e.id, e.owner, e.tenant_id, e.title, e.status, e.order_policy,
               e.profile, e.expiry, e.version, e.created_at, e.updated_at,
               (SELECT COALESCE(jsonb_agg(ed.document_id ORDER BY ed.document_id), '[]'::jsonb)
                  FROM envelope.envelope_document ed
                 WHERE ed.envelope_id = e.id)                      AS doc_ids,
               (SELECT count(*) FROM envelope.signer_slot s
                 WHERE s.envelope_id = e.id)                       AS slot_count,
               (SELECT count(*) FROM envelope.signer_slot s
                 WHERE s.envelope_id = e.id AND s.status = 'signed') AS signed_count,
               -- your_turn is computed for the CALLER: the owner's outstanding own slot
               -- (identity_ref IS NULL), or the matched participant's outstanding slot —
               -- each only when order-eligible under the envelope's policy.
               (e.status IN ('sent', 'in_progress') AND EXISTS (
                   SELECT 1 FROM envelope.signer_slot s
                   WHERE s.envelope_id = e.id
                     AND ((e.owner = v_owner AND s.identity_ref IS NULL)
                          OR (v_serial IS NOT NULL AND s.identity_ref = v_serial))
                     AND s.status IN ('draft', 'sent', 'in_progress')
                     AND (e.order_policy = 'parallel' OR NOT EXISTS (
                         SELECT 1 FROM envelope.signer_slot lo
                         WHERE lo.envelope_id = e.id
                           AND lo.order_index < s.order_index
                           AND lo.status <> 'signed'))
               ))                                                  AS your_turn
        FROM envelope.envelope e
        WHERE EXISTS (
                  SELECT 1 FROM envelope.envelope_document ed
                  WHERE ed.envelope_id = e.id AND ed.document_id = v_doc)
          AND (
              e.owner = v_owner
              OR (v_serial IS NOT NULL AND e.status <> 'draft' AND EXISTS (
                  SELECT 1 FROM envelope.signer_slot s2
                  WHERE s2.envelope_id = e.id AND s2.identity_ref = v_serial))
          )
        ORDER BY e.id DESC
        LIMIT v_limit
    ) t;

    po_data := util.result_success(jsonb_build_object('envelopes', v_rows));
END
$$;

-- envelope.list_signing_tasks — the SIGNER INBOX (the co-signer leg):
-- non-draft envelopes where the CALLER is an invited signer — a slot's identity_ref matches
-- the caller's authenticated eIDAS `caller_serial` — and that slot's signature is still
-- OUTSTANDING (slot status draft/sent/in_progress), i.e. "awaiting your signature". Keyed on
-- the SERIAL, not the owner, so a co-signer (a different person from the owner) discovers the
-- envelope they were invited to. Envelopes the caller OWNS are excluded (they list under
-- list_envelopes — no double-listing). Each task carries the caller's own slot and `your_turn`
-- (the order-policy eligibility: always true for a parallel envelope; for a sequential one,
-- true only once every lower-order slot is signed) so the inbox can tell "your turn" from
-- "waiting for earlier signers". Fail-closed: an empty caller_serial matches nobody.
-- pi_data = { caller_serial, [owner], [limit], [cursor] }.  cursor = the last envelope id of the prior page.
CREATE OR REPLACE PROCEDURE envelope.list_signing_tasks(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_serial text    := NULLIF(pi_data->>'caller_serial', '');
    v_owner  text    := NULLIF(pi_data->>'owner', '');
    v_limit  integer := LEAST(COALESCE((pi_data->>'limit')::integer, 50), 200);
    v_cursor text    := NULLIF(pi_data->>'cursor', '');
    v_rows   jsonb;
BEGIN
    IF v_serial IS NULL THEN
        po_data := util.result_error('envelope:invalid', 'caller_serial is required'); RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(t.task ORDER BY t.id DESC, t.order_index), '[]'::jsonb)
    INTO v_rows
    FROM (
        SELECT e.id, s.order_index,
            jsonb_build_object(
                -- The task's envelope carries its document refs (doc_ids), same as
                -- list_envelopes: a listing consumer composing envelopes and standalone
                -- documents into one view needs to know which chains an invited
                -- envelope covers, or the shared document double-renders for a signer.
                'envelope', to_jsonb(e) || jsonb_build_object('doc_ids',
                    (SELECT COALESCE(jsonb_agg(ed.document_id ORDER BY ed.document_id), '[]'::jsonb)
                       FROM envelope.envelope_document ed
                      WHERE ed.envelope_id = e.id)),
                'slot', to_jsonb(s),
                'your_turn',
                CASE
                    WHEN e.order_policy = 'parallel' THEN true
                    ELSE NOT EXISTS (
                        SELECT 1 FROM envelope.signer_slot lo
                        WHERE lo.envelope_id = e.id
                          AND lo.order_index < s.order_index
                          AND lo.status <> 'signed')
                END
            ) AS task
        FROM envelope.envelope e
        JOIN envelope.signer_slot s ON s.envelope_id = e.id
        WHERE s.identity_ref = v_serial
          AND e.status IN ('sent', 'in_progress')
          AND s.status IN ('draft', 'sent', 'in_progress')
          AND (v_owner IS NULL OR e.owner <> v_owner)
          AND (v_cursor IS NULL OR e.id < v_cursor)
        ORDER BY e.id DESC, s.order_index
        LIMIT v_limit
    ) t;

    po_data := util.result_success(jsonb_build_object('tasks', v_rows));
END
$$;

-- envelope.attach_document — pin a document ref onto a DRAFT envelope (owner-filtered).
-- pi_data = { envelope_id, owner, document_id, content_hash }.
CREATE OR REPLACE PROCEDURE envelope.attach_document(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_env    text := pi_data->>'envelope_id';
    v_owner  text := pi_data->>'owner';
    v_doc    text := pi_data->>'document_id';
    v_hash   text := pi_data->>'content_hash';
    v_status text;
BEGIN
    IF v_env IS NULL OR v_env = '' OR v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'envelope_id and owner are required'); RETURN;
    END IF;
    IF v_doc IS NULL OR v_doc = '' OR v_hash IS NULL OR v_hash = '' THEN
        po_data := util.result_error('envelope:invalid', 'document_id and content_hash are required'); RETURN;
    END IF;

    SELECT status INTO v_status FROM envelope.envelope WHERE id = v_env AND owner = v_owner;
    IF v_status IS NULL THEN
        po_data := util.result_error('envelope:not_found', 'envelope not found'); RETURN;
    END IF;
    IF v_status <> 'draft' THEN
        po_data := util.result_error('envelope:invalid', 'documents can only be attached to a draft envelope'); RETURN;
    END IF;

    INSERT INTO envelope.envelope_document (envelope_id, document_id, content_hash)
    VALUES (v_env, v_doc, v_hash);

    po_data := util.result_success(jsonb_build_object('envelope_id', v_env, 'document_id', v_doc));
EXCEPTION
    WHEN unique_violation THEN
        po_data := util.result_error('envelope:duplicate', 'document already attached');
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:attach_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.add_slot — add a signer slot to a DRAFT envelope (owner-filtered).
-- pi_data = { envelope_id, owner, order_index, [identity_ref], [role], [flow],
--             [required_loa], [max_signer_slots] }.
-- max_signer_slots caps how many 'signer' slots one envelope may hold; the calling
-- service owns that number and sends it. Counted, never derived from order_index:
-- callers number their slots from 0 or from 1 as they please, so an index bound
-- would refuse a slot that is inside the limit.
CREATE OR REPLACE PROCEDURE envelope.add_slot(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_env    text    := pi_data->>'envelope_id';
    v_owner  text    := pi_data->>'owner';
    v_idx    integer := (pi_data->>'order_index')::integer;
    v_role   text    := COALESCE(NULLIF(pi_data->>'role', ''), 'signer');
    v_flow   text    := NULLIF(pi_data->>'flow', '');
    v_max    integer := COALESCE((pi_data->>'max_signer_slots')::integer, 2);
    v_status text;
    v_signers integer;
    v_id     text;
BEGIN
    IF v_env IS NULL OR v_env = '' OR v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'envelope_id and owner are required'); RETURN;
    END IF;
    IF v_idx IS NULL THEN
        po_data := util.result_error('envelope:invalid', 'order_index is required'); RETURN;
    END IF;
    IF v_role NOT IN ('signer', 'approver', 'observer') THEN
        po_data := util.result_error('envelope:invalid', 'invalid role'); RETURN;
    END IF;
    IF v_flow IS NOT NULL AND v_flow NOT IN ('webEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'csc') THEN
        po_data := util.result_error('envelope:invalid', 'invalid flow'); RETURN;
    END IF;

    -- FOR UPDATE: the signer count below and the insert must be one decision. Two
    -- concurrent adds would otherwise each read the same count and each insert. The
    -- lock is per envelope, so adds to different envelopes are unaffected.
    SELECT status INTO v_status FROM envelope.envelope WHERE id = v_env AND owner = v_owner FOR UPDATE;
    IF v_status IS NULL THEN
        po_data := util.result_error('envelope:not_found', 'envelope not found'); RETURN;
    END IF;
    IF v_status <> 'draft' THEN
        po_data := util.result_error('envelope:invalid', 'slots can only be added to a draft envelope'); RETURN;
    END IF;

    IF v_role = 'signer' THEN
        SELECT count(*) INTO v_signers
          FROM envelope.signer_slot WHERE envelope_id = v_env AND role = 'signer';
        IF v_signers >= v_max THEN
            po_data := util.result_error('envelope:slot_limit',
                'this envelope already has its signers'); RETURN;
        END IF;
    END IF;

    INSERT INTO envelope.signer_slot (envelope_id, order_index, identity_ref, role, flow, required_loa)
    VALUES (v_env, v_idx, NULLIF(pi_data->>'identity_ref', ''), v_role, v_flow, NULLIF(pi_data->>'required_loa', ''))
    RETURNING id INTO v_id;

    po_data := util.result_success(jsonb_build_object('id', v_id));
EXCEPTION
    WHEN unique_violation THEN
        po_data := util.result_error('envelope:duplicate', 'order_index already used in this envelope');
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:add_slot_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.apply_transition — THICK apply + THIN decide. Go decides the target
-- status; the proc CAS-applies it on the optimistic `version` so a transition can't be
-- lost/doubled. Used for send (draft→sent), cancel, and envelope-level decline.
-- pi_data = { id, owner, expected_version, to_status }.
CREATE OR REPLACE PROCEDURE envelope.apply_transition(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_id      text    := pi_data->>'id';
    v_owner   text    := pi_data->>'owner';
    v_to      text    := pi_data->>'to_status';
    v_expect  integer := (pi_data->>'expected_version')::integer;
    v_newver  integer;
    v_cur     integer;
BEGIN
    IF v_id IS NULL OR v_id = '' OR v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'id and owner are required'); RETURN;
    END IF;
    IF v_expect IS NULL THEN
        po_data := util.result_error('envelope:invalid', 'expected_version is required'); RETURN;
    END IF;
    -- The null test is not redundant: this value is read straight from the
    -- request, so an absent key arrives as NULL, and NULL NOT IN (...)
    -- evaluates to NULL rather than true — without it the branch never fires
    -- for a missing field, and the caller gets whatever the write fails with
    -- instead of the precise refusal this check exists to give.
    IF v_to IS NULL OR v_to NOT IN ('draft', 'sent', 'in_progress', 'completed', 'declined', 'expired', 'cancelled') THEN
        po_data := util.result_error('envelope:invalid', 'invalid to_status'); RETURN;
    END IF;

    UPDATE envelope.envelope
       SET status = v_to, version = version + 1
     WHERE id = v_id AND owner = v_owner AND version = v_expect
     RETURNING version INTO v_newver;

    IF v_newver IS NULL THEN
        SELECT version INTO v_cur FROM envelope.envelope WHERE id = v_id AND owner = v_owner;
        IF v_cur IS NULL THEN
            po_data := util.result_error('envelope:not_found', 'envelope not found'); RETURN;
        END IF;
        po_data := util.result_error('envelope:conflict', 'version conflict'); RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('id', v_id, 'status', v_to, 'version', v_newver));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:transition_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.slot_eligible — order-policy precondition the BFF checks before triggering
-- a slot's signing. sequential ⇒ all lower order_index slots must be 'signed'. The OWNER
-- may check any slot; a PARTICIPANT may check only THEIR slot (caller_serial matches the
-- slot's identity_ref on a non-draft envelope).
-- pi_data = { envelope_id, slot_id, owner, [caller_serial] }.
CREATE OR REPLACE PROCEDURE envelope.slot_eligible(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_env       text := pi_data->>'envelope_id';
    v_slot      text := pi_data->>'slot_id';
    v_owner     text := pi_data->>'owner';
    v_serial    text := NULLIF(pi_data->>'caller_serial', '');
    v_idx       integer;
    v_policy    text;
    v_envstatus text;
    v_slotstat  text;
    v_eligible  boolean := false;
BEGIN
    IF v_env IS NULL OR v_env = '' OR v_slot IS NULL OR v_slot = '' OR v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'envelope_id, slot_id and owner are required'); RETURN;
    END IF;

    SELECT s.order_index, s.status, e.order_policy, e.status
      INTO v_idx, v_slotstat, v_policy, v_envstatus
      FROM envelope.signer_slot s
      JOIN envelope.envelope e ON e.id = s.envelope_id
     WHERE s.envelope_id = v_env AND s.id = v_slot
       AND (
           e.owner = v_owner
           OR (v_serial IS NOT NULL AND e.status <> 'draft' AND s.identity_ref = v_serial)
       );

    IF v_idx IS NULL THEN
        po_data := util.result_error('envelope:not_found', 'slot not found'); RETURN;
    END IF;

    IF v_envstatus IN ('sent', 'in_progress') AND v_slotstat IN ('draft', 'sent', 'in_progress') THEN
        IF v_policy = 'parallel' THEN
            v_eligible := true;
        ELSE
            v_eligible := NOT EXISTS (
                SELECT 1 FROM envelope.signer_slot
                WHERE envelope_id = v_env AND order_index < v_idx AND status <> 'signed');
        END IF;
    END IF;

    po_data := util.result_success(jsonb_build_object('eligible', v_eligible));
END
$$;

-- envelope.set_slot_job — record the signflow job_id on a slot when signing starts +
-- advance the envelope sent→in_progress on first signing. The OWNER may set it on any
-- slot; a PARTICIPANT may set it only on THEIR slot (caller_serial matches the slot's
-- identity_ref on a non-draft envelope).
-- pi_data = { envelope_id, slot_id, owner, job_id, [caller_serial] }.
CREATE OR REPLACE PROCEDURE envelope.set_slot_job(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_env    text := pi_data->>'envelope_id';
    v_slot   text := pi_data->>'slot_id';
    v_owner  text := pi_data->>'owner';
    v_serial text := NULLIF(pi_data->>'caller_serial', '');
    v_job    text := pi_data->>'job_id';
    v_found  text;
BEGIN
    IF v_env IS NULL OR v_env = '' OR v_slot IS NULL OR v_slot = '' OR v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'envelope_id, slot_id and owner are required'); RETURN;
    END IF;
    IF v_job IS NULL OR v_job = '' THEN
        po_data := util.result_error('envelope:invalid', 'job_id is required'); RETURN;
    END IF;

    UPDATE envelope.signer_slot s
       SET job_id = v_job, status = 'in_progress'
      FROM envelope.envelope e
     WHERE s.envelope_id = e.id AND e.id = v_env AND s.id = v_slot
       AND (
           e.owner = v_owner
           OR (v_serial IS NOT NULL AND e.status <> 'draft' AND s.identity_ref = v_serial)
       )
       AND s.status IN ('draft', 'sent', 'in_progress')
     RETURNING s.id INTO v_found;

    IF v_found IS NULL THEN
        po_data := util.result_error('envelope:not_found', 'slot not found or not signable'); RETURN;
    END IF;

    UPDATE envelope.envelope SET status = 'in_progress', version = version + 1
     WHERE id = v_env AND status = 'sent';

    po_data := util.result_success(jsonb_build_object('id', v_found, 'job_id', v_job));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:set_slot_job_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.mark_slot_signed (callback) — the signing orchestrator reports a
-- slot finalized. NOT owner-scoped (signflow, not the owner, calls it); keyed by
-- (envelope_id, slot_id); IDEMPOTENT (a replayed callback is a no-op). Advances the
-- envelope sent→in_progress and, when every slot is 'signed', rolls up to 'completed'.
-- pi_data = { envelope_id, slot_id, signature_id, [signed_doc_ref], [job_id] }.
CREATE OR REPLACE PROCEDURE envelope.mark_slot_signed(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_env      text := pi_data->>'envelope_id';
    v_slot     text := pi_data->>'slot_id';
    v_sig      text := pi_data->>'signature_id';
    v_slotstat text;
    v_envstat  text;
BEGIN
    IF v_env IS NULL OR v_env = '' OR v_slot IS NULL OR v_slot = '' THEN
        po_data := util.result_error('envelope:invalid', 'envelope_id and slot_id are required'); RETURN;
    END IF;
    IF v_sig IS NULL OR v_sig = '' THEN
        po_data := util.result_error('envelope:invalid', 'signature_id is required'); RETURN;
    END IF;

    SELECT status INTO v_slotstat FROM envelope.signer_slot
     WHERE envelope_id = v_env AND id = v_slot;
    IF v_slotstat IS NULL THEN
        po_data := util.result_error('envelope:not_found', 'slot not found'); RETURN;
    END IF;
    IF v_slotstat = 'signed' THEN
        -- idempotent: a replayed callback is a no-op success
        SELECT status INTO v_envstat FROM envelope.envelope WHERE id = v_env;
        po_data := util.result_success(jsonb_build_object('id', v_slot, 'status', 'signed', 'idempotent', true, 'envelope_status', v_envstat,
            'doc_ids', (SELECT COALESCE(jsonb_agg(ed.document_id ORDER BY ed.document_id), '[]'::jsonb)
                          FROM envelope.envelope_document ed WHERE ed.envelope_id = v_env))); RETURN;
    END IF;

    UPDATE envelope.signer_slot
       SET status = 'signed',
           signature_id = v_sig,
           signed_doc_ref = NULLIF(pi_data->>'signed_doc_ref', ''),
           job_id = COALESCE(NULLIF(pi_data->>'job_id', ''), job_id),
           signed_at = now()
     WHERE envelope_id = v_env AND id = v_slot;

    -- advance sent→in_progress on the first signing
    UPDATE envelope.envelope SET status = 'in_progress', version = version + 1
     WHERE id = v_env AND status = 'sent';

    -- Roll up to completed once no slot remains unsigned AND every signature landed
    -- in ONE shared container. Each co-signature merges into the chain's single
    -- container, so the signed slots reference the same one; more than one means the
    -- signatures diverged into separate containers — a wrong result that must NOT read
    -- as "completed". That should be impossible (one container is kept per chain), so
    -- if it ever happens we log loudly and leave the envelope in_progress for
    -- reconciliation rather than asserting a false completion. WARNING (not an error)
    -- so the just-recorded slot signature is not rolled back.
    IF NOT EXISTS (SELECT 1 FROM envelope.signer_slot WHERE envelope_id = v_env AND status <> 'signed') THEN
        IF (SELECT COUNT(DISTINCT signed_doc_ref) FROM envelope.signer_slot
             WHERE envelope_id = v_env AND status = 'signed'
               AND NULLIF(signed_doc_ref, '') IS NOT NULL) > 1 THEN
            RAISE WARNING 'envelope % has signed slots referencing more than one container; not marking completed', v_env;
        ELSE
            UPDATE envelope.envelope SET status = 'completed', version = version + 1
             WHERE id = v_env AND status <> 'completed';
        END IF;
    END IF;

    SELECT status INTO v_envstat FROM envelope.envelope WHERE id = v_env;
    -- doc_ids ride the answer so the caller can administer chain-level state
    -- (e.g. lift the download freeze) when the envelope just went terminal,
    -- without an owner-scoped re-read it has no authority for.
    po_data := util.result_success(jsonb_build_object('id', v_slot, 'status', 'signed', 'envelope_status', v_envstat,
        'doc_ids', (SELECT COALESCE(jsonb_agg(ed.document_id ORDER BY ed.document_id), '[]'::jsonb)
                      FROM envelope.envelope_document ed WHERE ed.envelope_id = v_env)));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:mark_signed_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.decline_slot — a signer declines: slot → declined, envelope → declined
-- (unless already terminal). The OWNER may decline any slot; a PARTICIPANT may decline
-- only THEIR slot (caller_serial matches the slot's identity_ref on a non-draft
-- envelope).
-- pi_data = { envelope_id, slot_id, owner, [caller_serial] }.
CREATE OR REPLACE PROCEDURE envelope.decline_slot(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_env    text := pi_data->>'envelope_id';
    v_slot   text := pi_data->>'slot_id';
    v_owner  text := pi_data->>'owner';
    v_serial text := NULLIF(pi_data->>'caller_serial', '');
    v_found  text;
BEGIN
    IF v_env IS NULL OR v_env = '' OR v_slot IS NULL OR v_slot = '' OR v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('envelope:invalid', 'envelope_id, slot_id and owner are required'); RETURN;
    END IF;

    UPDATE envelope.signer_slot s
       SET status = 'declined'
      FROM envelope.envelope e
     WHERE s.envelope_id = e.id AND e.id = v_env AND s.id = v_slot
       AND (
           e.owner = v_owner
           OR (v_serial IS NOT NULL AND e.status <> 'draft' AND s.identity_ref = v_serial)
       )
       AND s.status <> 'signed'
     RETURNING s.id INTO v_found;

    IF v_found IS NULL THEN
        po_data := util.result_error('envelope:not_found', 'slot not found or already signed'); RETURN;
    END IF;

    UPDATE envelope.envelope SET status = 'declined', version = version + 1
     WHERE id = v_env AND status NOT IN ('declined', 'cancelled', 'completed', 'expired');

    -- envelope_status + doc_ids ride the answer so the caller can administer
    -- chain-level state (e.g. lift the download freeze) when the decline drove
    -- the envelope terminal.
    po_data := util.result_success(jsonb_build_object('id', v_found, 'status', 'declined',
        'envelope_status', (SELECT status FROM envelope.envelope WHERE id = v_env),
        'doc_ids', (SELECT COALESCE(jsonb_agg(ed.document_id ORDER BY ed.document_id), '[]'::jsonb)
                      FROM envelope.envelope_document ed WHERE ed.envelope_id = v_env)));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:decline_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.capture_signer_name — record a participant's display NAME on THEIR own slot,
-- supplied from that person's authenticated session (never a code someone else typed, never
-- the validation answer). The OWNER may name their own (identity-less) slot; a PARTICIPANT
-- may name only THEIR slot (caller_serial matches the slot's identity_ref on a non-draft
-- envelope). Write-once: set only while empty, so a repeated open is a no-op. A non-match /
-- already-named slot is an idempotent success (captured=false) — no enumeration, no churn.
-- pi_data = { envelope_id, slot_id, owner, [caller_serial], name }.
CREATE OR REPLACE PROCEDURE envelope.capture_signer_name(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_env    text := pi_data->>'envelope_id';
    v_slot   text := pi_data->>'slot_id';
    v_owner  text := pi_data->>'owner';
    v_serial text := NULLIF(pi_data->>'caller_serial', '');
    v_name   text := NULLIF(pi_data->>'name', '');
    v_found  text;
BEGIN
    IF v_env IS NULL OR v_env = '' OR v_slot IS NULL OR v_slot = '' OR v_owner IS NULL OR v_owner = '' OR v_name IS NULL THEN
        po_data := util.result_error('envelope:invalid', 'envelope_id, slot_id, owner and name are required'); RETURN;
    END IF;

    UPDATE envelope.signer_slot s
       SET signer_name = v_name
      FROM envelope.envelope e
     WHERE s.envelope_id = e.id AND e.id = v_env AND s.id = v_slot
       AND (s.signer_name IS NULL OR s.signer_name = '')
       AND (
           e.owner = v_owner
           OR (v_serial IS NOT NULL AND e.status <> 'draft' AND s.identity_ref = v_serial)
       )
     RETURNING s.id INTO v_found;

    po_data := util.result_success(jsonb_build_object('slot', v_slot, 'captured', v_found IS NOT NULL));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:capture_name_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.sweep_retention — the retention driver: the envelope's own exit.
--
-- A finished envelope has no purpose left to serve. Its documents' bytes are gone
-- on their own clock, the signed container belongs to the signer, and the signing
-- acts live in the evidence chain, which references the envelope by id and does not
-- need the row. What remains is personal data — a signer's identity code, a signer's
-- name, the owner's subject — kept past its purpose, and the largest schema in the
-- database. So the row is DELETED, not tombstoned: nothing downstream reads a dead
-- envelope.
--
-- Three stages, each optional (a caller that omits an instant skips that stage) and
-- each capped by `batch`, so a large backlog drains over successive sweeps instead of
-- locking the table in one pass:
--   (a) expire  — a `sent`/`in_progress` envelope whose own expiry has passed becomes
--                 `expired`. Returns their ids so the caller can announce the
--                 transition to whoever notifies the parties. This also BUMPS the
--                 optimistic `version`: an actor still holding the pre-expiry version
--                 must lose its compare-and-set rather than resurrect the envelope.
--   (b) terminal — a terminal envelope whose documents stopped being downloadable
--                 before `terminal_before` is deleted; its signer slots and document
--                 references go with it (cascade). The clock is `retention_until`,
--                 recorded at the terminal transition, NOT the row's own timestamp:
--                 the envelope is the tracking page for those documents, so it must
--                 not disappear while they can still be read. An envelope whose
--                 horizon was never recorded is left alone — waiting is recoverable,
--                 deleting early is not.
--   (c) drafts  — a draft abandoned before `draft_before` is deleted. Judged on
--                 creation, and "abandoned" is TESTED rather than read off the
--                 status: an envelope reopened for a further signature is a draft
--                 again, so the branch also requires no recorded retention horizon
--                 and no signed slot — the two marks a reopened envelope carries and
--                 a never-sent one cannot.
--
-- The retention windows themselves are the calling service's configuration, never a
-- constant here — this procedure applies instants it is given and invents none.
-- pi_data = { [terminal_before], [draft_before], [expire_before], [batch] }.
CREATE OR REPLACE PROCEDURE envelope.sweep_retention(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_terminal_before timestamptz := (pi_data->>'terminal_before')::timestamptz;
    v_draft_before    timestamptz := (pi_data->>'draft_before')::timestamptz;
    v_expire_before   timestamptz := (pi_data->>'expire_before')::timestamptz;
    v_limit           int         := LEAST(COALESCE((pi_data->>'batch')::int, 500), 5000);
    v_expired         jsonb       := '[]'::jsonb;
    v_terminal        integer     := 0;
    v_drafts          integer     := 0;
    v_stranded        integer     := 0;
BEGIN
    -- Fail closed: a call naming no instant at all would be a sweep with no window,
    -- which is a misconfiguration, not a no-op worth reporting as success.
    IF v_terminal_before IS NULL AND v_draft_before IS NULL AND v_expire_before IS NULL THEN
        po_data := util.result_error('envelope:invalid',
            'at least one of terminal_before, draft_before, expire_before is required'); RETURN;
    END IF;
    IF v_limit < 1 THEN
        po_data := util.result_error('envelope:invalid', 'batch must be positive'); RETURN;
    END IF;

    -- (a) past its expiry and still open -> expired.
    IF v_expire_before IS NOT NULL THEN
        WITH due AS (
            SELECT id
            FROM envelope.envelope
            WHERE status IN ('sent', 'in_progress')
              AND expiry IS NOT NULL
              AND expiry < v_expire_before
            ORDER BY expiry
            LIMIT v_limit
            FOR UPDATE SKIP LOCKED
        ),
        flipped AS (
            UPDATE envelope.envelope e
               SET status = 'expired', version = e.version + 1
              FROM due d
             WHERE e.id = d.id
            RETURNING e.id
        )
        SELECT COALESCE(jsonb_agg(id), '[]'::jsonb) INTO v_expired FROM flipped;
    END IF;

    -- (b) terminal, and its documents are past being downloadable -> gone, with its
    --     slots and doc refs.
    IF v_terminal_before IS NOT NULL THEN
        WITH doomed AS (
            SELECT id
            FROM envelope.envelope
            WHERE status IN ('completed', 'declined', 'cancelled', 'expired')
              AND retention_until IS NOT NULL
              AND retention_until < v_terminal_before
            ORDER BY retention_until
            LIMIT v_limit
            FOR UPDATE SKIP LOCKED
        ),
        removed AS (
            DELETE FROM envelope.envelope e
             USING doomed d
             WHERE e.id = d.id
            RETURNING e.id
        )
        SELECT count(*) INTO v_terminal FROM removed;
    END IF;

    -- (c) never sent, long abandoned -> gone.
    --
    -- "Never sent" is tested, not assumed from the status. `status = 'draft'` alone
    -- meant never-sent only while nothing could return to draft; a further-signature
    -- round reopens a COMPLETED envelope back to draft, and such an envelope created
    -- more than the draft window ago would then be deleted with its new round in
    -- flight. Two marks tell the two apart, and a reopened envelope carries both: the
    -- retention horizon its previous terminal recorded, and a slot that has signed. A
    -- genuinely abandoned draft has neither, because nothing sets a horizon before a
    -- terminal transition and nothing signs before a send.
    IF v_draft_before IS NOT NULL THEN
        WITH doomed AS (
            SELECT id
            FROM envelope.envelope e
            WHERE status = 'draft'
              AND created_at < v_draft_before
              AND retention_until IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM envelope.signer_slot s
                   WHERE s.envelope_id = e.id AND s.status = 'signed'
              )
            ORDER BY created_at
            LIMIT v_limit
            FOR UPDATE SKIP LOCKED
        ),
        removed AS (
            DELETE FROM envelope.envelope e
             USING doomed d
             WHERE e.id = d.id
            RETURNING e.id
        )
        SELECT count(*) INTO v_drafts FROM removed;
    END IF;

    -- Terminal envelopes the sweep cannot judge, because their horizon was never
    -- recorded. Reported rather than guessed at: this is the one way the retention
    -- policy silently stops applying to a row, so it has to be a number somebody
    -- can watch, not an absence nobody notices.
    IF v_terminal_before IS NOT NULL THEN
        SELECT count(*) INTO v_stranded
        FROM envelope.envelope
        WHERE status IN ('completed', 'declined', 'cancelled', 'expired')
          AND retention_until IS NULL;
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'expired',          v_expired,
        'expired_count',    jsonb_array_length(v_expired),
        'terminal_deleted', v_terminal,
        'drafts_deleted',   v_drafts,
        'awaiting_horizon', v_stranded));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:sweep_retention_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.list_unsettled_terminal — terminal envelopes whose retention horizon was
-- never recorded, with the documents each one is waiting on.
--
-- A terminal envelope with no horizon is one the sweep cannot judge, so it is never
-- deleted. Three ways a row lands here: the workflow expired it on its own deadline
-- (a transition with no request behind it, so nothing read the documents), the read
-- failed at the transition, or the row predates the horizon being recorded at all.
-- All three are the same repair — read the documents' retention now and pin it — so
-- they are one list rather than three.
--
-- Unordered on purpose: the caller drains the whole set over successive passes, so
-- picking a favourite would cost a sort of the largest table in the database and buy
-- nothing. The batch is what bounds one pass.
--
-- Returns a row per envelope with its document ids, because the caller needs both to
-- do the repair and one round trip is enough for it.
-- pi_data = { [batch] }.
CREATE OR REPLACE PROCEDURE envelope.list_unsettled_terminal(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_limit int   := LEAST(COALESCE((pi_data->>'batch')::int, 500), 5000);
    v_rows  jsonb := '[]'::jsonb;
BEGIN
    IF v_limit < 1 THEN
        po_data := util.result_error('envelope:invalid', 'batch must be positive'); RETURN;
    END IF;

    WITH unsettled AS (
        SELECT id
        FROM envelope.envelope
        WHERE status IN ('completed', 'declined', 'cancelled', 'expired')
          AND retention_until IS NULL
        LIMIT v_limit
    )
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id', u.id,
        'documents', COALESCE((
            SELECT jsonb_agg(ed.document_id ORDER BY ed.document_id)
            FROM envelope.envelope_document ed
            WHERE ed.envelope_id = u.id), '[]'::jsonb))), '[]'::jsonb)
      INTO v_rows
      FROM unsettled u;

    po_data := util.result_success(jsonb_build_object('envelopes', v_rows));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:list_unsettled_terminal_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- envelope.set_retention_until — record when this envelope's documents stop being
-- downloadable, so the retention sweep knows how long the tracking page must stay.
--
-- Called once, at the terminal transition, with the value read from the service that
-- owns the documents. It cannot be computed here: the documents live elsewhere and
-- their retention rolls forward on every signing act, so only a read taken after the
-- last signature is final.
--
-- NOT owner-scoped — the transition that triggers it can arrive on the signing
-- service's callback, where there is no owner in the request at all. Like the other
-- callback-driven procedure it is keyed by id alone and idempotent, and it records a
-- clock rather than granting anything, so it opens no access.
--
-- Write-once by policy but tolerant in practice: a later call overwrites, because a
-- re-lift after a failed first attempt is a repair, not a change of mind. It does NOT
-- touch `version` — this is bookkeeping about the envelope, not a transition of it,
-- and bumping the token would fail a caller's compare-and-set for no reason.
-- pi_data = { id, retention_until }.
CREATE OR REPLACE PROCEDURE envelope.set_retention_until(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = envelope, util, pg_temp
AS $$
DECLARE
    v_id    text        := pi_data->>'id';
    v_until timestamptz := (pi_data->>'retention_until')::timestamptz;
    v_found text;
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('envelope:invalid', 'id is required'); RETURN;
    END IF;
    IF v_until IS NULL THEN
        po_data := util.result_error('envelope:invalid', 'retention_until is required'); RETURN;
    END IF;

    UPDATE envelope.envelope
       SET retention_until = v_until
     WHERE id = v_id
    RETURNING id INTO v_found;

    IF v_found IS NULL THEN
        po_data := util.result_error('envelope:not_found', 'envelope not found'); RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('id', v_id, 'retention_until', v_until));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('envelope:set_retention_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- ---------------------------------------------------------------------------
-- EXECUTE grants — lock every procedure down, then grant only to envelope_public.
-- ---------------------------------------------------------------------------
REVOKE ALL ON PROCEDURE envelope.create_envelope(jsonb, jsonb)  FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.get_envelope(jsonb, jsonb)     FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.list_envelopes(jsonb, jsonb)   FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.find_envelopes_for_document(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.list_signing_tasks(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.attach_document(jsonb, jsonb)  FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.add_slot(jsonb, jsonb)         FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.apply_transition(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.slot_eligible(jsonb, jsonb)    FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.set_slot_job(jsonb, jsonb)     FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.mark_slot_signed(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.decline_slot(jsonb, jsonb)     FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.capture_signer_name(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.sweep_retention(jsonb, jsonb)  FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.list_unsettled_terminal(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE envelope.set_retention_until(jsonb, jsonb) FROM PUBLIC;

GRANT EXECUTE ON PROCEDURE envelope.create_envelope(jsonb, jsonb)  TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.get_envelope(jsonb, jsonb)     TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.list_envelopes(jsonb, jsonb)   TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.find_envelopes_for_document(jsonb, jsonb) TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.list_signing_tasks(jsonb, jsonb) TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.attach_document(jsonb, jsonb)  TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.add_slot(jsonb, jsonb)         TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.apply_transition(jsonb, jsonb) TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.slot_eligible(jsonb, jsonb)    TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.set_slot_job(jsonb, jsonb)     TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.mark_slot_signed(jsonb, jsonb) TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.decline_slot(jsonb, jsonb)     TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.capture_signer_name(jsonb, jsonb) TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.sweep_retention(jsonb, jsonb)  TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.list_unsettled_terminal(jsonb, jsonb) TO envelope_public;
GRANT EXECUTE ON PROCEDURE envelope.set_retention_until(jsonb, jsonb) TO envelope_public;
