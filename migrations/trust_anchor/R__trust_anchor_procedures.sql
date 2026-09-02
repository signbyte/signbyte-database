-- R: repeatable migration — the trust_anchor store API (4 procedures).
--
-- These back the store.Store interface the trust-anchor service uses
-- (SaveSnapshot/LoadLatestSnapshot, SaveBootstrap/LoadLatestBootstrap). They run
-- as the migrating owner (the owner of the tables — implicit ownership), so the
-- EXECUTE-only `trust_anchor_public` service role drives them without any table privileges. Each:
--   * uses the uniform JSONB envelope `(pi_data jsonb, INOUT po_data jsonb)`,
--   * pins `search_path` ending in pg_temp (SECURITY DEFINER hardening),
--   * returns a structured result via util.result_success / util.result_error
--     with `<domain>:<reason>` error codes,
--   * validates BEFORE any write (Pattern A: return) and, on any unexpected
--     error after a write, re-raises a structured error with SQLSTATE P0001
--     (Pattern B) so the transaction ROLLS BACK rather than committing a partial
--     write.
-- For the *save* procedures, `pi_data` IS the full serialized object (the Go
-- backend passes the marshalled trust.Snapshot / trust.Bootstrap directly); the
-- object is stored verbatim in `content` and key columns are projected from it.
-- Re-applied automatically whenever the checksum changes.

-- trust_anchor.save_snapshot — append a new snapshot version.
-- pi_data = serialized trust.Snapshot (id, prevId, generatedAt, lotlSequence, …).
CREATE OR REPLACE PROCEDURE trust_anchor.save_snapshot(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
AS $$
DECLARE
    v_id text := pi_data->>'id';
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('trust_anchor:invalid', 'snapshot id is required');
        RETURN;
    END IF;

    INSERT INTO trust_anchor.snapshot (snapshot_id, prev_id, generated_at, lotl_sequence, content)
    VALUES (
        v_id,
        NULLIF(pi_data->>'prevId', ''),
        COALESCE((pi_data->>'generatedAt')::timestamptz, now()),
        COALESCE((pi_data->>'lotlSequence')::bigint, 0),
        pi_data
    );

    po_data := util.result_success(jsonb_build_object('snapshotId', v_id));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:save_snapshot_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- trust_anchor.load_latest_snapshot — newest snapshot, or {"snapshot": null}.
-- pi_data is ignored. Returns data = {"snapshot": <full object> | null}; the Go
-- backend treats null as "none persisted yet" → (nil, nil).
CREATE OR REPLACE PROCEDURE trust_anchor.load_latest_snapshot(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
AS $$
DECLARE
    v_content jsonb;
BEGIN
    SELECT content INTO v_content
    FROM trust_anchor.snapshot
    ORDER BY seq DESC
    LIMIT 1;

    po_data := util.result_success(jsonb_build_object('snapshot', v_content));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:load_snapshot_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- trust_anchor.save_bootstrap — append a new approved bootstrap version.
-- pi_data = serialized trust.Bootstrap (version, ojReference, activatedAt, …).
CREATE OR REPLACE PROCEDURE trust_anchor.save_bootstrap(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
AS $$
DECLARE
    v_version int;
BEGIN
    IF pi_data->>'version' IS NULL THEN
        po_data := util.result_error('trust_anchor:invalid', 'bootstrap version is required');
        RETURN;
    END IF;
    v_version := (pi_data->>'version')::int;

    INSERT INTO trust_anchor.bootstrap (version, oj_reference, seeded, activated_at, content)
    VALUES (
        v_version,
        COALESCE(pi_data->>'ojReference', ''),
        COALESCE((pi_data->>'seeded')::boolean, false),
        COALESCE((pi_data->>'activatedAt')::timestamptz, now()),
        pi_data
    );

    po_data := util.result_success(jsonb_build_object('version', v_version));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:save_bootstrap_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- trust_anchor.load_latest_bootstrap — authoritative bootstrap (highest version,
-- newest write as tiebreaker), or {"bootstrap": null} when none.
CREATE OR REPLACE PROCEDURE trust_anchor.load_latest_bootstrap(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = trust_anchor, util, pg_temp
AS $$
DECLARE
    v_content jsonb;
BEGIN
    SELECT content INTO v_content
    FROM trust_anchor.bootstrap
    ORDER BY version DESC, seq DESC
    LIMIT 1;

    po_data := util.result_success(jsonb_build_object('bootstrap', v_content));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('trust_anchor:load_bootstrap_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- Procedures are owned by the migrating role (implicit ownership) — no explicit
-- OWNER TO, so the script stays owner-name-free and portable across deployments.
-- EXECUTE-only: revoke from PUBLIC, grant only to the service role.
REVOKE ALL ON PROCEDURE trust_anchor.save_snapshot(jsonb, jsonb)         FROM PUBLIC;
REVOKE ALL ON PROCEDURE trust_anchor.load_latest_snapshot(jsonb, jsonb)  FROM PUBLIC;
REVOKE ALL ON PROCEDURE trust_anchor.save_bootstrap(jsonb, jsonb)        FROM PUBLIC;
REVOKE ALL ON PROCEDURE trust_anchor.load_latest_bootstrap(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE trust_anchor.save_snapshot(jsonb, jsonb)         TO trust_anchor_public;
GRANT EXECUTE ON PROCEDURE trust_anchor.load_latest_snapshot(jsonb, jsonb)  TO trust_anchor_public;
GRANT EXECUTE ON PROCEDURE trust_anchor.save_bootstrap(jsonb, jsonb)        TO trust_anchor_public;
GRANT EXECUTE ON PROCEDURE trust_anchor.load_latest_bootstrap(jsonb, jsonb) TO trust_anchor_public;
