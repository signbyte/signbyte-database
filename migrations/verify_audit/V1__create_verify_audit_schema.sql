-- V1: verify-audit (public-verification abuse evidence) store — the
-- `verify_audit` schema.
--
-- Backs the audit service's second, purpose-scoped surface: evidence of who
-- drove the ANONYMOUS document-verification endpoint (and with what), so a
-- provider-side complaint about quota abuse is answerable. It is deliberately
-- separate from the `access_audit` schema: different purpose (abuse evidence,
-- not a GDPR access log), different lawful basis (legitimate interest in
-- protecting the service), and its own — shorter — retention window, after
-- which rows are swept. It records request metadata and the upload's hash;
-- never any document content.
--
-- Same data-layer contract as every other schema here: access ONLY via
-- SECURITY DEFINER procedures (R__verify_audit_procedures.sql) driven by the
-- EXECUTE-only service role. The audit service binary hosts both surfaces, so
-- the existing `access_audit_public` role drives this schema too — co-location
-- in a binary/role is not co-mingling of purposes; the schema split is the
-- purpose boundary.
--
-- Prerequisite: the shared `util` schema (generate_ulid / result_success /
-- result_error). Applied as its own Flyway location with its own history table.

CREATE SCHEMA IF NOT EXISTS verify_audit;

-- ---------------------------------------------------------------------------
-- The event table. IP + user agent are personal data — the retention sweep is
-- what keeps holding them proportionate. `source_service` is derived from the
-- AUTHENTICATED caller identity, never from the event body.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verify_audit.verify_event (
    row_id          text         PRIMARY KEY DEFAULT util.generate_ulid(),
    occurred_at     timestamptz  NOT NULL,
    ip              text,                              -- originating client address
    user_agent      text,
    size_bytes      bigint       NOT NULL DEFAULT 0,   -- uploaded file size
    sha256          text,                              -- hex digest of the uploaded bytes (hash, never content)
    verdict         text         NOT NULL,             -- normalized verdict or a typed reject/error marker
    correlation_id  text,                              -- joins the request across service logs
    session_id      text,                              -- provider-side transient validation session
    source_service  text,                              -- authenticated caller (derived, NOT from body)
    recorded_at     timestamptz  NOT NULL DEFAULT now()
);

-- Abuse queries group by address over a window; the sweep scans by time.
CREATE INDEX IF NOT EXISTS idx_verify_event_occurred ON verify_audit.verify_event (occurred_at);
CREATE INDEX IF NOT EXISTS idx_verify_event_ip       ON verify_audit.verify_event (ip, occurred_at);

-- ---------------------------------------------------------------------------
-- Append-only guard (defense-in-depth on top of the role grants): UPDATE is
-- never allowed; DELETE only when the retention sweep has set the
-- session-local flag. Evidence that can be quietly edited is not evidence.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION verify_audit.guard_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = verify_audit, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION '%', util.result_error('verify_audit:append_only', 'verify events are immutable') USING ERRCODE = 'P0001';
    END IF;
    IF current_setting('verify_audit.allow_purge', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION '%', util.result_error('verify_audit:append_only', 'verify events may only be removed by the retention sweep') USING ERRCODE = 'P0001';
    END IF;
    RETURN OLD;
END
$$;

DROP TRIGGER IF EXISTS trg_verify_event_append_only ON verify_audit.verify_event;
CREATE TRIGGER trg_verify_event_append_only
    BEFORE UPDATE OR DELETE ON verify_audit.verify_event
    FOR EACH ROW EXECUTE FUNCTION verify_audit.guard_append_only();

-- ---------------------------------------------------------------------------
-- Least-privilege grants. The audit service's EXECUTE-only role (created
-- outside migrations by provision-roles.sh) drives this schema's procedures
-- and holds NO table privileges. Procedure EXECUTE grants live in the
-- repeatable migration (R__).
-- ---------------------------------------------------------------------------
REVOKE ALL ON SCHEMA verify_audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA verify_audit FROM PUBLIC;
REVOKE ALL ON verify_audit.verify_event FROM access_audit_public;

GRANT USAGE ON SCHEMA verify_audit TO access_audit_public;
